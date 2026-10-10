using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Cms;
using X509Certificate = Org.BouncyCastle.X509.X509Certificate;

namespace UA.Cryptography.Tests.Signatures;

/// <summary>
/// A PAdES-B-LTA signed PDF made with the synthetic <see cref="Hierarchy"/> (docs/signature-formats.md, section 11):
/// the original file plus three incremental updates — the signature (detached CAdES-T over /ByteRange), the Document
/// Security Store with certificates and OCSP responses, and a document time-stamp over the whole file.
/// </summary>
public class PadesTests
{
    private static readonly Lazy<byte[]> SignedPdf = new(() => PadesBuilder.Sign(PadesBuilder.OriginalPdf, Hierarchy.Shared, PadesLevel.LTA));

    private static byte[] Pdf => SignedPdf.Value;

    private static List<X509Certificate> DssCertificates(byte[] pdf) =>
        PdfInspector.DssReferences(pdf, "Certs").Select(n => UaPki.ParseCertificate(PdfInspector.Stream(pdf, n))).ToList();

    [Fact]
    public void FileIsTheOriginalPdfWithIncrementalUpdates()
    {
        byte[] pdf = Pdf;
        Assert.True(pdf.AsSpan().StartsWith(PadesBuilder.OriginalPdf)); // the signed document is never rewritten, only appended to

        List<PdfInspector.Signature> signatures = PdfInspector.ReadSignatures(pdf);
        Assert.Equal([("Sig", "ETSI.CAdES.detached"), ("DocTimeStamp", "ETSI.RFC3161")], signatures.Select(s => (s.Type, s.SubFilter)));

        foreach (PdfInspector.Signature s in signatures)
        {
            long[] r = s.ByteRange;
            // The ranges cover everything from the start of the file to the end of its revision except /Contents <...>.
            Assert.Equal(0, r[0]);
            Assert.Equal(s.ContentsStart, r[1]);
            Assert.Equal(s.ContentsEnd, r[2]);
            Assert.EndsWith("%%EOF\n", PdfInspector.Text(pdf.AsSpan(0, (int)(r[2] + r[3])).ToArray()), StringComparison.Ordinal);
        }
        Assert.True(signatures[0].ByteRange[2] + signatures[0].ByteRange[3] < pdf.Length);         // the DSS came after the signature
        Assert.Equal(pdf.Length, signatures[^1].ByteRange[2] + signatures[^1].ByteRange[3]); // LTA: the last one covers all
    }

    [Theory]
    [InlineData(PadesLevel.B)]
    [InlineData(PadesLevel.LTA)]
    public void SignatureVerifies(PadesLevel level)
    {
        byte[] pdf = level == PadesLevel.LTA ? Pdf : PadesBuilder.Sign(PadesBuilder.OriginalPdf, Hierarchy.Shared, level);
        PdfInspector.Signature pades = PdfInspector.ReadSignatures(pdf).Single(s => s.SubFilter == "ETSI.CAdES.detached");
        Assert.Null(pades.Cms.SignedContent);
        SignerInformation signer = Assert.Single(pades.Cms.GetSignerInfos().GetSigners());
        Assert.Equal(Oids.Dstu7564_256, signer.DigestAlgorithmID.Algorithm.Id);
        Assert.Null(signer.SignedAttributes![PkcsObjectIdentifiers.Pkcs9AtSigningTime]); // PAdES keeps the time in /M
        X509Certificate certificate = Assert.Single(pades.Cms.GetCertificates().EnumerateMatches(signer.SignerID));

        // messageDigest covers the byte ranges; signingCertificateV2 and the signature are checked as in CAdES.
        byte[] messageDigest = UaPki.MessageDigest(signer);
        Assert.Equal(UaPki.Hash(Oids.Dstu7564_256, PdfInspector.Covered(pdf, pades.ByteRange)), messageDigest);
        Assert.True(UaPki.VerifyCmsSigner(signer, certificate));

        // A changed byte inside the signed range changes the digest.
        byte[] tampered = (byte[])pdf.Clone();
        tampered[20] ^= 1;
        Assert.NotEqual(messageDigest, UaPki.Hash(Oids.Dstu7564_256, PdfInspector.Covered(tampered, pades.ByteRange)));
    }

    /// <summary>
    /// PAdES-B-T: the signature time-stamp covers the signature value; PAdES-B-LTA: the document time-stamp covers the
    /// whole file including the DSS. The service's certificate is taken from the DSS.
    /// </summary>
    [Fact]
    public void TimeStampsVerify()
    {
        byte[] pdf = Pdf;
        List<X509Certificate> dss = DssCertificates(pdf);
        List<PdfInspector.Signature> signatures = PdfInspector.ReadSignatures(pdf);

        SignerInformation signer = Assert.Single(signatures.Single(s => s.SubFilter == "ETSI.CAdES.detached").Cms.GetSignerInfos().GetSigners());
        var signatureTimeStamp = new CmsSignedData(UaPki.UnsignedAttribute(signer, PkcsObjectIdentifiers.IdAASignatureTimeStampToken).ToAsn1Object().GetEncoded());
        CheckTimeStamp(signatureTimeStamp, signer.GetSignature(), dss);

        PdfInspector.Signature document = signatures.Single(s => s.SubFilter == "ETSI.RFC3161");
        CheckTimeStamp(document.Cms, PdfInspector.Covered(pdf, document.ByteRange), dss);
    }

    private static void CheckTimeStamp(CmsSignedData token, byte[] covered, List<X509Certificate> known)
    {
        Assert.True(UaPki.ImprintCovers(UaPki.ReadTimeStamp(token), covered));
        X509Certificate tsa = UaPki.FindTimeStampSigner(token, known)!;
        Assert.True(UaPki.VerifyCmsSigner(Assert.Single(token.GetSignerInfos().GetSigners()), tsa));
    }

    /// <summary>
    /// The DSS makes the signature verifiable later: every certificate chains to the self-signed root, each link
    /// verified, and every OCSP response is correctly signed and says "good" — for the signer, its CA and the TSA.
    /// </summary>
    [Fact]
    public void DocumentSecurityStoreIsComplete()
    {
        byte[] pdf = Pdf;
        List<X509Certificate> dss = DssCertificates(pdf);
        PdfInspector.Signature pades = PdfInspector.ReadSignatures(pdf).Single(s => s.SubFilter == "ETSI.CAdES.detached");
        SignerInformation signer = Assert.Single(pades.Cms.GetSignerInfos().GetSigners());
        X509Certificate signerCertificate = Assert.Single(pades.Cms.GetCertificates().EnumerateMatches(signer.SignerID));
        List<X509Certificate> all = [.. dss, signerCertificate];

        X509Certificate root = Assert.Single(dss, c => c.SubjectDN.Equivalent(c.IssuerDN));
        Assert.All(all, c => Assert.True(UaPki.ChainsToTrusted(c, dss, [root])));

        int[] ocsps = PdfInspector.DssReferences(pdf, "OCSPs");
        Assert.NotEmpty(ocsps);
        var covered = new List<X509Certificate>();
        foreach (int n in ocsps)
        {
            BasicOcspResponse response = UaPki.ReadOcspResponse(PdfInspector.Stream(pdf, n));
            Assert.True(UaPki.VerifyOcsp(response, UaPki.FindOcspResponder(response, all)));
            foreach (SingleResponse single in response.TbsResponseData.Responses.Cast<Org.BouncyCastle.Asn1.Asn1Encodable>().Select(SingleResponse.GetInstance))
            {
                Assert.Equal(0, single.CertStatus.TagNo); // good
                covered.Add(Assert.Single(all, c => c.SerialNumber.Equals(single.CertId.SerialNumber.Value)));
            }
        }

        Assert.Contains(signerCertificate, covered);
        Assert.Contains(covered, c => c.SubjectDN.Equivalent(signerCertificate.IssuerDN));
        Assert.Contains(Hierarchy.Shared.Tsa.Identity.Certificate, covered);
    }
}
