using System.Text;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.Esf;
using Org.BouncyCastle.Asn1.Ess;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.Tsp;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cms;
using PkcsObjectIdentifiers = Org.BouncyCastle.Asn1.Pkcs.PkcsObjectIdentifiers;
using SignedData = Org.BouncyCastle.Asn1.Cms.SignedData;
using X509Certificate = Org.BouncyCastle.X509.X509Certificate;

namespace UA.Cryptography.Tests.Signatures;

/// <summary>
/// CAdES (CMS) signatures made with the synthetic <see cref="Hierarchy"/> and checked by the recipe of
/// docs/signature-formats.md, section 9: messageDigest binds the data, signingCertificateV2 the certificate, and the
/// DSTU 4145 signature covers the DER signed attributes. Time-stamps, references and OCSP values are checked as well.
/// </summary>
public class CadesTests
{
    private static readonly byte[] Data = Encoding.UTF8.GetBytes("test");

    public static TheoryData<string, bool> Variants => new()
    {
        { Oids.Dstu7564_256, true },
        { Oids.Dstu7564_256, false },
        { Oids.Gost34311, true },
        { Oids.Gost34311, false },
    };

    /// <summary>The CMS and the signed data, wherever the data is kept.</summary>
    private sealed record Signed(CmsSignedData Cms, byte[] Data)
    {
        public SignerInformation Signer => Assert.Single(Cms.GetSignerInfos().GetSigners());

        public X509Certificate SignerCertificate => Assert.Single(Cms.GetCertificates().EnumerateMatches(Signer.SignerID));
    }

    private static Signed Create(CadesOptions options)
    {
        var cms = new CmsSignedData(CadesBuilder.Build(Data, Hierarchy.Shared, options));
        if (!options.Enveloped)
        {
            Assert.Null(cms.SignedContent);
            return new Signed(cms, Data);
        }
        var encapsulated = SignedData.GetInstance(cms.ContentInfo.Content).EncapContentInfo;
        Assert.Equal(CmsObjectIdentifiers.Data, encapsulated.ContentType);
        return new Signed(cms, ((Asn1OctetString)encapsulated.Content).GetOctets());
    }

    private static CmsSignedData Token(Asn1Encodable attributeValue) => new(attributeValue.ToAsn1Object().GetEncoded());

    [Theory]
    [MemberData(nameof(Variants))]
    public void SignatureVerifies(string hashOid, bool enveloped)
    {
        Signed s = Create(new CadesOptions(hashOid, enveloped));
        SignerInformation signer = s.Signer;
        Assert.Equal(hashOid, signer.DigestAlgorithmID.Algorithm.Id);
        Assert.Equal(UaPki.SignatureAlgorithmFor(hashOid), signer.SignatureAlgorithm.Algorithm.Id);
        X509Certificate certificate = s.SignerCertificate;
        var (parameters, publicKey, _) = UaPki.ReadPublicKey(certificate);

        // contentType and messageDigest bind the signed attributes to the data; CMS digests keep the hash bytes as they are.
        Assert.Equal(CmsObjectIdentifiers.Data, UaPki.SignedAttribute(signer, PkcsObjectIdentifiers.Pkcs9AtContentType));
        Assert.Equal(Data, s.Data);
        Assert.Equal(UaPki.Hash(hashOid, s.Data), UaPki.MessageDigest(signer));
        Assert.NotEqual(UaPki.Hash(hashOid, Encoding.ASCII.GetBytes("tesT")), UaPki.MessageDigest(signer));

        // signingCertificateV2 binds them to the signer's certificate.
        var signingCertificate = SigningCertificateV2.GetInstance(UaPki.SignedAttribute(signer, PkcsObjectIdentifiers.IdAASigningCertificateV2));
        EssCertIDv2 certId = signingCertificate.GetCerts()[0];
        Assert.Equal(UaPki.Hash(certId.HashAlgorithm.Algorithm.Id, certificate.GetEncoded()), certId.GetCertHash());

        // The signature covers the DER signed attributes; the field holds D (64 bytes for m = 257, little-endian).
        byte[] attributesHash = UaPki.Hash(hashOid, signer.GetEncodedSignedAttributes());
        byte[] signature = signer.GetSignature();
        Assert.Equal(64, signature.Length);
        Assert.True(UaPki.VerifyDstu4145(parameters, publicKey, attributesHash, signature));
        Assert.True(UaPki.VerifyCmsSigner(signer, certificate));

        attributesHash[0] ^= 1;
        Assert.False(UaPki.VerifyDstu4145(parameters, publicKey, attributesHash, signature));
    }

    [Fact]
    public void SignerCertificateChainsToTheRoot()
    {
        Hierarchy pki = Hierarchy.Shared;
        Signed s = Create(new CadesOptions());
        Assert.True(UaPki.ChainsToTrusted(s.SignerCertificate, pki.ValidationCertificates.ToList(), [pki.Root.Certificate]));
    }

    /// <summary>
    /// ASiC-S (ETSI EN 319 162): mimetype first and uncompressed, one data file and META-INF/signature.p7s, a detached
    /// CAdES-T signature with time-stamps on both the data and the signature.
    /// </summary>
    [Fact]
    public void AsicSContainerIsWellFormedAndVerifies()
    {
        Hierarchy pki = Hierarchy.Shared;
        var options = new CadesOptions(Oids.Gost34311, Enveloped: false, CadesLevel.T, ContentTimeStamp: true);
        byte[] asics = CadesBuilder.WrapAsicS("data.txt", Data, CadesBuilder.Build(Data, pki, options));

        Dictionary<string, byte[]> entries = Zip.ReadContainer(asics, CadesBuilder.AsicSMimeType);
        Assert.Equal(["mimetype", "data.txt", CadesBuilder.AsicSSignatureEntry], entries.Keys);
        byte[] content = entries["data.txt"];

        var cms = new CmsSignedData(entries[CadesBuilder.AsicSSignatureEntry]);
        Assert.Null(cms.SignedContent);
        SignerInformation signer = Assert.Single(cms.GetSignerInfos().GetSigners());
        Assert.Equal(UaPki.Hash(Oids.Gost34311, content), UaPki.MessageDigest(signer));
        Assert.True(UaPki.VerifyCmsSigner(signer, Assert.Single(cms.GetCertificates().EnumerateMatches(signer.SignerID))));
    }

    /// <summary>
    /// Two RFC 3161 time-stamps: the signed attribute contentTimeStamp covers the data, the unsigned
    /// signatureTimeStampToken covers the signature value. Both are signed by the time-stamping service.
    /// </summary>
    [Theory]
    [InlineData(Oids.Dstu7564_256)]
    [InlineData(Oids.Gost34311)]
    public void TimeStampsCoverDataAndSignature(string hashOid)
    {
        Hierarchy pki = Hierarchy.Shared;
        Signed s = Create(new CadesOptions(hashOid, Level: CadesLevel.T, ContentTimeStamp: true));
        SignerInformation signer = s.Signer;

        CmsSignedData contentToken = Token(UaPki.SignedAttribute(signer, PkcsObjectIdentifiers.IdAAEtsContentTimestamp));
        Assert.True(UaPki.ImprintCovers(UaPki.ReadTimeStamp(contentToken), s.Data));

        CmsSignedData signatureToken = Token(UaPki.UnsignedAttribute(signer, PkcsObjectIdentifiers.IdAASignatureTimeStampToken));
        TstInfo info = UaPki.ReadTimeStamp(signatureToken);
        Assert.Equal(hashOid, info.MessageImprint.HashAlgorithm.Algorithm.Id);
        Assert.True(UaPki.ImprintCovers(info, signer.GetSignature()));

        foreach (CmsSignedData token in new[] { contentToken, signatureToken })
        {
            X509Certificate tsa = UaPki.FindTimeStampSigner(token, s.Cms.GetCertificates().EnumerateMatches(null))!;
            Assert.Equal(pki.Tsa.Identity.Certificate, tsa);
            Assert.True(UaPki.VerifyCmsSigner(Assert.Single(token.GetSignerInfos().GetSigners()), tsa));
        }
    }

    /// <summary>
    /// CAdES-X Long: the certificate and revocation references match the included values, the CA among them verifies
    /// the signer's certificate, and every OCSP response is signed by its responder and says "good".
    /// </summary>
    [Fact]
    public void LongTermValidationDataIsConsistent()
    {
        Signed s = Create(new CadesOptions(Level: CadesLevel.XLong));
        SignerInformation signer = s.Signer;
        X509Certificate certificate = s.SignerCertificate;

        // certificate-values and complete-certificate-references
        List<X509Certificate> certificates = Asn1Sequence.GetInstance(UaPki.UnsignedAttribute(signer, PkcsObjectIdentifiers.IdAAEtsCertValues))
            .Cast<Asn1Encodable>()
            .Select(c => new X509Certificate(X509CertificateStructure.GetInstance(c)))
            .ToList();
        OtherCertID[] certificateRefs = CompleteCertificateRefs.GetInstance(
            UaPki.UnsignedAttribute(signer, PkcsObjectIdentifiers.IdAAEtsCertificateRefs)).GetOtherCertIDs();
        Assert.Equal(certificates.Count, certificateRefs.Length);
        foreach (OtherCertID reference in certificateRefs)
        {
            OtherHash hash = reference.OtherCertHash;
            Assert.Contains(certificates, c => UaPki.Hash(hash.HashAlgorithm.Algorithm.Id, c.GetEncoded()).SequenceEqual(hash.GetHashValue()));
        }

        X509Certificate ca = Assert.Single(certificates, c => c.SubjectDN.Equivalent(certificate.IssuerDN));
        Assert.True(UaPki.VerifyCertificate(certificate, ca));

        // revocation-values and complete-revocation-references
        BasicOcspResponse[] responses = RevocationValues.GetInstance(
            UaPki.UnsignedAttribute(signer, PkcsObjectIdentifiers.IdAAEtsRevocationValues)).GetOcspVals();
        OcspResponsesID[] ocspRefs = CompleteRevocationRefs.GetInstance(UaPki.UnsignedAttribute(signer, PkcsObjectIdentifiers.IdAAEtsRevocationRefs))
            .GetCrlOcspRefs()
            .SelectMany(r => r.OcspIDs?.GetOcspResponses() ?? [])
            .ToArray();
        Assert.NotEmpty(responses);
        Assert.Equal(responses.Length, ocspRefs.Length);
        foreach (OcspResponsesID reference in ocspRefs)
        {
            OtherHash hash = reference.OcspRepHash;
            Assert.Contains(responses, r => UaPki.Hash(hash.HashAlgorithm.Algorithm.Id, r.GetDerEncoded()).SequenceEqual(hash.GetHashValue()));
        }

        // Each response is signed by its responder (certificate inside the response) and reports "good".
        List<X509Certificate> known = [.. certificates, certificate];
        var covered = new List<X509Certificate>();
        foreach (BasicOcspResponse response in responses)
        {
            Assert.True(UaPki.VerifyOcsp(response, UaPki.FindOcspResponder(response, known)));
            SingleResponse single = SingleResponse.GetInstance(Assert.Single(response.TbsResponseData.Responses));
            Assert.Equal(0, single.CertStatus.TagNo); // good
            covered.Add(Assert.Single(known, c => c.SerialNumber.Equals(single.CertId.SerialNumber.Value)));
        }
        Assert.Contains(certificate, covered);
        Assert.Contains(ca, covered);
    }

    [Fact]
    public void TamperedDataFailsMessageDigest()
    {
        Signed s = Create(new CadesOptions());
        Assert.NotEqual(UaPki.Hash(Oids.Dstu7564_256, Encoding.UTF8.GetBytes("tesT")), UaPki.MessageDigest(s.Signer));
    }

    [Fact]
    public void ForeignCertificateFailsSigningCertificateCheck()
    {
        Signed s = Create(new CadesOptions());
        Assert.False(UaPki.VerifyCmsSigner(s.Signer, Hierarchy.Shared.IssuingCa.Certificate));
    }
}
