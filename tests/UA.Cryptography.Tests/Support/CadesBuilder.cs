using System.IO.Compression;
using System.Text;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.Esf;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.X509;
using AttributeCms = Org.BouncyCastle.Asn1.Cms.Attribute;
using PkcsObjectIdentifiers = Org.BouncyCastle.Asn1.Pkcs.PkcsObjectIdentifiers;
using Time = Org.BouncyCastle.Asn1.Cms.Time;
using X509Certificate = Org.BouncyCastle.X509.X509Certificate;

namespace UA.Cryptography.Tests.Support;

/// <summary>CAdES levels met in the national PKI.</summary>
public enum CadesLevel
{
    /// <summary>CAdES-B: the signed attributes only.</summary>
    B,

    /// <summary>CAdES-T: + signatureTimeStampToken over the signature value.</summary>
    T,

    /// <summary>CAdES-X Long: + complete certificate and revocation references and their values.</summary>
    XLong,
}

/// <param name="HashOid">Digest of the data and of the signed attributes (<see cref="Oids.Dstu7564_256"/> or <see cref="Oids.Gost34311"/>).</param>
/// <param name="Enveloped">Keep the data inside (.p7s) or detach it (ASiC-S, PAdES).</param>
/// <param name="ContentTimeStamp">Add a contentTimeStamp signed attribute over the data.</param>
/// <param name="SigningTime">Add a signingTime signed attribute (PAdES keeps the time in /M instead).</param>
internal sealed record CadesOptions(
    string HashOid = Oids.Dstu7564_256,
    bool Enveloped = true,
    CadesLevel Level = CadesLevel.B,
    bool ContentTimeStamp = false,
    bool SigningTime = true);

/// <summary>
/// Builds CAdES signatures with the <see cref="Hierarchy"/> signer, shaped like the ones produced by Ukrainian
/// qualified signature tools (docs/signature-formats.md, sections 9 and 10).
/// </summary>
internal static class CadesBuilder
{
    public const string AsicSMimeType = "application/vnd.etsi.asic-s+zip";
    public const string AsicSSignatureEntry = "META-INF/signature.p7s";

    public static byte[] Build(byte[] data, Hierarchy pki, CadesOptions options)
    {
        string hashOid = options.HashOid;
        var signed = new List<AttributeCms>();
        if (options.SigningTime)
            signed.Add(new AttributeCms(PkcsObjectIdentifiers.Pkcs9AtSigningTime, new DerSet(new Time(DateTime.UtcNow))));
        if (options.ContentTimeStamp)
            signed.Add(new AttributeCms(PkcsObjectIdentifiers.IdAAEtsContentTimestamp, new DerSet(Token(pki.Tsa.Stamp(data, hashOid)))));

        SignerInfo signerInfo = CmsBuilder.CreateSignerInfo(data, CmsObjectIdentifiers.Data, pki.Signer, hashOid, signed);

        var unsigned = new List<AttributeCms>();
        if (options.Level >= CadesLevel.T)
        {
            byte[] token = pki.Tsa.Stamp(signerInfo.Signature.GetOctets(), hashOid);
            unsigned.Add(new AttributeCms(PkcsObjectIdentifiers.IdAASignatureTimeStampToken, new DerSet(Token(token))));
        }
        if (options.Level >= CadesLevel.XLong)
            unsigned.AddRange(LongTermValidationAttributes(pki));
        if (unsigned.Count > 0)
            signerInfo = CmsBuilder.WithUnsignedAttributes(signerInfo, unsigned);

        return CmsBuilder.SignedData(signerInfo, CmsObjectIdentifiers.Data, options.Enveloped ? data : null, [pki.Signer.Certificate])
            .GetDerEncoded();
    }

    /// <summary>
    /// CAdES-C references and CAdES-X Long values: the CA certificates of the signer's chain and "good" OCSP responses
    /// for the signer and its CA, each referenced by its DSTU 7564 hash.
    /// </summary>
    private static IEnumerable<AttributeCms> LongTermValidationAttributes(Hierarchy pki)
    {
        X509Certificate[] certificates = [pki.IssuingCa.Certificate, pki.Root.Certificate];
        BasicOcspResponse[] responses = [.. pki.SignerRevocationData];

        OtherCertID[] certificateRefs = certificates.Select(c => new OtherCertID(Hash(c.GetEncoded()), null)).ToArray();
        OcspResponsesID[] ocspRefs = responses.Select(r => new OcspResponsesID(
            new OcspIdentifier(r.TbsResponseData.ResponderID, r.TbsResponseData.ProducedAt), Hash(r.GetDerEncoded()))).ToArray();

        yield return new AttributeCms(PkcsObjectIdentifiers.IdAAEtsCertificateRefs, new DerSet(new CompleteCertificateRefs(certificateRefs)));
        yield return new AttributeCms(PkcsObjectIdentifiers.IdAAEtsRevocationRefs,
            new DerSet(new CompleteRevocationRefs([new CrlOcspRef(null, new OcspListID(ocspRefs), null)])));
        yield return new AttributeCms(PkcsObjectIdentifiers.IdAAEtsCertValues,
            new DerSet(new DerSequence(certificates.Select(c => (Asn1Encodable)c.CertificateStructure).ToArray())));
        yield return new AttributeCms(PkcsObjectIdentifiers.IdAAEtsRevocationValues, new DerSet(new RevocationValues(null, responses, null)));
    }

    private static OtherHash Hash(byte[] data) =>
        new(new OtherHashAlgAndValue(new AlgorithmIdentifier(new DerObjectIdentifier(Oids.Dstu7564_256)),
            new DerOctetString(UaPki.Hash(Oids.Dstu7564_256, data))));

    private static Asn1Object Token(byte[] token) => Asn1Object.FromByteArray(token);

    /// <summary>Wraps the data and a detached signature as an ASiC-S container (ETSI EN 319 162).</summary>
    public static byte[] WrapAsicS(string dataEntryName, byte[] data, byte[] detachedP7s)
    {
        using var buffer = new MemoryStream();
        using (var zip = new ZipArchive(buffer, ZipArchiveMode.Create, leaveOpen: true))
        {
            Zip.WriteMimeType(zip, AsicSMimeType);
            Zip.Write(zip, dataEntryName, data);
            Zip.Write(zip, AsicSSignatureEntry, detachedP7s);
        }
        return buffer.ToArray();
    }
}
