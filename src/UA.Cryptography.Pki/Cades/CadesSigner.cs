using UA.Cryptography.Pki.Asn1;
using UA.Cryptography.Pki.Cms;
using UA.Cryptography.Pki.Ocsp;
using UA.Cryptography.Pki.Services;
using UA.Cryptography.Pki.Tsp;
using UA.Cryptography.Pki.X509;

namespace UA.Cryptography.Pki.Cades;

/// <param name="HashOid">Hash of the data and of the signed attributes: <see cref="Oids.Dstu7564_256"/> or <see cref="Oids.Gost34311"/>.</param>
/// <param name="Detached">Leave the data out of the signature (ASiC-S, a .p7s next to the file).</param>
/// <param name="Level">B, T (signatureTimeStampToken) or LT (CAdES-X Long).</param>
/// <param name="SigningTime">Add the signingTime signed attribute.</param>
/// <param name="ContentTimeStamp">Add a contentTimeStamp signed attribute over the data.</param>
public sealed record CadesOptions(
    string HashOid = Oids.Dstu7564_256,
    bool Detached = false,
    SignatureLevel Level = SignatureLevel.B,
    bool SigningTime = true,
    bool ContentTimeStamp = false);

/// <summary>
/// Creates CAdES signatures (ETSI EN 319 122) shaped like those of Ukrainian qualified signature tools
/// (docs/signature-formats.md, sections 9 and 10).
/// </summary>
public sealed class CadesSigner(SigningKey signer, SignatureServices? services = null)
{
    private readonly SignatureServices _services = services ?? new SignatureServices();

    public byte[] Sign(byte[] data, CadesOptions options)
    {
        string hashOid = options.HashOid;
        var extra = new List<byte[]>();
        if (options.SigningTime)
            extra.Add(CmsBuilder.Attribute(Oids.SigningTime, Der.Time(DateTimeOffset.UtcNow)));
        if (options.ContentTimeStamp)
            extra.Add(CmsBuilder.Attribute(Oids.ContentTimeStamp, Stamp(data, hashOid).Encoded));

        byte[] signedAttributes = CmsBuilder.SignedAttributes(data, Oids.Data, signer, hashOid, extra);
        (byte[] signerInfo, byte[] signature) = CmsBuilder.SignerInfo(signedAttributes, signer, hashOid);

        var unsigned = new List<byte[]>();
        if (options.Level >= SignatureLevel.T)
            unsigned.Add(CmsBuilder.Attribute(Oids.SignatureTimeStampToken, Stamp(signature, hashOid).Encoded));
        if (options.Level >= SignatureLevel.LT)
            unsigned.AddRange(LongTermAttributes(_services.CollectLongTermData(signer, hashOid), hashOid));
        if (unsigned.Count > 0)
            signerInfo = CmsBuilder.SignerInfoWith(signedAttributes, signature, signer.Certificate, hashOid, unsigned);

        return CmsBuilder.SignedData(signerInfo, hashOid, Oids.Data, options.Detached ? null : data, [signer.Certificate]);
    }

    private TimeStampToken Stamp(byte[] covered, string hashOid) =>
        _services.RequireTimeStamps().GetToken(PkiAlgorithms.Hash(hashOid, covered), hashOid);

    /// <summary>
    /// CAdES-C references and CAdES-X Long values: completeCertificateRefs and certValues over the CA and responder
    /// certificates, completeRevocationRefs and revocationValues over the OCSP responses. References hash with the
    /// signature's hash algorithm.
    /// </summary>
    private static IEnumerable<byte[]> LongTermAttributes(LongTermValidationData data, string hashOid)
    {
        byte[] OtherHash(byte[] encoded) =>
            Der.Sequence(Der.AlgorithmIdentifier(hashOid), Der.OctetString(PkiAlgorithms.Hash(hashOid, encoded)));

        IReadOnlyList<Certificate> certificates = data.Certificates;
        IReadOnlyList<OcspResponse> responses = data.Responses;

        byte[] certificateRefs = Der.Sequence(certificates.Select(c => Der.Sequence(OtherHash(c.Encoded))));
        byte[] ocspIds = Der.Sequence(responses.Select(r => Der.Sequence(
            Der.Sequence(r.ResponderIdEncoded, Der.GeneralizedTime(r.ProducedAt)),
            OtherHash(r.BasicEncoded))));
        byte[] revocationRefs = Der.Sequence(Der.Sequence(Der.Explicit(1, Der.Sequence(ocspIds))));

        yield return CmsBuilder.Attribute(Oids.CertificateRefs, certificateRefs);
        yield return CmsBuilder.Attribute(Oids.RevocationRefs, revocationRefs);
        yield return CmsBuilder.Attribute(Oids.CertValues, Der.Sequence(certificates.Select(c => c.Encoded)));
        yield return CmsBuilder.Attribute(Oids.RevocationValues, Der.Sequence(Der.Explicit(1, Der.Sequence(responses.Select(r => r.BasicEncoded)))));
    }
}
