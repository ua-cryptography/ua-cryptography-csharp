using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.X509;
using X509Certificate = Org.BouncyCastle.X509.X509Certificate;

namespace UA.Cryptography.Tests.Support;

/// <summary>
/// A synthetic OCSP responder (RFC 6960) that says "good" about every certificate it is asked about. Responses are
/// signed over the DER tbsResponseData with DSTU 4145 + DSTU 7564, the signature value is a BIT STRING wrapping an
/// OCTET STRING with D (as in certificates), the CertID uses DSTU 7564 and the responder's certificate travels inside
/// the response — the shape found in the national PKI (docs/signature-formats.md, section 5).
/// </summary>
internal sealed class OcspResponder(TestPki.TestIdentity identity)
{
    public TestPki.TestIdentity Identity { get; } = identity;

    /// <param name="zeroKeyHash">Fill the CertID issuerKeyHash with zeros, as the "Дія" responder does.</param>
    public BasicOcspResponse Respond(X509Certificate certificate, X509Certificate issuer, bool zeroKeyHash = false)
    {
        byte[] keyHash = UaPki.Hash(Oids.Dstu7564_256, issuer.CertificateStructure.SubjectPublicKeyInfo.PublicKey.GetBytes());
        if (zeroKeyHash)
            Array.Clear(keyHash);
        var certId = new CertID(new AlgorithmIdentifier(new DerObjectIdentifier(Oids.Dstu7564_256)),
            new DerOctetString(UaPki.Hash(Oids.Dstu7564_256, issuer.SubjectDN.GetEncoded())),
            new DerOctetString(keyHash),
            new DerInteger(certificate.SerialNumber));
        var now = new DerGeneralizedTime(DateTime.UtcNow);
        var single = new SingleResponse(certId, new CertStatus(), now, null, null);
        var data = new ResponseData(new ResponderID(Identity.Certificate.SubjectDN), now, new DerSequence(single), null);

        var algorithm = new AlgorithmIdentifier(new DerObjectIdentifier(Oids.Dstu4145WithDstu7564));
        byte[] signature = TestPki.Sign(Identity.Key, data.GetDerEncoded(), Oids.Dstu4145WithDstu7564);
        return new BasicOcspResponse(data, algorithm, new DerBitString(new DerOctetString(signature).GetDerEncoded()),
            new DerSequence(Identity.Certificate.CertificateStructure));
    }

    /// <summary>The full OCSPResponse ("successful", id-pkix-ocsp-basic) as it is stored in PDF and XAdES.</summary>
    public static byte[] Encode(BasicOcspResponse response) =>
        new OcspResponse(new OcspResponseStatus(OcspResponseStatus.Successful),
            new ResponseBytes(OcspObjectIdentifiers.PkixOcspBasic, new DerOctetString(response.GetDerEncoded()))).GetDerEncoded();
}
