using UA.Cryptography.Pki;
using UA.Cryptography.Pki.Ocsp;
using UA.Cryptography.Pki.Services;
using UA.Cryptography.Pki.Tsp;
using UA.Cryptography.Pki.X509;
using X509Certificate = Org.BouncyCastle.X509.X509Certificate;

namespace UA.Cryptography.Tests.Support;

/// <summary>
/// Bridges the synthetic <see cref="Hierarchy"/> (built with BouncyCastle ASN.1) to the UA.Cryptography.Pki layer, so
/// that the package's signers use the hierarchy's time-stamping and OCSP services and its outputs are checked by the
/// BouncyCastle-based recipes of <see cref="UaPki"/>, and vice versa.
/// </summary>
internal static class PkiLayer
{
    public static Certificate ToPki(this X509Certificate certificate) => Certificate.Load(certificate.GetEncoded());

    public static Dstu4145PrivateKey ToPki(this TestPki.TestKey key) => new(key.Domain, key.PrivateKey, key.Dke);

    /// <summary>The hierarchy's signer with its chain (signer, issuing CA, root).</summary>
    public static SigningKey Signer(Hierarchy pki) =>
        new(pki.Signer.Key.ToPki(), pki.SignerChain.Select(c => c.ToPki()).ToList());

    public static Certificate Root(Hierarchy pki) => pki.Root.Certificate.ToPki();

    /// <summary>Every certificate of the hierarchy in the package's type.</summary>
    public static List<Certificate> AllCertificates(Hierarchy pki) =>
        [pki.Signer.Certificate.ToPki(), .. pki.ValidationCertificates.Select(c => c.ToPki())];

    public static SignatureServices Services(Hierarchy pki) => new()
    {
        TimeStamps = new TimeStamps(pki),
        Ocsp = new Ocsp(pki),
    };

    /// <summary>The hierarchy's TSA, called directly.</summary>
    public sealed class TimeStamps(Hierarchy pki) : ITimeStampService
    {
        public TimeStampToken GetToken(byte[] hash, string hashOid) => TimeStampToken.Load(pki.Tsa.StampHash(hash, hashOid));
    }

    /// <summary>The hierarchy's OCSP responders: the issuing CA's for its certificates, the root's for the root's.</summary>
    public sealed class Ocsp(Hierarchy pki) : IOcspService
    {
        public int Requests { get; private set; }

        public OcspResponse? GetResponse(Certificate certificate, Certificate issuer, string hashOid)
        {
            Requests++;
            OcspResponder? responder = Responder(pki, issuer);
            if (responder is null)
                return null;
            X509Certificate subject = UaPki.ParseCertificate(certificate.Encoded);
            return OcspResponse.Load(OcspResponder.Encode(responder.Respond(subject, UaPki.ParseCertificate(issuer.Encoded))));
        }
    }

    public static OcspResponder? Responder(Hierarchy pki, Certificate issuer) =>
        issuer.Encoded.AsSpan().SequenceEqual(pki.IssuingCa.Certificate.GetEncoded()) ? pki.IssuingCaOcsp
        : issuer.Encoded.AsSpan().SequenceEqual(pki.Root.Certificate.GetEncoded()) ? pki.RootOcsp
        : null;
}
