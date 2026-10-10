using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.Tsp;
using Org.BouncyCastle.Asn1.X509;
using BcBigInteger = Org.BouncyCastle.Math.BigInteger;

namespace UA.Cryptography.Tests.Support;

/// <summary>
/// A synthetic RFC 3161 time-stamping service. A token is a CMS SignedData whose content is a DER TSTInfo; its signer
/// carries contentType, messageDigest (hash of the TSTInfo) and signingCertificateV2, and signs with the algorithm that
/// matches the requested hash, as the national services do (docs/signature-formats.md, section 6).
/// </summary>
internal sealed class TimeStampAuthority(TestPki.TestIdentity identity)
{
    private long _serial;

    public TestPki.TestIdentity Identity { get; } = identity;

    /// <summary>A DER-encoded time-stamp token whose message imprint is the hash of <paramref name="covered"/>.</summary>
    public byte[] Stamp(byte[] covered, string hashOid, bool includeCertificate = true) =>
        StampHash(UaPki.Hash(hashOid, covered), hashOid, includeCertificate);

    /// <summary>A token over an already computed hash, with the request's nonce when one is given.</summary>
    public byte[] StampHash(byte[] hash, string hashOid, bool includeCertificate = true, BcBigInteger? nonce = null)
    {
        string policy = hashOid == Oids.Gost34311 ? Oids.TspPolicyGost34311 : Oids.TspPolicyDstu7564;
        var imprint = new MessageImprint(new AlgorithmIdentifier(new DerObjectIdentifier(hashOid)), hash);
        var info = new TstInfo(new DerObjectIdentifier(policy), imprint,
            new DerInteger(BcBigInteger.ValueOf(Interlocked.Increment(ref _serial))),
            new DerGeneralizedTime(DateTime.UtcNow), null, null, nonce is null ? null : new DerInteger(nonce), null, null);

        return CmsBuilder.Sign(info.GetDerEncoded(), PkcsObjectIdentifiers.IdCTTstInfo, encapsulate: true, Identity,
            includeCertificate ? [Identity.Certificate] : [], hashOid).GetDerEncoded();
    }
}
