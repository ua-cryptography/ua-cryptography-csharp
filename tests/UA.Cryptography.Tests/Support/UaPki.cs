using System.Numerics;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Ess;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.Tsp;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cms;
using UA.Cryptography.Dstu4145;
using UA.Cryptography.Dstu7564;
using UA.Cryptography.EC;
using UA.Cryptography.Gost;
using UA.Cryptography.Math;
using X509Certificate = Org.BouncyCastle.X509.X509Certificate;
using X509CertificateParser = Org.BouncyCastle.X509.X509CertificateParser;

namespace UA.Cryptography.Tests.Support;

/// <summary>
/// The verifying side of the Ukrainian PKI conventions (docs/signature-formats.md): hashes by OID, DSTU 4145 keys in
/// certificates, and the checks of certificates, CMS signers, time-stamps and OCSP responses. BouncyCastle only splits
/// the DER; every hash and every DSTU 4145 verification is done by this library.
/// </summary>
internal static class UaPki
{
    public static byte[] Reverse(byte[] b) => b.Reverse().ToArray();

    public static BigInteger BigEndian(byte[] b) => new(b, isUnsigned: true, isBigEndian: true);

    /// <summary>Hash by its ASN.1 algorithm identifier; GOST 34.311 uses <paramref name="dke"/> or DKE No. 1.</summary>
    public static byte[] Hash(string oid, byte[] data, byte[]? dke = null) => oid switch
    {
        Oids.Gost34311 when dke is null => Gost34311.HashData(data),
        Oids.Gost34311 => Gost34311.FromDke(dke).ComputeHash(data),
        Oids.Dstu7564_256 => Dstu7564Hash.HashData(data, 256),
        _ => throw new NotSupportedException($"Hash algorithm {oid}"),
    };

    /// <summary>The hash a signature algorithm ("DSTU 4145 with …") or a bare hash OID stands for.</summary>
    public static string HashOf(string algorithm) => algorithm switch
    {
        Oids.Dstu4145WithDstu7564 => Oids.Dstu7564_256,
        Oids.Dstu4145WithGost34311 => Oids.Gost34311,
        _ => algorithm,
    };

    /// <summary>The signature algorithm that goes with a hash: the pairs found in the national PKI.</summary>
    public static string SignatureAlgorithmFor(string hashOid) => hashOid switch
    {
        Oids.Dstu7564_256 => Oids.Dstu4145WithDstu7564,
        Oids.Gost34311 => Oids.Dstu4145WithGost34311,
        _ => throw new NotSupportedException($"Hash algorithm {hashOid}"),
    };

    /// <summary>
    /// Ukrainian PKI convention for DSTU 4145 signatures: the hash bytes are reversed before 5.9 and the signature
    /// value D = S‖R (5.10) is stored little-endian. Both GOST 34.311 and DSTU 7564 follow it.
    /// </summary>
    public static bool VerifyDstu4145(Dstu4145DomainParameters parameters, CurvePoint publicKey, byte[] hash, byte[] signature) =>
        new Dstu4145Signer(parameters).VerifyHash(publicKey, Reverse(hash), Reverse(signature));

    /// <summary>Signatures in certificates and OCSP responses: a BIT STRING that wraps an OCTET STRING with D.</summary>
    public static byte[] UnwrapSignature(byte[] bitString) => ((Asn1OctetString)Asn1Object.FromByteArray(bitString)).GetOctets();

    /// <summary>
    /// The certificate is signed by the issuer's key. The hash comes from the certificate's signature algorithm;
    /// GOST 34.311 takes its substitution table from the issuer's key parameters (DKE No. 1 when there is none).
    /// </summary>
    public static bool VerifyCertificate(X509Certificate certificate, X509Certificate issuer)
    {
        var (parameters, key, dke) = ReadPublicKey(issuer);
        byte[] hash = Hash(HashOf(certificate.SigAlgOid), certificate.GetTbsCertificate(), dke);
        return VerifyDstu4145(parameters, key, hash, UnwrapSignature(certificate.GetSignature()));
    }

    /// <summary>
    /// A CMS signer (CAdES signature or time-stamp token): signingCertificateV2 names the certificate, and the signature
    /// over the DER signed attributes verifies with its key. The signature field holds D directly.
    /// </summary>
    public static bool VerifyCmsSigner(SignerInformation signer, X509Certificate certificate)
    {
        var id = SigningCertificateV2.GetInstance(SignedAttribute(signer, PkcsObjectIdentifiers.IdAASigningCertificateV2));
        EssCertIDv2 certId = id.GetCerts()[0];
        if (!Hash(certId.HashAlgorithm.Algorithm.Id, certificate.GetEncoded()).SequenceEqual(certId.GetCertHash()))
            return false;
        var (parameters, key, _) = ReadPublicKey(certificate);
        byte[] hash = Hash(signer.DigestAlgorithmID.Algorithm.Id, signer.GetEncodedSignedAttributes());
        return VerifyDstu4145(parameters, key, hash, signer.GetSignature());
    }

    public static Asn1Encodable SignedAttribute(SignerInformation signer, DerObjectIdentifier oid) =>
        (signer.SignedAttributes?[oid] ?? throw new InvalidDataException($"Signed attribute {oid} is missing")).AttrValues[0];

    public static Asn1Encodable UnsignedAttribute(SignerInformation signer, DerObjectIdentifier oid) =>
        (signer.UnsignedAttributes?[oid] ?? throw new InvalidDataException($"Unsigned attribute {oid} is missing")).AttrValues[0];

    public static byte[] MessageDigest(SignerInformation signer) =>
        ((Asn1OctetString)SignedAttribute(signer, PkcsObjectIdentifiers.Pkcs9AtMessageDigest)).GetOctets();

    /// <summary>The TSTInfo of an RFC 3161 time-stamp token, after checking that messageDigest covers it.</summary>
    public static TstInfo ReadTimeStamp(CmsSignedData token)
    {
        Assert.Equal(PkcsObjectIdentifiers.IdCTTstInfo.Id, token.SignedContentType.Id);
        var encapsulated = Org.BouncyCastle.Asn1.Cms.SignedData.GetInstance(token.ContentInfo.Content).EncapContentInfo;
        byte[] content = ((Asn1OctetString)encapsulated.Content).GetOctets();
        SignerInformation signer = Assert.Single(token.GetSignerInfos().GetSigners());
        Assert.Equal(Hash(signer.DigestAlgorithmID.Algorithm.Id, content), MessageDigest(signer));
        return TstInfo.GetInstance(Asn1Object.FromByteArray(content));
    }

    /// <summary>The message imprint of a time-stamp matches <paramref name="covered"/>; the hash is not reversed.</summary>
    public static bool ImprintCovers(TstInfo info, byte[] covered) =>
        Hash(info.MessageImprint.HashAlgorithm.Algorithm.Id, covered).SequenceEqual(info.MessageImprint.GetHashedMessage());

    /// <summary>
    /// The time-stamping service's certificate: from the token itself or among the known ones (by issuer and serial
    /// number), or null when it is not available.
    /// </summary>
    public static X509Certificate? FindTimeStampSigner(CmsSignedData token, IEnumerable<X509Certificate> known)
    {
        SignerInformation tsa = Assert.Single(token.GetSignerInfos().GetSigners());
        return token.GetCertificates().EnumerateMatches(tsa.SignerID).Concat(known)
            .FirstOrDefault(c => c.SerialNumber.Equals(tsa.SignerID.SerialNumber) && c.IssuerDN.Equivalent(tsa.SignerID.Issuer));
    }

    /// <summary>The OCSP responder's certificate: in the response itself or among the known ones.</summary>
    public static X509Certificate FindOcspResponder(BasicOcspResponse response, IEnumerable<X509Certificate> known)
    {
        IEnumerable<X509Certificate> candidates = (response.Certs?.Cast<Asn1Encodable>() ?? [])
            .Select(c => new X509Certificate(X509CertificateStructure.GetInstance(c)))
            .Concat(known);
        ResponderID id = response.TbsResponseData.ResponderID;
        X509Name? name = id.Name;
        byte[]? keyHash = id.GetKeyHash();
        return candidates.First(c => name is not null
            ? c.SubjectDN.Equivalent(name)
            : c.GetExtensionValue(X509Extensions.SubjectKeyIdentifier) is { } skid
              && SubjectKeyIdentifier.GetInstance(Asn1Object.FromByteArray(skid.GetOctets())).GetKeyIdentifier().SequenceEqual(keyHash!));
    }

    /// <summary>The OCSP response is signed by the responder over the DER tbsResponseData.</summary>
    public static bool VerifyOcsp(BasicOcspResponse response, X509Certificate responder)
    {
        var (parameters, key, dke) = ReadPublicKey(responder);
        byte[] hash = Hash(HashOf(response.SignatureAlgorithm.Algorithm.Id), response.TbsResponseData.GetDerEncoded(), dke);
        return VerifyDstu4145(parameters, key, hash, UnwrapSignature(response.GetSignatureOctets()));
    }

    /// <summary>The BasicOCSPResponse inside a full OCSPResponse, after checking that the response is "successful".</summary>
    public static BasicOcspResponse ReadOcspResponse(byte[] der)
    {
        var response = OcspResponse.GetInstance(Asn1Object.FromByteArray(der));
        Assert.Equal(OcspResponseStatus.Successful, response.ResponseStatus.IntValueExact);
        Assert.Equal(OcspObjectIdentifiers.PkixOcspBasic, response.ResponseBytes.ResponseType);
        return BasicOcspResponse.GetInstance(Asn1Object.FromByteArray(response.ResponseBytes.Response.GetOctets()));
    }

    public static X509Certificate ParseCertificate(byte[] der) => new X509CertificateParser().ReadCertificate(der);

    /// <summary>
    /// Parses the DSTU 4145 parameters, the public key and the optional DKE from SubjectPublicKeyInfo.
    /// Parameters are either a named curve OID (1.2.804.2.1.1.1.1.3.1.1.2.i, the i-th curve of table Г.1) or
    /// an explicit ECBinary structure; the DKE (GOST 34.311 S-box) follows when present.
    /// The parameters are checked by section 8 and the key by 10.1.
    /// </summary>
    public static (Dstu4145DomainParameters Parameters, CurvePoint PublicKey, byte[]? Dke) ReadPublicKey(X509Certificate certificate)
    {
        var spki = certificate.CertificateStructure.SubjectPublicKeyInfo;
        bool littleEndian = spki.Algorithm.Algorithm.Id == Oids.Dstu4145Le;
        var parameters = (Asn1Sequence)spki.Algorithm.Parameters;
        byte[]? dke = parameters.Count > 1 ? ((Asn1OctetString)parameters[1]).GetOctets() : null;

        Dstu4145DomainParameters domain;
        if (parameters[0] is DerObjectIdentifier namedCurve)
        {
            int index = int.Parse(namedCurve.Id.Split('.').Last());
            domain = Dstu4145NamedCurves.Polynomial(Dstu4145NamedCurves.PolynomialDegrees[index]);
        }
        else
        {
            var ec = (Asn1Sequence)parameters[0];
            var fieldSeq = (Asn1Sequence)ec[0];
            int m = ((DerInteger)fieldSeq[0]).IntValueExact;
            PolynomialBasisField field = fieldSeq[1] is DerInteger k
                ? new PolynomialBasisField(m, k.IntValueExact)
                : new PolynomialBasisField(m,
                    ((DerInteger)((Asn1Sequence)fieldSeq[1])[0]).IntValueExact,
                    ((DerInteger)((Asn1Sequence)fieldSeq[1])[1]).IntValueExact,
                    ((DerInteger)((Asn1Sequence)fieldSeq[1])[2]).IntValueExact);
            int a = ((DerInteger)ec[1]).IntValueExact;
            byte[] b = ((Asn1OctetString)ec[2]).GetOctets();
            BigInteger n = BigEndian(((DerInteger)ec[3]).Value.ToByteArrayUnsigned());
            byte[] g = ((Asn1OctetString)ec[4]).GetOctets();
            if (littleEndian)
            {
                b = Reverse(b);
                g = Reverse(g);
            }
            var curve = new BinaryCurve(field, a, BigEndian(b));
            domain = new Dstu4145DomainParameters(curve, curve.Decompress(BigEndian(g)), n);
            Assert.Null(domain.Validate());
        }

        byte[] q = ((Asn1OctetString)Asn1Object.FromByteArray(spki.PublicKey.GetBytes())).GetOctets();
        if (littleEndian)
            q = Reverse(q);
        CurvePoint publicKey = domain.Curve.Decompress(BigEndian(q));
        Assert.Null(domain.ValidatePublicKey(publicKey));
        return (domain, publicKey, dke);
    }

    /// <summary>
    /// Walks issuer links (by DN) from <paramref name="leaf"/>, verifying each with the issuer's key, up to a
    /// self-signed root; succeeds only when that root verifies itself and is one of <paramref name="trusted"/>.
    /// </summary>
    public static bool ChainsToTrusted(X509Certificate leaf, IReadOnlyCollection<X509Certificate> pool, IReadOnlyCollection<X509Certificate> trusted)
    {
        X509Certificate current = leaf;
        for (int depth = 0; depth < 10; depth++)
        {
            if (current.SubjectDN.Equivalent(current.IssuerDN))
                return VerifyCertificate(current, current) && trusted.Any(t => t.GetEncoded().SequenceEqual(current.GetEncoded()));
            X509Certificate? issuer = pool.FirstOrDefault(c => c.SubjectDN.Equivalent(current.IssuerDN) && !c.Equals(current));
            if (issuer is null || !VerifyCertificate(current, issuer))
                return false;
            current = issuer;
        }
        return false;
    }
}
