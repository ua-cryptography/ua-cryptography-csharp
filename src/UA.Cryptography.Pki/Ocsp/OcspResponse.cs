using System.Numerics;
using UA.Cryptography.Pki.Asn1;
using UA.Cryptography.Pki.X509;

namespace UA.Cryptography.Pki.Ocsp;

public enum OcspCertificateStatus
{
    Good,
    Revoked,
    Unknown,
}

/// <summary>A SingleResponse: the certificate identifier (CertID), its status and the validity interval.</summary>
public sealed record OcspSingleResponse(
    string HashAlgorithm,
    byte[] IssuerNameHash,
    byte[] IssuerKeyHash,
    BigInteger SerialNumber,
    OcspCertificateStatus Status,
    DateTimeOffset ThisUpdate,
    DateTimeOffset? NextUpdate,
    DateTimeOffset? RevocationTime)
{
    /// <summary>
    /// True when the CertID names <paramref name="certificate"/> issued by <paramref name="issuer"/>. An issuerKeyHash of
    /// zeros (the "Дія" responder sends one) is matched by the serial number and the name hash alone: the response must
    /// still be signed by the issuer or by a responder the issuer certified, which binds it to the issuer's key.
    /// </summary>
    public bool Matches(Certificate certificate, Certificate issuer) =>
        SerialNumber == certificate.SerialNumber
        && PkiAlgorithms.IsSupportedHash(HashAlgorithm)
        && IssuerNameHash.AsSpan().SequenceEqual(PkiAlgorithms.Hash(HashAlgorithm, issuer.Subject.Encoded))
        && (IsZeroKeyHash || IssuerKeyHash.AsSpan().SequenceEqual(PkiAlgorithms.Hash(HashAlgorithm, issuer.PublicKeyBits)));

    private bool IsZeroKeyHash => IssuerKeyHash.Length > 0 && !IssuerKeyHash.AsSpan().ContainsAnyExcept((byte)0);
}

/// <summary>
/// A BasicOCSPResponse (RFC 6960, 4.2.1) as used in the national PKI (docs/signature-formats.md, section 5): signed
/// over the DER tbsResponseData, the signature value is a BIT STRING wrapping an OCTET STRING with D, the responder is
/// identified by name or key hash and its certificate travels in the response.
/// </summary>
public sealed class OcspResponse
{
    private OcspResponse(byte[] basic)
    {
        BasicEncoded = basic;
        Asn1Node node = Asn1Node.Parse(basic).Expect(Asn1Tag.Sequence);
        Asn1Node tbs = node[0].Expect(Asn1Tag.Sequence);
        TbsResponseData = tbs.Encoded.ToArray();
        SignatureAlgorithm = node[1][0].GetOid();
        SignatureValue = node[2].GetBitString();
        Certificates = node.Count > 3 && node[3].IsContext(0)
            ? node[3][0].Children.Select(c => Certificate.Load(c.Encoded.Span)).ToList()
            : [];

        int i = tbs[0].IsContext(0) ? 1 : 0; // version [0] EXPLICIT DEFAULT v1
        Asn1Node responder = tbs[i++];
        ResponderIdEncoded = responder.Encoded.ToArray();
        if (responder.IsContext(1))
            ResponderName = DistinguishedName.FromAsn1(responder[0]);
        else if (responder.IsContext(2))
            ResponderKeyHash = responder[0].GetOctetString();
        ProducedAt = tbs[i++].GetTime();
        Responses = tbs[i].Children.Select(ParseSingle).ToList();
    }

    /// <summary>Parses a full OCSPResponse; throws unless its status is successful and it holds a basic response.</summary>
    public static OcspResponse Load(ReadOnlySpan<byte> data)
    {
        Asn1Node response = Asn1Node.Parse(data.ToArray()).Expect(Asn1Tag.Sequence);
        int status = response[0].Expect(Asn1Tag.Enumerated).Content.Span[0];
        if (status != 0)
            throw new InvalidDataException($"The OCSP responder returned status {status} ({StatusName(status)}).");
        Asn1Node bytes = response[1][0];
        if (bytes[0].GetOid() != Oids.OcspBasic)
            throw new InvalidDataException($"Unsupported OCSP response type {bytes[0].GetOid()}.");
        return new OcspResponse(bytes[1].GetOctetString());
    }

    /// <summary>Parses a BasicOCSPResponse, as CAdES revocationValues stores it.</summary>
    public static OcspResponse LoadBasic(ReadOnlySpan<byte> data) => new(data.ToArray());

    private static string StatusName(int status) => status switch
    {
        1 => "malformedRequest",
        2 => "internalError",
        3 => "tryLater",
        5 => "sigRequired",
        6 => "unauthorized",
        _ => "unknown",
    };

    /// <summary>The DER BasicOCSPResponse.</summary>
    public byte[] BasicEncoded { get; }

    /// <summary>The full OCSPResponse ("successful", id-pkix-ocsp-basic), as stored in XAdES and PDF.</summary>
    public byte[] FullEncoded => Der.Sequence(
        Der.Encode(Asn1Tag.Enumerated, [0]),
        Der.Explicit(0, Der.Sequence(Der.ObjectIdentifier(Oids.OcspBasic), Der.OctetString(BasicEncoded))));

    public byte[] TbsResponseData { get; }

    public byte[] ResponderIdEncoded { get; }

    public DistinguishedName? ResponderName { get; }

    public byte[]? ResponderKeyHash { get; }

    public DateTimeOffset ProducedAt { get; }

    public IReadOnlyList<OcspSingleResponse> Responses { get; }

    public string SignatureAlgorithm { get; }

    public byte[] SignatureValue { get; }

    public IReadOnlyList<Certificate> Certificates { get; }

    /// <summary>The response about <paramref name="certificate"/>, if this response has one.</summary>
    public OcspSingleResponse? Find(Certificate certificate, Certificate issuer) => Responses.FirstOrDefault(r => r.Matches(certificate, issuer));

    /// <summary>The responder's certificate: in the response or among <paramref name="known"/>, by name or by key hash.</summary>
    public Certificate? FindResponder(IEnumerable<Certificate> known) =>
        Certificates.Concat(known).FirstOrDefault(c => ResponderName is not null
            ? c.Subject.Equals(ResponderName)
            : ResponderKeyHash is not null && (c.SubjectKeyIdentifier?.AsSpan().SequenceEqual(ResponderKeyHash) == true
                || PkiAlgorithms.Hash(Oids.Sha1, c.PublicKeyBits).AsSpan().SequenceEqual(ResponderKeyHash)));

    public bool IsSignedBy(Certificate responder)
    {
        try
        {
            byte[] d = Asn1Node.Parse(SignatureValue).Expect(Asn1Tag.OctetString).GetOctetString();
            return responder.HasDstu4145Key && responder.PublicKey.Verify(SignatureAlgorithm, TbsResponseData, d);
        }
        catch (Exception e) when (e is InvalidDataException or NotSupportedException or ArgumentException)
        {
            return false;
        }
    }

    // SingleResponse ::= SEQUENCE { certID, certStatus CHOICE { good [0] NULL, revoked [1] RevokedInfo, unknown [2] NULL },
    //                               thisUpdate GeneralizedTime, nextUpdate [0] EXPLICIT OPTIONAL, singleExtensions [1] OPTIONAL }
    private static OcspSingleResponse ParseSingle(Asn1Node single)
    {
        Asn1Node certId = single[0];
        Asn1Node status = single[1];
        (OcspCertificateStatus value, DateTimeOffset? revoked) = status.IsContext(0)
            ? (OcspCertificateStatus.Good, (DateTimeOffset?)null)
            : status.IsContext(1)
                ? (OcspCertificateStatus.Revoked, status[0].GetTime()) // [1] IMPLICIT RevokedInfo { revocationTime, reason }
                : (OcspCertificateStatus.Unknown, null);
        DateTimeOffset? next = single.Count > 3 && single[3].IsContext(0) ? single[3][0].GetTime() : null;
        return new OcspSingleResponse(certId[0][0].GetOid(), certId[1].GetOctetString(), certId[2].GetOctetString(), certId[3].GetInteger(),
            value, single[2].GetTime(), next, revoked);
    }

    /// <summary>
    /// OCSPRequest for one certificate with a nonce: CertID hashes the issuer's name and key with <paramref name="hashOid"/>.
    /// </summary>
    public static byte[] CreateRequest(Certificate certificate, Certificate issuer, string hashOid, byte[] nonce)
    {
        byte[] certId = Der.Sequence(
            Der.AlgorithmIdentifier(hashOid),
            Der.OctetString(PkiAlgorithms.Hash(hashOid, issuer.Subject.Encoded)),
            Der.OctetString(PkiAlgorithms.Hash(hashOid, issuer.PublicKeyBits)),
            Der.Integer(certificate.SerialNumber));
        byte[] nonceExtension = Der.Sequence(Der.ObjectIdentifier(Oids.OcspNonce), Der.OctetString(Der.OctetString(nonce)));
        byte[] tbsRequest = Der.Sequence(Der.Sequence(Der.Sequence(certId)), Der.Explicit(2, Der.Sequence(nonceExtension)));
        return Der.Sequence(tbsRequest);
    }
}
