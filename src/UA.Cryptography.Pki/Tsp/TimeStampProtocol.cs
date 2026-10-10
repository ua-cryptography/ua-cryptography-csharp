using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using UA.Cryptography.Pki.Asn1;

namespace UA.Cryptography.Pki.Tsp;

/// <summary>The messages of the time-stamp protocol (RFC 3161, 2.4).</summary>
public static class TimeStampProtocol
{
    public const string RequestMediaType = "application/timestamp-query";
    public const string ResponseMediaType = "application/timestamp-reply";

    /// <summary>A fresh 64-bit nonce for a request.</summary>
    public static BigInteger NewNonce() => new(RandomNumberGenerator.GetBytes(8), isUnsigned: true);

    /// <summary>
    /// TimeStampReq ::= SEQUENCE { version 1, messageImprint, reqPolicy OPTIONAL, nonce, certReq TRUE }: the service is
    /// asked to include its certificate.
    /// </summary>
    public static byte[] CreateRequest(byte[] hash, string hashOid, BigInteger nonce, string? policy = null)
    {
        var fields = new List<byte[]>
        {
            Der.Integer(1),
            Der.Sequence(Der.AlgorithmIdentifier(hashOid), Der.OctetString(hash)),
        };
        if (policy is not null)
            fields.Add(Der.ObjectIdentifier(policy));
        fields.Add(Der.Integer(nonce));
        fields.Add(Der.Boolean(true));
        return Der.Sequence(fields);
    }

    /// <summary>
    /// Parses TimeStampResp ::= SEQUENCE { status PKIStatusInfo, timeStampToken OPTIONAL } and checks that the token answers
    /// the request: status granted (0) or grantedWithMods (1), the same imprint and nonce.
    /// </summary>
    public static TimeStampToken ParseResponse(byte[] response, byte[] hash, string hashOid, BigInteger nonce)
    {
        Asn1Node resp = Asn1Node.Parse(response).Expect(Asn1Tag.Sequence);
        Asn1Node statusInfo = resp[0];
        int status = statusInfo[0].GetInt32();
        if (status is not (0 or 1))
        {
            string text = statusInfo.Count > 1 && statusInfo[1].Is(Asn1Tag.Sequence)
                ? string.Join("; ", statusInfo[1].Children.Select(s => s.GetString()))
                : "";
            throw new InvalidDataException($"The time-stamping service refused the request (status {status}) {text}".Trim());
        }
        if (resp.Count < 2)
            throw new InvalidDataException("The time-stamp response has no token.");

        TimeStampToken token = TimeStampToken.Load(resp[1].Encoded.Span);
        if (token.ImprintAlgorithm != hashOid || !token.Imprint.AsSpan().SequenceEqual(hash))
            throw new InvalidDataException("The time-stamp token covers other data than requested.");
        if (token.Nonce != nonce)
            throw new InvalidDataException("The time-stamp token has a different nonce than requested.");
        return token;
    }

    internal static string Describe(byte[] body) => Encoding.ASCII.GetString(body, 0, System.Math.Min(body.Length, 200));
}
