using System.Net.Http.Headers;
using System.Security.Cryptography;
using UA.Cryptography.Pki.Asn1;
using UA.Cryptography.Pki.Cms;
using UA.Cryptography.Pki.Ocsp;
using UA.Cryptography.Pki.Tsp;
using UA.Cryptography.Pki.X509;

namespace UA.Cryptography.Pki.Services;

/// <summary>A time-stamping service.</summary>
public interface ITimeStampService
{
    /// <summary>A token whose message imprint is <paramref name="hash"/>.</summary>
    TimeStampToken GetToken(byte[] hash, string hashOid);
}

/// <summary>An OCSP service.</summary>
public interface IOcspService
{
    /// <summary>A response about <paramref name="certificate"/>, or null when no responder is known for it.</summary>
    OcspResponse? GetResponse(Certificate certificate, Certificate issuer, string hashOid);
}

/// <summary>Downloads CA certificates named by authorityInfoAccess (caIssuers): DER, PEM or a CMS bundle (.p7b/.p7c).</summary>
public interface ICertificateSource
{
    IReadOnlyList<Certificate> Download(string url);
}

/// <summary>HTTP transport shared by the services (POST of DER bodies, RFC 3161 section 3.4 and RFC 6960 appendix A).</summary>
public static class PkiHttp
{
    private static readonly Lazy<HttpClient> SharedClient = new(() =>
    {
        var client = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
        client.DefaultRequestHeaders.UserAgent.ParseAdd("UA.Cryptography.Pki");
        return client;
    });

    public static HttpClient Client => SharedClient.Value;

    public static byte[] Post(HttpClient client, string url, byte[] body, string mediaType)
    {
        using var content = new ByteArrayContent(body);
        content.Headers.ContentType = new MediaTypeHeaderValue(mediaType);
        using var request = new HttpRequestMessage(HttpMethod.Post, url) { Content = content };
        return Send(client, request, url);
    }

    public static byte[] Get(HttpClient client, string url)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        return Send(client, request, url);
    }

    /// <summary>The largest response accepted: time-stamps, OCSP responses and CA certificates are a few kilobytes.</summary>
    public const int MaxResponseBytes = 10 << 20;

    private static byte[] Send(HttpClient client, HttpRequestMessage request, string url)
    {
        using HttpResponseMessage response = client.Send(request, HttpCompletionOption.ResponseHeadersRead);
        if (!response.IsSuccessStatusCode)
            throw new HttpRequestException($"{url} answered {(int)response.StatusCode} {response.ReasonPhrase}.");
        using Stream body = response.Content.ReadAsStream();
        using var buffer = new MemoryStream();
        var chunk = new byte[16384];
        int read;
        while ((read = body.Read(chunk)) > 0)
        {
            if (buffer.Length + read > MaxResponseBytes)
                throw new HttpRequestException($"{url} answered with more than {MaxResponseBytes} bytes.");
            buffer.Write(chunk, 0, read);
        }
        return buffer.ToArray();
    }
}

/// <summary>An RFC 3161 service over HTTP.</summary>
public sealed class HttpTimeStampService(string url, HttpClient? client = null) : ITimeStampService
{
    public string Url { get; } = url;

    public TimeStampToken GetToken(byte[] hash, string hashOid)
    {
        var nonce = TimeStampProtocol.NewNonce();
        byte[] request = TimeStampProtocol.CreateRequest(hash, hashOid, nonce);
        byte[] response = PkiHttp.Post(client ?? PkiHttp.Client, Url, request, TimeStampProtocol.RequestMediaType);
        return TimeStampProtocol.ParseResponse(response, hash, hashOid, nonce);
    }
}

/// <summary>
/// OCSP over HTTP. The responder is the URL from the certificate's authorityInfoAccess, unless
/// <paramref name="overrideUrl"/> is given.
/// </summary>
public sealed class HttpOcspService(string? overrideUrl = null, HttpClient? client = null) : IOcspService
{
    public OcspResponse? GetResponse(Certificate certificate, Certificate issuer, string hashOid)
    {
        string? url = overrideUrl ?? certificate.OcspUrls.FirstOrDefault();
        if (url is null)
            return null;
        byte[] request = OcspResponse.CreateRequest(certificate, issuer, hashOid, RandomNumberGenerator.GetBytes(16));
        return OcspResponse.Load(PkiHttp.Post(client ?? PkiHttp.Client, url, request, "application/ocsp-request"));
    }
}

/// <summary>Downloads certificates over HTTP.</summary>
public sealed class HttpCertificateSource(HttpClient? client = null) : ICertificateSource
{
    public IReadOnlyList<Certificate> Download(string url) => CertificateFiles.Parse(PkiHttp.Get(client ?? PkiHttp.Client, url));
}

/// <summary>Reads certificates from files: DER, PEM (one or several blocks) or a CMS certificate bundle.</summary>
public static class CertificateFiles
{
    public static IReadOnlyList<Certificate> Parse(byte[] data)
    {
        string text = System.Text.Encoding.ASCII.GetString(data);
        if (text.Contains("-----BEGIN CERTIFICATE-----", StringComparison.Ordinal))
        {
            return text.Split("-----END CERTIFICATE-----", StringSplitOptions.RemoveEmptyEntries)
                .Where(b => b.Contains("-----BEGIN CERTIFICATE-----", StringComparison.Ordinal))
                .Select(b => Certificate.Load(System.Text.Encoding.ASCII.GetBytes(b + "-----END CERTIFICATE-----")))
                .ToList();
        }
        byte[] der = Pem.Decode(data, "CERTIFICATE");
        Asn1Node node = Asn1Node.Parse(der);
        return node[0].Is(Asn1Tag.ObjectIdentifier) ? SignedData.Load(der).Certificates : [Certificate.Load(der)];
    }

    public static IReadOnlyList<Certificate> Load(string path) => Parse(File.ReadAllBytes(path));
}
