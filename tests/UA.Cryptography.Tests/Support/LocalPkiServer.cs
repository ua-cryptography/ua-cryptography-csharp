using System.Net;
using System.Net.Sockets;
using System.Text;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cmp;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.Tsp;
using X509Certificate = Org.BouncyCastle.X509.X509Certificate;

namespace UA.Cryptography.Tests.Support;

/// <summary>
/// The <see cref="Hierarchy"/>'s time-stamping service and OCSP responders over HTTP on 127.0.0.1 — a minimal HTTP/1.1
/// server on a raw socket (no platform HTTP stack), enough for the package's HTTP clients and for the command-line tool.
/// Requests are parsed by BouncyCastle (<see cref="TimeStampRequest"/>, <see cref="OcspReq"/>), independently of the
/// package's encoders.
/// </summary>
internal sealed class LocalPkiServer : IDisposable
{
    private readonly TcpListener _listener;
    private readonly Hierarchy _pki;
    private readonly CancellationTokenSource _stop = new();
    private readonly Task _loop;

    public LocalPkiServer(Hierarchy pki)
    {
        _pki = pki;
        _listener = new TcpListener(IPAddress.Loopback, 0);
        _listener.Start();
        int port = ((IPEndPoint)_listener.LocalEndpoint).Port;
        TsaUrl = $"http://127.0.0.1:{port}/tsp";
        OcspUrl = $"http://127.0.0.1:{port}/ocsp";
        CaIssuersUrl = $"http://127.0.0.1:{port}/ca.p7b";
        _loop = Task.Run(Serve);
    }

    public string TsaUrl { get; }

    public string OcspUrl { get; }

    /// <summary>
    /// A certs-only CMS bundle (.p7b) with the provider's certificates — the issuing CA, the TSA and the OCSP responder —
    /// as qualified providers publish at their certificates' caIssuers address.
    /// </summary>
    public string CaIssuersUrl { get; }

    public int CaIssuersRequests { get; private set; }

    /// <summary>
    /// More certificates issued by the hierarchy's CAs that the OCSP responders answer for — added after the server
    /// starts, since such a certificate names the server's addresses.
    /// </summary>
    public List<X509Certificate> ExtraCertificates { get; } = [];

    public int TimeStampRequests { get; private set; }

    public int OcspRequests { get; private set; }

    private async Task Serve()
    {
        while (!_stop.IsCancellationRequested)
        {
            TcpClient client;
            try
            {
                client = await _listener.AcceptTcpClientAsync(_stop.Token);
            }
            catch (Exception e) when (e is OperationCanceledException or ObjectDisposedException or SocketException)
            {
                return;
            }
            _ = Task.Run(() => Handle(client));
        }
    }

    private void Handle(TcpClient client)
    {
        using (client)
        using (NetworkStream stream = client.GetStream())
        {
            // Request line and headers, then exactly Content-Length bytes of body.
            var header = new List<byte>();
            while (header.Count < 4 || !(header[^4] == '\r' && header[^3] == '\n' && header[^2] == '\r' && header[^1] == '\n'))
            {
                int b = stream.ReadByte();
                if (b < 0)
                    return;
                header.Add((byte)b);
            }
            string[] lines = Encoding.ASCII.GetString(header.ToArray()).Split("\r\n");
            string path = lines[0].Split(' ')[1];
            int length = lines.Where(l => l.StartsWith("Content-Length:", StringComparison.OrdinalIgnoreCase))
                .Select(l => int.Parse(l["Content-Length:".Length..].Trim())).FirstOrDefault();
            var body = new byte[length];
            for (int read = 0; read < length;)
                read += stream.Read(body, read, length - read);

            (int status, byte[] content, string type) = path switch
            {
                "/tsp" => (200, TimeStamp(body), "application/timestamp-reply"),
                "/ocsp" => (200, Ocsp(body), "application/ocsp-response"),
                "/ca.p7b" => (200, CaIssuers(), "application/pkcs7-mime"),
                _ => (404, Encoding.ASCII.GetBytes("not found"), "text/plain"),
            };
            byte[] head = Encoding.ASCII.GetBytes(
                $"HTTP/1.1 {status} {(status == 200 ? "OK" : "Not Found")}\r\nContent-Type: {type}\r\nContent-Length: {content.Length}\r\nConnection: close\r\n\r\n");
            stream.Write(head);
            stream.Write(content);
        }
    }

    private byte[] TimeStamp(byte[] body)
    {
        TimeStampRequests++;
        var request = new TimeStampRequest(body);
        byte[] token = _pki.Tsa.StampHash(request.GetMessageImprintDigest(), request.MessageImprintAlgOid, request.CertReq, request.Nonce);
        return new Org.BouncyCastle.Asn1.Tsp.TimeStampResp(new PkiStatusInfo(0), ContentInfo.GetInstance(Asn1Object.FromByteArray(token)))
            .GetDerEncoded();
    }

    private byte[] Ocsp(byte[] body)
    {
        OcspRequests++;
        CertificateID id = new OcspReq(body).GetRequestList()[0].GetCertID();
        X509Certificate[] all = [_pki.Signer.Certificate, .. _pki.ValidationCertificates, .. ExtraCertificates];
        X509Certificate subject = all.Single(c => c.SerialNumber.Equals(id.SerialNumber));
        X509Certificate issuer = all.Single(c => c.SubjectDN.Equivalent(subject.IssuerDN));
        OcspResponder responder = PkiLayer.Responder(_pki, issuer.ToPki()) ?? throw new InvalidOperationException("No responder");
        return OcspResponder.Encode(responder.Respond(subject, issuer));
    }

    private byte[] CaIssuers()
    {
        CaIssuersRequests++;
        X509Certificate[] bundle = [_pki.IssuingCa.Certificate, _pki.Tsa.Identity.Certificate, _pki.IssuingCaOcsp.Identity.Certificate];
        var certsOnly = new SignedData(new DerSet(), new ContentInfo(CmsObjectIdentifiers.Data, null),
            new DerSet(bundle.Select(c => (Asn1Encodable)c.CertificateStructure).ToArray()), null, new DerSet());
        return new ContentInfo(CmsObjectIdentifiers.SignedData, certsOnly).GetDerEncoded();
    }

    public void Dispose()
    {
        _stop.Cancel();
        _listener.Stop();
        try
        {
            _loop.Wait(TimeSpan.FromSeconds(5));
        }
        catch (AggregateException)
        {
            // stopped
        }
        _stop.Dispose();
    }
}
