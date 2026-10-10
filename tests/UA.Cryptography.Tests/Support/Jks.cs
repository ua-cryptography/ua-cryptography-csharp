using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.X509;
using UA.Cryptography.Dstu4145;
using UA.Cryptography.EC;
using UA.Cryptography.Gost;
using BigInteger = System.Numerics.BigInteger;

namespace UA.Cryptography.Tests.Support;

/// <summary>
/// Sun JKS key stores with a DSTU 4145 private key, the container some Ukrainian banks hand out (see
/// docs/signature-formats.md, "Key containers"). The private key is a PKCS#8 PrivateKeyInfo: version 0, the key's
/// AlgorithmIdentifier ({ named curve, DKE }) and d as a little-endian OCTET STRING.
/// </summary>
internal static class Jks
{
    private const uint Magic = 0xFEEDFEED;
    private const int Version = 2;
    private const string KeyProtectorOid = "1.3.6.1.4.1.42.2.17.1.1"; // Sun JKS key protector
    private static readonly byte[] IntegritySalt = Encoding.UTF8.GetBytes("Mighty Aphrodite");

    /// <summary>A key store entry read back: the private key, its domain and DKE, and the certificate chain.</summary>
    public sealed record Entry(string Alias, TestPki.TestKey Key, IReadOnlyList<X509Certificate> Chain);

    public static byte[] BuildPkcs8(TestPki.TestKey key)
    {
        byte[] d = TestPki.ToFixedLittleEndian(key.PrivateKey, (int)((key.Domain.N.GetBitLength() + 7) / 8));
        return new DerSequence(DerInteger.Zero, TestPki.KeyAlgorithmIdentifier(key), new DerOctetString(d)).GetDerEncoded();
    }

    /// <summary>Writes a key store holding one PrivateKeyEntry (the key and its certificate chain).</summary>
    public static byte[] Write(string alias, TestPki.TestKey key, IReadOnlyList<X509Certificate> chain, string password)
    {
        using var body = new MemoryStream();
        using var w = new BinaryWriter(body);
        WriteUInt32(w, Magic);
        WriteUInt32(w, Version);
        WriteUInt32(w, 1); // one entry
        WriteUInt32(w, 1); // tag 1 = PrivateKeyEntry
        WriteJavaUtf(w, alias);
        WriteUInt64(w, (ulong)DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());

        byte[] protectedKey = ProtectKey(BuildPkcs8(key), password);
        WriteUInt32(w, (uint)protectedKey.Length);
        w.Write(protectedKey);

        WriteUInt32(w, (uint)chain.Count);
        foreach (X509Certificate certificate in chain)
        {
            WriteJavaUtf(w, "X.509");
            byte[] der = certificate.GetEncoded();
            WriteUInt32(w, (uint)der.Length);
            w.Write(der);
        }

        w.Flush();
        byte[] content = body.ToArray();
        return [.. content, .. SHA1.HashData([.. PasswordBytes(password), .. IntegritySalt, .. content])];
    }

    /// <summary>Reads a single-entry key store, verifying its integrity and the key protector.</summary>
    public static Entry Read(byte[] jks, string password)
    {
        byte[] content = jks[..^20];
        if (!SHA1.HashData([.. PasswordBytes(password), .. IntegritySalt, .. content]).SequenceEqual(jks[^20..]))
            throw new CryptographicException("JKS integrity check failed (wrong password or tampered store).");

        int o = 0;
        if (ReadUInt32(content, ref o) != Magic)
            throw new InvalidDataException("Not a JKS store.");
        ReadUInt32(content, ref o); // version
        if (ReadUInt32(content, ref o) != 1)
            throw new NotSupportedException("Only single-entry stores are handled by the tests.");
        if (ReadUInt32(content, ref o) != 1)
            throw new NotSupportedException("Only PrivateKeyEntry is handled by the tests.");
        string alias = ReadJavaUtf(content, ref o);
        o += 8; // creation date

        int protectedLength = (int)ReadUInt32(content, ref o);
        byte[] pkcs8 = UnprotectKey(content[o..(o + protectedLength)], password);
        o += protectedLength;

        int count = (int)ReadUInt32(content, ref o);
        var chain = new List<X509Certificate>(count);
        for (int i = 0; i < count; i++)
        {
            ReadJavaUtf(content, ref o); // "X.509"
            int length = (int)ReadUInt32(content, ref o);
            chain.Add(new X509CertificateParser().ReadCertificate(content[o..(o + length)]));
            o += length;
        }

        return new Entry(alias, ParsePkcs8(pkcs8), chain);
    }

    private static TestPki.TestKey ParsePkcs8(byte[] pkcs8)
    {
        var sequence = (Asn1Sequence)Asn1Object.FromByteArray(pkcs8);
        var parameters = (Asn1Sequence)AlgorithmIdentifier.GetInstance(sequence[1]).Parameters;
        int index = int.Parse(((DerObjectIdentifier)parameters[0]).Id.Split('.').Last());
        byte[] dke = parameters.Count > 1 ? ((Asn1OctetString)parameters[1]).GetOctets() : Gost34311.DefaultDke.ToArray();
        BigInteger d = new(((Asn1OctetString)sequence[2]).GetOctets(), isUnsigned: true, isBigEndian: false);

        Dstu4145DomainParameters domain = Dstu4145NamedCurves.Polynomial(Dstu4145NamedCurves.PolynomialDegrees[index]);
        CurvePoint q = new Dstu4145Signer(domain).ComputePublicKey(d);
        return new TestPki.TestKey(domain, d, q, dke);
    }

    // The Sun key protector: salt(20) ‖ (key XOR keystream) ‖ SHA1(password ‖ key)(20),
    // keystream_i = SHA1(password ‖ previous), previous_0 = salt.
    private static byte[] ProtectKey(byte[] pkcs8, string password)
    {
        byte[] pw = PasswordBytes(password);
        byte[] salt = RandomNumberGenerator.GetBytes(20);
        byte[] encrypted = [.. salt, .. Xor(pkcs8, KeyStream(pw, salt, pkcs8.Length)), .. SHA1.HashData([.. pw, .. pkcs8])];
        return new DerSequence(
            new AlgorithmIdentifier(new DerObjectIdentifier(KeyProtectorOid), DerNull.Instance),
            new DerOctetString(encrypted)).GetDerEncoded();
    }

    private static byte[] UnprotectKey(byte[] encryptedPrivateKeyInfo, string password)
    {
        var sequence = (Asn1Sequence)Asn1Object.FromByteArray(encryptedPrivateKeyInfo);
        byte[] encrypted = ((Asn1OctetString)sequence[1]).GetOctets();
        byte[] pw = PasswordBytes(password);
        byte[] cipher = encrypted[20..^20];
        byte[] key = Xor(cipher, KeyStream(pw, encrypted[..20], cipher.Length));
        if (!SHA1.HashData([.. pw, .. key]).SequenceEqual(encrypted[^20..]))
            throw new CryptographicException("JKS key protector check failed (wrong password).");
        return key;
    }

    private static byte[] KeyStream(byte[] pw, byte[] salt, int length)
    {
        var stream = new byte[length];
        byte[] previous = salt;
        for (int offset = 0; offset < length; offset += 20)
        {
            previous = SHA1.HashData([.. pw, .. previous]);
            Array.Copy(previous, 0, stream, offset, System.Math.Min(20, length - offset));
        }
        return stream;
    }

    private static byte[] PasswordBytes(string password) => Encoding.BigEndianUnicode.GetBytes(password);

    private static byte[] Xor(byte[] a, byte[] b) => a.Zip(b, (x, y) => (byte)(x ^ y)).ToArray();

    private static void WriteUInt32(BinaryWriter w, uint value) =>
        w.Write([(byte)(value >> 24), (byte)(value >> 16), (byte)(value >> 8), (byte)value]);

    private static void WriteUInt64(BinaryWriter w, ulong value)
    {
        WriteUInt32(w, (uint)(value >> 32));
        WriteUInt32(w, (uint)value);
    }

    private static void WriteJavaUtf(BinaryWriter w, string s)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(s); // ASCII aliases only; no modified-UTF-8 edge cases here
        w.Write([(byte)(bytes.Length >> 8), (byte)bytes.Length]);
        w.Write(bytes);
    }

    private static uint ReadUInt32(byte[] b, ref int o)
    {
        uint v = (uint)((b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]);
        o += 4;
        return v;
    }

    private static string ReadJavaUtf(byte[] b, ref int o)
    {
        int length = (b[o] << 8) | b[o + 1];
        string s = Encoding.UTF8.GetString(b, o + 2, length);
        o += 2 + length;
        return s;
    }
}
