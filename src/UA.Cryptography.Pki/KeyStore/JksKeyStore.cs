using System.Security.Cryptography;
using System.Text;
using UA.Cryptography.Pki.Asn1;
using UA.Cryptography.Pki.X509;

namespace UA.Cryptography.Pki.KeyStore;

/// <summary>An entry of a key store.</summary>
public abstract class JksEntry(string alias, DateTimeOffset created)
{
    public string Alias { get; } = alias;

    public DateTimeOffset Created { get; } = created;
}

/// <summary>A PrivateKeyEntry: the key protected by the Sun key protector and its certificate chain (end entity first).</summary>
public sealed class JksPrivateKeyEntry(string alias, DateTimeOffset created, byte[] protectedKey, IReadOnlyList<Certificate> chain)
    : JksEntry(alias, created)
{
    /// <summary>The DER EncryptedPrivateKeyInfo as stored.</summary>
    public byte[] ProtectedKey { get; } = protectedKey;

    public IReadOnlyList<Certificate> Chain { get; } = chain;

    /// <summary>The PKCS#8 PrivateKeyInfo. The caller should wipe it after use.</summary>
    public byte[] DecryptPkcs8(string password) => JksKeyStore.UnprotectKey(ProtectedKey, password);

    /// <summary>The DSTU 4145 private key; when a certificate is present, its public key must match.</summary>
    public Dstu4145PrivateKey GetPrivateKey(string password)
    {
        byte[] pkcs8 = DecryptPkcs8(password);
        try
        {
            Dstu4145PrivateKey key = Dstu4145PrivateKey.FromPkcs8(pkcs8);
            if (Chain.Count > 0 && Chain[0].HasDstu4145Key && !Chain[0].PublicKey.Q.Equals(key.PublicKey.Q))
                throw new InvalidDataException($"The private key of '{Alias}' does not match its certificate.");
            return key;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(pkcs8);
        }
    }
}

/// <summary>A TrustedCertEntry.</summary>
public sealed class JksTrustedCertificateEntry(string alias, DateTimeOffset created, Certificate certificate) : JksEntry(alias, created)
{
    public Certificate Certificate { get; } = certificate;
}

/// <summary>
/// Sun JKS key store (docs/signature-formats.md, section 14), the container in which some Ukrainian banks issue DSTU 4145
/// keys. Layout (all integers big-endian): magic FEEDFEED, version 2, entry count, entries, then SHA-1 over the password
/// (UTF-16BE), the string "Mighty Aphrodite" and everything before it. A PrivateKeyEntry holds an EncryptedPrivateKeyInfo
/// under the Sun key protector (1.3.6.1.4.1.42.2.17.1.1): salt(20) ‖ key XOR keystream ‖ SHA-1(password ‖ key), where
/// keystream block i = SHA-1(password ‖ block i − 1) and block 0 is the salt.
/// </summary>
public sealed class JksKeyStore
{
    private const uint Magic = 0xFEEDFEED;
    private const int PrivateKeyTag = 1;
    private const int TrustedCertificateTag = 2;
    private static readonly byte[] IntegritySalt = Encoding.UTF8.GetBytes("Mighty Aphrodite");

    private readonly List<JksEntry> _entries = [];

    public IReadOnlyList<JksEntry> Entries => _entries;

    public IEnumerable<JksPrivateKeyEntry> PrivateKeys => _entries.OfType<JksPrivateKeyEntry>();

    public JksEntry? Find(string alias) => _entries.FirstOrDefault(e => e.Alias.Equals(alias, StringComparison.OrdinalIgnoreCase));

    /// <summary>Adds a private key protected with <paramref name="password"/>, with its certificate chain (end entity first).</summary>
    public JksPrivateKeyEntry AddPrivateKey(string alias, Dstu4145PrivateKey key, IReadOnlyList<Certificate> chain, string password)
    {
        if (Find(alias) is not null)
            throw new ArgumentException($"The key store already has an entry '{alias}'.", nameof(alias));
        byte[] pkcs8 = key.ToPkcs8();
        try
        {
            var entry = new JksPrivateKeyEntry(alias, DateTimeOffset.UtcNow, ProtectKey(pkcs8, password), chain);
            _entries.Add(entry);
            return entry;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(pkcs8);
        }
    }

    public JksTrustedCertificateEntry AddTrustedCertificate(string alias, Certificate certificate)
    {
        if (Find(alias) is not null)
            throw new ArgumentException($"The key store already has an entry '{alias}'.", nameof(alias));
        var entry = new JksTrustedCertificateEntry(alias, DateTimeOffset.UtcNow, certificate);
        _entries.Add(entry);
        return entry;
    }

    // ---- Reading -----------------------------------------------------------------------------------------------

    /// <summary>Reads a key store after checking its integrity with <paramref name="password"/>.</summary>
    public static JksKeyStore Load(byte[] data, string password)
    {
        if (data.Length < 32)
            throw new InvalidDataException("The file is too short to be a JKS key store.");
        var reader = new Reader(data.AsMemory(0, data.Length - 20));
        if (reader.UInt32() != Magic)
            throw new InvalidDataException("Not a JKS key store (JCEKS and PKCS#12 are not supported).");

        byte[] pw = PasswordBytes(password);
        try
        {
            byte[] expected = SHA1.HashData([.. pw, .. IntegritySalt, .. data.AsSpan(0, data.Length - 20)]);
            if (!CryptographicOperations.FixedTimeEquals(expected, data.AsSpan(data.Length - 20)))
                throw new CryptographicException("JKS integrity check failed: wrong password or a damaged file.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(pw);
        }

        int version = (int)reader.UInt32();
        if (version is not (1 or 2))
            throw new InvalidDataException($"Unsupported JKS version {version}.");
        var store = new JksKeyStore();
        uint count = reader.UInt32();
        for (uint n = 0; n < count; n++)
        {
            int tag = (int)reader.UInt32();
            string alias = reader.JavaUtf();
            DateTimeOffset created = DateTimeOffset.FromUnixTimeMilliseconds((long)reader.UInt64());
            if (tag == PrivateKeyTag)
            {
                byte[] protectedKey = reader.Bytes((int)reader.UInt32());
                int chainLength = (int)reader.UInt32();
                var chain = new List<Certificate>(chainLength);
                for (int i = 0; i < chainLength; i++)
                    chain.Add(ReadCertificate(reader, version));
                store._entries.Add(new JksPrivateKeyEntry(alias, created, protectedKey, chain));
            }
            else if (tag == TrustedCertificateTag)
            {
                store._entries.Add(new JksTrustedCertificateEntry(alias, created, ReadCertificate(reader, version)));
            }
            else
            {
                throw new InvalidDataException($"Unknown JKS entry type {tag}.");
            }
        }
        if (!reader.AtEnd)
            throw new InvalidDataException("Unexpected data after the last JKS entry.");
        return store;
    }

    private static Certificate ReadCertificate(Reader reader, int version)
    {
        if (version == 2)
        {
            string type = reader.JavaUtf();
            if (type != "X.509")
                throw new NotSupportedException($"Certificate type {type} is not supported.");
        }
        return Certificate.Load(reader.Bytes((int)reader.UInt32()));
    }

    // ---- Writing -----------------------------------------------------------------------------------------------

    public byte[] Save(string password)
    {
        using var body = new MemoryStream();
        WriteUInt32(body, Magic);
        WriteUInt32(body, 2);
        WriteUInt32(body, (uint)_entries.Count);
        foreach (JksEntry entry in _entries)
        {
            WriteUInt32(body, entry is JksPrivateKeyEntry ? PrivateKeyTag : (uint)TrustedCertificateTag);
            WriteJavaUtf(body, entry.Alias);
            long millis = entry.Created.ToUnixTimeMilliseconds();
            WriteUInt32(body, (uint)(millis >> 32));
            WriteUInt32(body, (uint)millis);
            switch (entry)
            {
                case JksPrivateKeyEntry key:
                    WriteUInt32(body, (uint)key.ProtectedKey.Length);
                    body.Write(key.ProtectedKey);
                    WriteUInt32(body, (uint)key.Chain.Count);
                    foreach (Certificate certificate in key.Chain)
                        WriteCertificate(body, certificate);
                    break;
                case JksTrustedCertificateEntry trusted:
                    WriteCertificate(body, trusted.Certificate);
                    break;
            }
        }

        byte[] content = body.ToArray();
        byte[] pw = PasswordBytes(password);
        try
        {
            return [.. content, .. SHA1.HashData([.. pw, .. IntegritySalt, .. content])];
        }
        finally
        {
            CryptographicOperations.ZeroMemory(pw);
        }
    }

    private static void WriteCertificate(Stream output, Certificate certificate)
    {
        WriteJavaUtf(output, "X.509");
        WriteUInt32(output, (uint)certificate.Encoded.Length);
        output.Write(certificate.Encoded);
    }

    // ---- The Sun key protector ---------------------------------------------------------------------------------

    internal static byte[] ProtectKey(byte[] pkcs8, string password)
    {
        byte[] pw = PasswordBytes(password);
        byte[] salt = RandomNumberGenerator.GetBytes(20);
        byte[] stream = KeyStream(pw, salt, pkcs8.Length);
        try
        {
            var encrypted = new byte[20 + pkcs8.Length + 20];
            salt.CopyTo(encrypted, 0);
            for (int i = 0; i < pkcs8.Length; i++)
                encrypted[20 + i] = (byte)(pkcs8[i] ^ stream[i]);
            SHA1.HashData([.. pw, .. pkcs8]).CopyTo(encrypted, 20 + pkcs8.Length);
            return Der.Sequence(Der.Sequence(Der.ObjectIdentifier(Oids.JksKeyProtector), Der.Null()), Der.OctetString(encrypted));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(pw);
            CryptographicOperations.ZeroMemory(stream);
        }
    }

    internal static byte[] UnprotectKey(byte[] encryptedPrivateKeyInfo, string password)
    {
        Asn1Node info = Asn1Node.Parse(encryptedPrivateKeyInfo).Expect(Asn1Tag.Sequence);
        string algorithm = info[0][0].GetOid();
        if (algorithm != Oids.JksKeyProtector)
            throw new NotSupportedException($"Key protection {algorithm} is not supported (only the Sun JKS key protector).");
        byte[] encrypted = info[1].GetOctetString();
        if (encrypted.Length < 40)
            throw new InvalidDataException("The protected key is too short.");

        byte[] pw = PasswordBytes(password);
        int length = encrypted.Length - 40;
        byte[] stream = KeyStream(pw, encrypted[..20], length);
        var key = new byte[length];
        for (int i = 0; i < length; i++)
            key[i] = (byte)(encrypted[20 + i] ^ stream[i]);
        byte[] check = SHA1.HashData([.. pw, .. key]);
        CryptographicOperations.ZeroMemory(pw);
        CryptographicOperations.ZeroMemory(stream);
        if (!CryptographicOperations.FixedTimeEquals(check, encrypted.AsSpan(encrypted.Length - 20)))
        {
            CryptographicOperations.ZeroMemory(key);
            throw new CryptographicException("The key protector check failed: wrong key password.");
        }
        return key;
    }

    private static byte[] KeyStream(byte[] pw, byte[] salt, int length)
    {
        var stream = new byte[length];
        byte[] previous = salt;
        for (int offset = 0; offset < length; offset += 20)
        {
            previous = SHA1.HashData([.. pw, .. previous]);
            previous.AsSpan(0, System.Math.Min(20, length - offset)).CopyTo(stream.AsSpan(offset));
        }
        return stream;
    }

    private static byte[] PasswordBytes(string password) => Encoding.BigEndianUnicode.GetBytes(password);

    // ---- Java DataOutput -----------------------------------------------------------------------------------------

    private static void WriteUInt32(Stream output, uint value) =>
        output.Write([(byte)(value >> 24), (byte)(value >> 16), (byte)(value >> 8), (byte)value]);

    /// <summary>Java's modified UTF-8 (DataOutput.writeUTF): U+0000 as C0 80, characters outside the BMP as two 3-byte surrogates.</summary>
    internal static void WriteJavaUtf(Stream output, string s)
    {
        var bytes = new List<byte>();
        foreach (char c in s)
        {
            if (c is >= '\u0001' and <= '\u007F')
            {
                bytes.Add((byte)c);
            }
            else if (c <= '߿')
            {
                bytes.Add((byte)(0xC0 | (c >> 6)));
                bytes.Add((byte)(0x80 | (c & 0x3F)));
            }
            else
            {
                bytes.Add((byte)(0xE0 | (c >> 12)));
                bytes.Add((byte)(0x80 | ((c >> 6) & 0x3F)));
                bytes.Add((byte)(0x80 | (c & 0x3F)));
            }
        }
        if (bytes.Count > 0xFFFF)
            throw new ArgumentException("The string is too long for a JKS entry.", nameof(s));
        output.Write([(byte)(bytes.Count >> 8), (byte)bytes.Count]);
        output.Write(bytes.ToArray());
    }

    private sealed class Reader(ReadOnlyMemory<byte> data)
    {
        private int _offset;

        public bool AtEnd => _offset == data.Length;

        public byte[] Bytes(int count)
        {
            if (count < 0 || count > data.Length - _offset)
                throw new InvalidDataException("Truncated JKS key store.");
            byte[] result = data.Slice(_offset, count).ToArray();
            _offset += count;
            return result;
        }

        public uint UInt32()
        {
            byte[] b = Bytes(4);
            return (uint)((b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]);
        }

        public ulong UInt64() => ((ulong)UInt32() << 32) | UInt32();

        public string JavaUtf()
        {
            byte[] lengthBytes = Bytes(2);
            byte[] b = Bytes((lengthBytes[0] << 8) | lengthBytes[1]);
            var s = new StringBuilder();
            for (int i = 0; i < b.Length;)
            {
                int x = b[i];
                if (x < 0x80)
                {
                    s.Append((char)x);
                    i += 1;
                }
                else if ((x & 0xE0) == 0xC0 && i + 1 < b.Length)
                {
                    s.Append((char)(((x & 0x1F) << 6) | (b[i + 1] & 0x3F)));
                    i += 2;
                }
                else if ((x & 0xF0) == 0xE0 && i + 2 < b.Length)
                {
                    s.Append((char)(((x & 0x0F) << 12) | ((b[i + 1] & 0x3F) << 6) | (b[i + 2] & 0x3F)));
                    i += 3;
                }
                else
                {
                    throw new InvalidDataException("Invalid modified UTF-8 in a JKS alias.");
                }
            }
            return s.ToString();
        }
    }
}
