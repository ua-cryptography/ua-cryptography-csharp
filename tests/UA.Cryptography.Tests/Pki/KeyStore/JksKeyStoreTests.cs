using System.Security.Cryptography;
using UA.Cryptography.Dstu4145;
using UA.Cryptography.Pki;
using UA.Cryptography.Pki.KeyStore;
using UA.Cryptography.Pki.X509;

namespace UA.Cryptography.Tests.Pki.KeyStore;

/// <summary>
/// The package's JKS reader and writer against the independent test implementation (<see cref="Jks"/>, BouncyCastle
/// ASN.1) in both directions, plus several entries, Java's modified UTF-8 and every way a password can be wrong.
/// </summary>
public class JksKeyStoreTests
{
    private const string Password = "correct horse battery staple";

    [Fact]
    public void StoreWrittenByThePackageIsReadByTheTestImplementation()
    {
        Hierarchy pki = Hierarchy.Shared;
        var store = new JksKeyStore();
        store.AddPrivateKey("signer", pki.Signer.Key.ToPki(), pki.SignerChain.Select(c => c.ToPki()).ToList(), Password);

        Jks.Entry entry = Jks.Read(store.Save(Password), Password);
        Assert.Equal("signer", entry.Alias);
        Assert.Equal(pki.Signer.Key.PrivateKey, entry.Key.PrivateKey);
        Assert.Equal(pki.SignerChain.Select(c => c.GetEncoded()), entry.Chain.Select(c => c.GetEncoded()));
    }

    [Fact]
    public void StoreWrittenByTheTestImplementationIsReadByThePackage()
    {
        Hierarchy pki = Hierarchy.Shared;
        byte[] data = Jks.Write("signer", pki.Signer.Key, pki.SignerChain, Password);

        JksKeyStore store = JksKeyStore.Load(data, Password);
        JksPrivateKeyEntry entry = Assert.IsType<JksPrivateKeyEntry>(Assert.Single(store.Entries));
        Dstu4145PrivateKey key = entry.GetPrivateKey(Password);
        Assert.Equal(pki.Signer.Key.PrivateKey, key.D);
        Assert.Equal(pki.Signer.Key.PublicKey, key.PublicKey.Q);
        Assert.Equal(pki.Signer.Key.Dke, key.Dke);
        Assert.Equal(3, entry.Chain.Count);

        SigningKey signer = SigningKey.FromJks(store, Password);
        Assert.Equal(pki.Signer.Certificate.GetEncoded(), signer.Certificate.Encoded);
    }

    [Fact]
    public void ChainStoredRootFirstWithAKeyAgreementCertificateIsReordered()
    {
        // As PrivatBank issues keys: root, CA, the signing certificate, then the certificate of the key-agreement key.
        Hierarchy pki = Hierarchy.Shared;
        Certificate signer = pki.Signer.Certificate.ToPki();
        Certificate ca = pki.IssuingCa.Certificate.ToPki();
        Certificate root = PkiLayer.Root(pki);
        var agreementKey = Dstu4145PrivateKey.Generate(Dstu4145NamedCurves.Polynomial(431));
        Certificate agreement = new CertificateBuilder(signer.Subject, agreementKey.PublicKey)
            .AddKeyUsage(KeyUsageFlags.KeyAgreement).Issue(ca, pki.IssuingCa.Key.ToPki());
        var store = new JksKeyStore();
        store.AddPrivateKey("pb_sign", pki.Signer.Key.ToPki(), [root, ca, signer, agreement], Password);
        JksKeyStore read = JksKeyStore.Load(store.Save(Password), Password);

        JksPrivateKeyEntry entry = read.PrivateKeys.Single();
        Assert.Equal(signer, entry.FindCertificate(entry.GetPrivateKey(Password).PublicKey));
        SigningKey key = SigningKey.FromJks(read, Password);
        Assert.Equal(signer, key.Certificate);
        Assert.Equal([signer, ca, root], key.Chain);

        // A key that matches none of the certificates is still refused.
        var other = new JksKeyStore();
        other.AddPrivateKey("other", agreementKey, [root, ca, signer], Password);
        Assert.Throws<InvalidDataException>(() => SigningKey.FromJks(JksKeyStore.Load(other.Save(Password), Password), Password));
    }

    [Fact]
    public void SeveralEntriesAndUnusualAliasesRoundTrip()
    {
        Hierarchy pki = Hierarchy.Shared;
        string[] aliases = ["підпис", "nul\u0000char", "emoji \U0001F511"];
        var store = new JksKeyStore();
        foreach (string alias in aliases)
        {
            Dstu4145PrivateKey key = Dstu4145PrivateKey.Generate(Dstu4145NamedCurves.Polynomial(257));
            Certificate certificate = new CertificateBuilder(DistinguishedName.Parse($"CN=Key {alias.Length}"), key.PublicKey).SelfSign(key);
            store.AddPrivateKey(alias, key, [certificate], Password);
        }
        store.AddTrustedCertificate("root", pki.Root.Certificate.ToPki());

        JksKeyStore read = JksKeyStore.Load(store.Save(Password), Password);
        Assert.Equal([.. aliases, "root"], read.Entries.Select(e => e.Alias));
        Assert.Equal(pki.Root.Certificate.GetEncoded(), Assert.IsType<JksTrustedCertificateEntry>(read.Find("root")).Certificate.Encoded);
        foreach (JksPrivateKeyEntry entry in read.PrivateKeys)
            Assert.True(entry.Chain[0].PublicKey.Q.Equals(entry.GetPrivateKey(Password).PublicKey.Q));

        // Java writes U+0000 as C0 80 (modified UTF-8), never as a zero byte.
        byte[] saved = store.Save(Password);
        Assert.True(saved.AsSpan().IndexOf("nulÀ"u8) < 0);
        Assert.True(saved.AsSpan().IndexOf((ReadOnlySpan<byte>)[(byte)'n', (byte)'u', (byte)'l', 0xC0, 0x80]) > 0);

        // Several keys: the alias decides.
        Assert.Throws<ArgumentException>(() => SigningKey.FromJks(read, Password));
        Assert.Equal(read.PrivateKeys.First().Chain[0], SigningKey.FromJks(read, Password, "ПІДПИС").Certificate);
    }

    [Fact]
    public void WrongPasswordsAndDamageAreDetected()
    {
        Hierarchy pki = Hierarchy.Shared;
        var store = new JksKeyStore();
        store.AddPrivateKey("signer", pki.Signer.Key.ToPki(), [pki.Signer.Certificate.ToPki()], "key password");
        byte[] data = store.Save(Password);

        Assert.Throws<CryptographicException>(() => JksKeyStore.Load(data, "wrong"));
        JksPrivateKeyEntry entry = JksKeyStore.Load(data, Password).PrivateKeys.Single();
        Assert.Throws<CryptographicException>(() => entry.GetPrivateKey(Password));
        Assert.Equal(pki.Signer.Key.PrivateKey, entry.GetPrivateKey("key password").D);

        for (int offset = 0; offset < data.Length; offset += 97)
        {
            byte[] damaged = data.ToArray();
            damaged[offset] ^= 0x40;
            Assert.ThrowsAny<Exception>(() => JksKeyStore.Load(damaged, Password));
        }
        Assert.Throws<InvalidDataException>(() => JksKeyStore.Load(new byte[10], Password));
    }

    [Fact]
    public void KeyThatDoesNotMatchItsCertificateIsRejected()
    {
        Hierarchy pki = Hierarchy.Shared;
        var store = new JksKeyStore();
        store.AddPrivateKey("mismatch", pki.Signer.Key.ToPki(), [pki.IssuingCa.Certificate.ToPki()], Password);
        JksPrivateKeyEntry entry = JksKeyStore.Load(store.Save(Password), Password).PrivateKeys.Single();
        Assert.Throws<InvalidDataException>(() => entry.GetPrivateKey(Password));
    }

    [Fact]
    public void Pkcs8AcceptsTheBouncyCastleIntegerForm()
    {
        Dstu4145PrivateKey key = Dstu4145PrivateKey.Generate(Dstu4145NamedCurves.Polynomial(257));
        Org.BouncyCastle.Asn1.Asn1Sequence pkcs8 = Org.BouncyCastle.Asn1.Asn1Sequence.GetInstance(key.ToPkcs8());
        byte[] bcForm = new Org.BouncyCastle.Asn1.DerSequence(pkcs8[0], pkcs8[1],
            new Org.BouncyCastle.Asn1.DerOctetString(new Org.BouncyCastle.Asn1.DerInteger(new Org.BouncyCastle.Math.BigInteger(1, key.D.ToByteArray(true, true))))).GetDerEncoded();
        Assert.Equal(key.D, Dstu4145PrivateKey.FromPkcs8(bcForm).D);
    }
}
