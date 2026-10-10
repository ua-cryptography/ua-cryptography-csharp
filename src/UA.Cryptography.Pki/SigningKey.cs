using UA.Cryptography.Pki.KeyStore;
using UA.Cryptography.Pki.Validation;
using UA.Cryptography.Pki.X509;

namespace UA.Cryptography.Pki;

/// <summary>A private key with its certificate and the rest of the chain (end entity first): what a signer needs.</summary>
public sealed class SigningKey
{
    public SigningKey(Dstu4145PrivateKey key, IReadOnlyList<Certificate> chain)
    {
        if (chain.Count == 0)
            throw new ArgumentException("The signer's certificate is required.", nameof(chain));
        if (!chain[0].PublicKey.Q.Equals(key.PublicKey.Q))
            throw new ArgumentException("The private key does not match the certificate.", nameof(key));
        Key = key;
        Chain = chain;
    }

    public Dstu4145PrivateKey Key { get; }

    public Certificate Certificate => Chain[0];

    public IReadOnlyList<Certificate> Chain { get; }

    /// <summary>
    /// Opens a key from a JKS store. Without <paramref name="alias"/> the store must hold exactly one private key, or
    /// exactly one with an end-entity certificate that allows signing (keyUsage digitalSignature or nonRepudiation).
    /// The chain is rebuilt from the key's certificate up through its issuers, whatever order the store keeps it in;
    /// certificates off that path (such as a key-agreement certificate) are left out.
    /// </summary>
    public static SigningKey FromJks(JksKeyStore store, string password, string? alias = null, string? keyPassword = null)
    {
        JksPrivateKeyEntry entry;
        if (alias is not null)
        {
            entry = store.Find(alias) as JksPrivateKeyEntry
                ?? throw new ArgumentException($"The key store has no private key '{alias}'.", nameof(alias));
        }
        else
        {
            List<JksPrivateKeyEntry> keys = store.PrivateKeys.ToList();
            if (keys.Count > 1)
                keys = keys.Where(k => k.Chain.Any(c => !c.IsCa && (c.KeyUsage is not { } usage || (usage & 0b11) != 0))).ToList();
            entry = keys.Count switch
            {
                1 => keys[0],
                0 => throw new ArgumentException("The key store holds no signing key."),
                _ => throw new ArgumentException(
                    $"The key store holds several keys; choose one by alias: {string.Join(", ", store.PrivateKeys.Select(k => k.Alias))}."),
            };
        }
        Dstu4145PrivateKey key = entry.GetPrivateKey(keyPassword ?? password);
        IReadOnlyList<Certificate> chain = entry.FindCertificate(key.PublicKey) is { } certificate
            ? CertificatePathValidator.BuildChain(certificate, entry.Chain, [])
            : entry.Chain;
        return new SigningKey(key, chain);
    }
}
