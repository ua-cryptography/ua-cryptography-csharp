using Org.BouncyCastle.Asn1.X509;
using X509Certificate = Org.BouncyCastle.X509.X509Certificate;

namespace UA.Cryptography.Tests.Support;

/// <summary>
/// A synthetic PKI shaped like the national one (docs/signature-formats.md, "Chain of trust"), so that every
/// signature level can be built and checked without real documents:
/// <code>
/// Test Root CA            self-signed, m = 431, DSTU 7564            (like the Central Certification Authority)
/// ├── Test Issuing CA     m = 257                                    (like a qualified trust service provider)
/// │   ├── Test Signer     m = 257, the key that signs documents
/// │   └── Test OCSP       answers for the Issuing CA's certificates
/// ├── Test TSP Server     m = 257, time-stamps
/// └── Test Root OCSP      answers for the root's certificates
/// </code>
/// Generating it takes a few milliseconds; <see cref="Shared"/> is one immutable instance for the whole test run.
/// </summary>
internal sealed class Hierarchy
{
    private static readonly Lazy<Hierarchy> SharedInstance = new(Create);

    private Hierarchy(TestPki.TestIdentity root, TestPki.TestIdentity issuingCa, TestPki.TestIdentity signer,
        TimeStampAuthority tsa, OcspResponder issuingCaOcsp, OcspResponder rootOcsp)
    {
        Root = root;
        IssuingCa = issuingCa;
        Signer = signer;
        Tsa = tsa;
        IssuingCaOcsp = issuingCaOcsp;
        RootOcsp = rootOcsp;
    }

    public static Hierarchy Shared => SharedInstance.Value;

    public TestPki.TestIdentity Root { get; }

    public TestPki.TestIdentity IssuingCa { get; }

    public TestPki.TestIdentity Signer { get; }

    public TimeStampAuthority Tsa { get; }

    public OcspResponder IssuingCaOcsp { get; }

    public OcspResponder RootOcsp { get; }

    /// <summary>Signer, issuing CA, root.</summary>
    public IReadOnlyList<X509Certificate> SignerChain => [Signer.Certificate, IssuingCa.Certificate, Root.Certificate];

    /// <summary>Every certificate except the signer's: what a validator needs besides the signature itself.</summary>
    public IReadOnlyList<X509Certificate> ValidationCertificates =>
        [IssuingCa.Certificate, Root.Certificate, Tsa.Identity.Certificate, IssuingCaOcsp.Identity.Certificate, RootOcsp.Identity.Certificate];

    /// <summary>"good" OCSP responses for the signer and its CA, from their issuers' responders.</summary>
    public IReadOnlyList<Org.BouncyCastle.Asn1.Ocsp.BasicOcspResponse> SignerRevocationData =>
    [
        IssuingCaOcsp.Respond(Signer.Certificate, IssuingCa.Certificate),
        RootOcsp.Respond(IssuingCa.Certificate, Root.Certificate),
    ];

    public static Hierarchy Create()
    {
        TestPki.TestIdentity root = TestPki.CreateSelfSigned("CN=Test Root CA,O=UA Cryptography Tests,C=UA",
            TestPki.GenerateKey(431), signatureAlgorithm: Oids.Dstu4145WithDstu7564);
        TestPki.TestIdentity issuingCa = TestPki.Issue("CN=Test Issuing CA,O=UA Cryptography Tests,C=UA", TestPki.GenerateKey(), root,
            isCa: true, signatureAlgorithm: Oids.Dstu4145WithDstu7564);
        TestPki.TestIdentity signer = TestPki.Issue("CN=Test Signer,O=UA Cryptography Tests,C=UA", TestPki.GenerateKey(), issuingCa,
            signatureAlgorithm: Oids.Dstu4145WithDstu7564);
        TestPki.TestIdentity tsa = TestPki.Issue("CN=Test TSP Server,O=UA Cryptography Tests,C=UA", TestPki.GenerateKey(), root,
            extendedKeyUsage: KeyPurposeID.id_kp_timeStamping, signatureAlgorithm: Oids.Dstu4145WithDstu7564);
        TestPki.TestIdentity issuingCaOcsp = TestPki.Issue("CN=Test OCSP,O=UA Cryptography Tests,C=UA", TestPki.GenerateKey(), issuingCa,
            extendedKeyUsage: KeyPurposeID.id_kp_OCSPSigning, signatureAlgorithm: Oids.Dstu4145WithDstu7564);
        TestPki.TestIdentity rootOcsp = TestPki.Issue("CN=Test Root OCSP,O=UA Cryptography Tests,C=UA", TestPki.GenerateKey(), root,
            extendedKeyUsage: KeyPurposeID.id_kp_OCSPSigning, signatureAlgorithm: Oids.Dstu4145WithDstu7564);
        return new Hierarchy(root, issuingCa, signer, new TimeStampAuthority(tsa), new OcspResponder(issuingCaOcsp), new OcspResponder(rootOcsp));
    }
}
