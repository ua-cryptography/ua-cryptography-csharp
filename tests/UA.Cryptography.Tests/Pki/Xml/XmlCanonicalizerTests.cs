using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;
using UA.Cryptography.Pki.Xml;

namespace UA.Cryptography.Tests.Pki.Xml;

/// <summary>
/// The package's canonicalization against Microsoft's (System.Security.Cryptography.Xml, used only here as an oracle):
/// inclusive and exclusive C14N, with and without comments, of whole documents, of element subtrees as same-document
/// references see them, with an InclusiveNamespaces prefix list and with the enveloped-signature transform.
/// </summary>
public class XmlCanonicalizerTests
{
    public static TheoryData<string> Documents => new()
    {
        """<a xmlns="urn:a" xmlns:b="urn:b" z="1" b:y="2" a="3"><b:c/><d xmlns=""/><e xmlns:b="urn:b">text &amp; &lt; &gt; "q" 'a'</e></a>""",
        "<?pi data?>\n<!-- before -->\n<root><!-- inner --><?p?><x>1</x></root>\n<!-- after -->\n<?last?>",
        """<r a="x&#9;y&#10;z&#13;w" b='"quoted"' c="&lt;&amp;&gt;"/>""",
        "<r>  <![CDATA[ <x> & ]]>  \n\t<s>\r\n</s> </r>",
        """<r xml:lang="uk" xmlns:p="urn:p"><s xml:space="preserve" p:a="1"><t Id="target"><u/></t></s></r>""",
        """<r xmlns:unused="urn:u" xmlns:p="urn:p"><p:x p:attr="1" Id="target"><y/></p:x></r>""",
        """<r xmlns="urn:r"><s xmlns="" Id="target"><t xmlns="urn:r"/><v/></s></r>""",
        """<p:r xmlns:p="urn:1"><p:s xmlns:p="urn:2" Id="target"><p:t xmlns:p="urn:2"/></p:s></p:r>""",
        """<doc xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:x="urn:x"><ds:Signature Id="target"><ds:SignedInfo x:a="b">Ж ї є ґ</ds:SignedInfo></ds:Signature></doc>""",
    };

    private static XmlDocument Load(string xml) => XmlSafe.Load(Encoding.UTF8.GetBytes(xml));

    private static byte[] Microsoft(Transform transform, XmlDocument document)
    {
        transform.LoadInput(document);
        using var output = (Stream)transform.GetOutput(typeof(Stream));
        using var buffer = new MemoryStream();
        output.CopyTo(buffer);
        return buffer.ToArray();
    }

    [Theory]
    [MemberData(nameof(Documents))]
    public void WholeDocumentMatchesMicrosoft(string xml)
    {
        Assert.Equal(Microsoft(new XmlDsigC14NTransform(false), Load(xml)), XmlCanonicalizer.Canonicalize(Load(xml), XmlCanonicalizer.InclusiveC14N));
        Assert.Equal(Microsoft(new XmlDsigC14NTransform(true), Load(xml)), XmlCanonicalizer.Canonicalize(Load(xml), XmlCanonicalizer.InclusiveC14NWithComments));
        Assert.Equal(Microsoft(new XmlDsigExcC14NTransform(false), Load(xml)), XmlCanonicalizer.Canonicalize(Load(xml), XmlCanonicalizer.ExclusiveC14N));
        Assert.Equal(Microsoft(new XmlDsigExcC14NTransform(true), Load(xml)), XmlCanonicalizer.Canonicalize(Load(xml), XmlCanonicalizer.ExclusiveC14NWithComments));
    }

    /// <summary>
    /// Exclusive C14N of a subtree does not depend on the ancestors, so Microsoft's transform of the element re-parsed
    /// from its OuterXml (which declares the namespaces it uses) is the oracle. ImportNode is not: it drops inherited
    /// declarations. OuterXml writes tabs and line ends in attribute values literally, and parsing turns them into spaces,
    /// so such elements are covered by <see cref="WholeDocumentMatchesMicrosoft"/> only.
    /// </summary>
    [Theory]
    [MemberData(nameof(Documents))]
    public void ExclusiveSubtreeMatchesMicrosoft(string xml)
    {
        XmlDocument document = Load(xml);
        foreach (XmlElement element in document.GetElementsByTagName("*").Cast<XmlElement>())
        {
            if (element.SelectNodes("descendant-or-self::*/@*")!.Cast<XmlAttribute>().Any(a => a.Value.IndexOfAny(['\t', '\n', '\r']) >= 0))
                continue;
            Assert.Equal(Microsoft(new XmlDsigExcC14NTransform(false), Load(element.OuterXml)), XmlCanonicalizer.Canonicalize(element, XmlCanonicalizer.ExclusiveC14N));
        }
    }

    /// <summary>
    /// Inclusive C14N of a "#id" subtree inherits the ancestors' namespaces and xml:* attributes: the digest Microsoft's
    /// SignedXml computes for such a reference (no transforms, i.e. inclusive C14N) is the oracle.
    /// </summary>
    [Theory]
    [MemberData(nameof(Documents))]
    public void InclusiveSubtreeMatchesSignedXmlReferenceDigest(string xml)
    {
        XmlDocument document = Load(xml);
        if (document.SelectSingleNode("//*[@Id='target']") is not XmlElement target)
            return;

        var signed = new SignedXml(document) { SigningKey = RSA.Create(2048) };
        var reference = new Reference("#target") { DigestMethod = SignedXml.XmlDsigSHA256Url };
        signed.AddReference(reference);
        signed.ComputeSignature();
        byte[] expected = reference.DigestValue!;

        Assert.Equal(expected, SHA256.HashData(XmlCanonicalizer.Canonicalize(target, XmlCanonicalizer.InclusiveC14N)));
    }

    [Fact]
    public void InclusiveNamespacesPrefixListMatchesMicrosoft()
    {
        const string xml = """<r xmlns:a="urn:a" xmlns:b="urn:b" xmlns="urn:d"><x><y a:z="1"/></x></r>""";
        foreach (string list in new[] { "b", "#default", "b #default", "a b" })
        {
            XmlDocument document = Load(xml);
            byte[] expected = Microsoft(new XmlDsigExcC14NTransform(false, list), document);
            Assert.Equal(expected, XmlCanonicalizer.Canonicalize(Load(xml), XmlCanonicalizer.ExclusiveC14N, list.Split(' ')));
        }
    }

    [Fact]
    public void EnvelopedSignatureTransformLeavesTheSignatureOut()
    {
        const string xml = """<doc a="1"><data>value</data><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo/></ds:Signature><tail/></doc>""";
        XmlDocument document = Load(xml);
        XmlNode signature = document.GetElementsByTagName("Signature", "http://www.w3.org/2000/09/xmldsig#")[0]!;

        XmlDocument without = Load(xml);
        XmlNode removed = without.GetElementsByTagName("Signature", "http://www.w3.org/2000/09/xmldsig#")[0]!;
        removed.ParentNode!.RemoveChild(removed);

        Assert.Equal(Microsoft(new XmlDsigC14NTransform(false), without),
            XmlCanonicalizer.Canonicalize(document, XmlCanonicalizer.InclusiveC14N, excluded: signature));
    }

    [Fact]
    public void XadesBuilderDocumentMatchesMicrosoft()
    {
        string xml = XadesBuilder.Build("test"u8.ToArray(), "data.txt", Hierarchy.Shared, Oids.Dstu7564_256).OuterXml;
        XmlDocument document = Load(xml);
        foreach (XmlElement element in document.GetElementsByTagName("*").Cast<XmlElement>())
            Assert.Equal(XadesBuilder.Canonicalize(element), XmlCanonicalizer.Canonicalize(element, XmlCanonicalizer.ExclusiveC14N));
        Assert.Equal(Microsoft(new XmlDsigC14NTransform(false), Load(xml)), XmlCanonicalizer.Canonicalize(Load(xml), XmlCanonicalizer.InclusiveC14N));
    }

    [Fact]
    public void DocumentTypeDefinitionsAreRefused()
    {
        const string xxe = """<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>""";
        Assert.Throws<XmlException>(() => XmlSafe.Load(Encoding.UTF8.GetBytes(xxe)));
    }
}
