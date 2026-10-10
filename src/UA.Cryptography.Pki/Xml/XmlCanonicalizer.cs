using System.Text;
using System.Xml;

namespace UA.Cryptography.Pki.Xml;

/// <summary>
/// Canonical XML 1.0 (W3C REC-xml-c14n-20010315) and Exclusive XML Canonicalization 1.0 (W3C REC-xml-exc-c14n-20020718)
/// over a <see cref="XmlDocument"/> loaded with <see cref="XmlSafe.Load"/>. The input node set is a whole document or one
/// element with its descendants (a same-document reference "#id"), optionally minus one subtree (the
/// enveloped-signature transform).
/// </summary>
/// <remarks>
/// Namespaces are taken from the element and attribute names (prefix and namespace URI) as well as from the xmlns
/// attributes, so a document built in memory canonicalizes the same way as after serialization and parsing.
/// </remarks>
public static class XmlCanonicalizer
{
    public const string InclusiveC14N = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
    public const string InclusiveC14NWithComments = InclusiveC14N + "#WithComments";
    public const string ExclusiveC14N = "http://www.w3.org/2001/10/xml-exc-c14n#";
    public const string ExclusiveC14NWithComments = ExclusiveC14N + "WithComments";

    private const string XmlNamespace = "http://www.w3.org/XML/1998/namespace";
    private const string XmlnsNamespace = "http://www.w3.org/2000/xmlns/";

    public static bool IsSupported(string algorithm) =>
        algorithm is InclusiveC14N or InclusiveC14NWithComments or ExclusiveC14N or ExclusiveC14NWithComments;

    /// <summary>
    /// Canonicalizes a document or an element subtree with <paramref name="algorithm"/>. For exclusive canonicalization,
    /// <paramref name="inclusivePrefixes"/> is the InclusiveNamespaces PrefixList ("#default" names the default namespace).
    /// <paramref name="excluded"/> and its descendants are left out.
    /// </summary>
    public static byte[] Canonicalize(XmlNode node, string algorithm, IReadOnlyCollection<string>? inclusivePrefixes = null, XmlNode? excluded = null)
    {
        if (!IsSupported(algorithm))
            throw new NotSupportedException($"Canonicalization {algorithm} is not supported.");
        var writer = new Writer(
            exclusive: algorithm.StartsWith(ExclusiveC14N, StringComparison.Ordinal),
            comments: algorithm.EndsWith("WithComments", StringComparison.Ordinal),
            inclusivePrefixes?.Select(p => p == "#default" ? "" : p).ToHashSet() ?? [],
            excluded);
        switch (node)
        {
            case XmlDocument document:
                writer.WriteDocument(document);
                break;
            case XmlElement element:
                writer.WriteApex(element);
                break;
            default:
                throw new ArgumentException("Only a document or an element can be canonicalized.", nameof(node));
        }
        return Encoding.UTF8.GetBytes(writer.ToString());
    }

    private sealed class Writer(bool exclusive, bool comments, HashSet<string> inclusivePrefixes, XmlNode? excluded)
    {
        private static readonly Dictionary<string, string> EmptyContext = new(StringComparer.Ordinal) { [""] = "" };
        private readonly StringBuilder _output = new();

        public override string ToString() => _output.ToString();

        public void WriteDocument(XmlDocument document)
        {
            bool afterRoot = false;
            foreach (XmlNode child in document.ChildNodes)
            {
                if (ReferenceEquals(child, excluded))
                    continue;
                switch (child)
                {
                    case XmlElement element:
                        WriteElement(element, EmptyContext, InScope(element, EmptyContext), apex: true);
                        afterRoot = true;
                        break;
                    case XmlComment when comments:
                    case XmlProcessingInstruction:
                        if (afterRoot)
                            _output.Append('\n');
                        WriteLeaf(child);
                        if (!afterRoot)
                            _output.Append('\n');
                        break;
                }
            }
        }

        /// <summary>An element and its descendants: the namespaces in scope come from the ancestors as well.</summary>
        public void WriteApex(XmlElement element)
        {
            var ancestors = new List<XmlElement>();
            for (XmlNode? n = element.ParentNode; n is XmlElement parent; n = n.ParentNode)
                ancestors.Add(parent);
            ancestors.Reverse();

            Dictionary<string, string> inherited = EmptyContext;
            foreach (XmlElement ancestor in ancestors)
                inherited = InScope(ancestor, inherited);
            WriteElement(element, EmptyContext, InScope(element, inherited), apex: true);
        }

        /// <summary>The namespaces in scope at <paramref name="element"/>: those of its parent plus its own declarations and names.</summary>
        private static Dictionary<string, string> InScope(XmlElement element, Dictionary<string, string> parent)
        {
            Dictionary<string, string>? scope = null;
            void Bind(string prefix, string uri)
            {
                if (parent.TryGetValue(prefix, out string? existing) && existing == uri && scope is null)
                    return;
                scope ??= new Dictionary<string, string>(parent, StringComparer.Ordinal);
                scope[prefix] = uri;
            }

            Bind(element.Prefix, element.NamespaceURI);
            foreach (XmlAttribute attribute in element.Attributes)
            {
                if (attribute.NamespaceURI == XmlnsNamespace)
                    Bind(attribute.Prefix == "xmlns" ? attribute.LocalName : "", attribute.Value);
                else if (attribute.Prefix.Length > 0 && attribute.Prefix != "xml")
                    Bind(attribute.Prefix, attribute.NamespaceURI);
            }
            return scope ?? parent;
        }

        private void WriteElement(XmlElement element, Dictionary<string, string> rendered, Dictionary<string, string> inScope, bool apex)
        {
            // Namespace nodes to render, sorted by prefix (the default namespace, with no prefix, first).
            var namespaces = new SortedDictionary<string, string>(StringComparer.Ordinal);
            IEnumerable<string> candidates = exclusive ? VisiblyUtilized(element).Concat(inclusivePrefixes.Where(inScope.ContainsKey)) : inScope.Keys;
            foreach (string prefix in candidates)
            {
                if (prefix == "xml" || !inScope.TryGetValue(prefix, out string? uri))
                    continue;
                string? current = rendered.TryGetValue(prefix, out string? r) ? r : null;
                bool render = prefix.Length == 0
                    ? uri != (current ?? "")              // xmlns="" only to undo a non-empty default of an output ancestor
                    : current != uri;
                if (render && !(prefix.Length > 0 && uri.Length == 0))
                    namespaces[prefix] = uri;
            }

            var attributes = new List<XmlAttribute>();
            foreach (XmlAttribute attribute in element.Attributes)
            {
                if (attribute.NamespaceURI != XmlnsNamespace)
                    attributes.Add(attribute);
            }
            if (!exclusive && apex)
                attributes.AddRange(InheritedXmlAttributes(element, attributes));
            attributes.Sort((a, b) =>
            {
                int c = string.CompareOrdinal(a.NamespaceURI, b.NamespaceURI);
                return c != 0 ? c : string.CompareOrdinal(a.LocalName, b.LocalName);
            });

            _output.Append('<').Append(element.Name);
            foreach ((string prefix, string uri) in namespaces)
            {
                _output.Append(prefix.Length == 0 ? " xmlns=\"" : $" xmlns:{prefix}=\"");
                EscapeAttribute(uri);
                _output.Append('"');
            }
            foreach (XmlAttribute attribute in attributes)
            {
                _output.Append(' ').Append(attribute.Name).Append("=\"");
                EscapeAttribute(attribute.Value);
                _output.Append('"');
            }
            _output.Append('>');

            Dictionary<string, string> childRendered = rendered;
            if (namespaces.Count > 0)
            {
                childRendered = new Dictionary<string, string>(rendered, StringComparer.Ordinal);
                foreach ((string prefix, string uri) in namespaces)
                    childRendered[prefix] = uri;
            }
            WriteChildren(element, childRendered, inScope);
            _output.Append("</").Append(element.Name).Append('>');
        }

        private void WriteChildren(XmlNode parent, Dictionary<string, string> rendered, Dictionary<string, string> inScope)
        {
            foreach (XmlNode child in parent.ChildNodes)
            {
                if (ReferenceEquals(child, excluded))
                    continue;
                switch (child)
                {
                    case XmlElement element:
                        WriteElement(element, rendered, InScope(element, inScope), apex: false);
                        break;
                    case XmlText or XmlCDataSection or XmlWhitespace or XmlSignificantWhitespace:
                        EscapeText(child.Value ?? "");
                        break;
                    case XmlEntityReference:
                        WriteChildren(child, rendered, inScope);
                        break;
                    default:
                        WriteLeaf(child);
                        break;
                }
            }
        }

        private void WriteLeaf(XmlNode node)
        {
            if (node is XmlComment comment && comments)
            {
                _output.Append("<!--").Append(comment.Value).Append("-->");
            }
            else if (node is XmlProcessingInstruction pi)
            {
                _output.Append("<?").Append(pi.Target);
                if (!string.IsNullOrEmpty(pi.Data))
                    _output.Append(' ').Append(pi.Data);
                _output.Append("?>");
            }
        }

        /// <summary>Exclusive C14N: the element's own prefix (or the default namespace) and the prefixes of its attributes.</summary>
        private static IEnumerable<string> VisiblyUtilized(XmlElement element)
        {
            yield return element.Prefix;
            foreach (XmlAttribute attribute in element.Attributes)
            {
                if (attribute.NamespaceURI != XmlnsNamespace && attribute.Prefix.Length > 0)
                    yield return attribute.Prefix;
            }
        }

        /// <summary>Canonical XML 1.0, 2.4: the xml:* attributes of the ancestors are copied to the apex unless it has its own.</summary>
        private static List<XmlAttribute> InheritedXmlAttributes(XmlElement element, List<XmlAttribute> own)
        {
            var inherited = new List<XmlAttribute>();
            for (XmlNode? n = element.ParentNode; n is XmlElement ancestor; n = n.ParentNode)
            {
                foreach (XmlAttribute attribute in ancestor.Attributes)
                {
                    if (attribute.NamespaceURI == XmlNamespace
                        && !own.Any(a => a.NamespaceURI == XmlNamespace && a.LocalName == attribute.LocalName)
                        && !inherited.Any(a => a.LocalName == attribute.LocalName))
                        inherited.Add(attribute);
                }
            }
            return inherited;
        }

        private void EscapeText(string text)
        {
            foreach (char c in text)
            {
                string? escaped = c switch
                {
                    '&' => "&amp;",
                    '<' => "&lt;",
                    '>' => "&gt;",
                    '\r' => "&#xD;",
                    _ => null,
                };
                if (escaped is null)
                    _output.Append(c);
                else
                    _output.Append(escaped);
            }
        }

        private void EscapeAttribute(string value)
        {
            foreach (char c in value)
            {
                string? escaped = c switch
                {
                    '&' => "&amp;",
                    '<' => "&lt;",
                    '"' => "&quot;",
                    '\t' => "&#x9;",
                    '\n' => "&#xA;",
                    '\r' => "&#xD;",
                    _ => null,
                };
                if (escaped is null)
                    _output.Append(c);
                else
                    _output.Append(escaped);
            }
        }
    }
}
