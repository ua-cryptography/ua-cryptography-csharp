using System.IO.Compression;
using System.Text;

namespace UA.Cryptography.Tests.Support;

/// <summary>ZIP helpers for ASiC containers (ETSI EN 319 162).</summary>
internal static class Zip
{
    /// <summary>The mimetype entry: first in the archive and stored uncompressed.</summary>
    public static void WriteMimeType(ZipArchive zip, string mimeType)
    {
        ZipArchiveEntry entry = zip.CreateEntry("mimetype", CompressionLevel.NoCompression);
        using Stream s = entry.Open();
        s.Write(Encoding.ASCII.GetBytes(mimeType));
    }

    public static void Write(ZipArchive zip, string name, byte[] content)
    {
        ZipArchiveEntry entry = zip.CreateEntry(name, CompressionLevel.Optimal);
        using Stream s = entry.Open();
        s.Write(content);
    }

    public static byte[] Read(ZipArchiveEntry entry)
    {
        using Stream s = entry.Open();
        using var buffer = new MemoryStream();
        s.CopyTo(buffer);
        return buffer.ToArray();
    }

    /// <summary>Every entry of a container, after checking that it starts with the expected mimetype entry.</summary>
    public static Dictionary<string, byte[]> ReadContainer(byte[] container, string expectedMimeType)
    {
        using var zip = new ZipArchive(new MemoryStream(container), ZipArchiveMode.Read);
        Assert.Equal("mimetype", zip.Entries[0].FullName); // must come first
        Assert.Equal(zip.Entries[0].Length, zip.Entries[0].CompressedLength); // stored, not deflated
        var entries = zip.Entries.ToDictionary(e => e.FullName, Read);
        Assert.Equal(expectedMimeType, Encoding.ASCII.GetString(entries["mimetype"]));
        return entries;
    }
}
