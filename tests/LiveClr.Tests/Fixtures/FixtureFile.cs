namespace LiveClr.Tests.Fixtures;

using System.Text;

/// <summary>
/// Hand-writes fixture container bytes, including deliberately malformed ones. The production
/// writer can only emit canonical files, so the loader's validation is otherwise untested —
/// and validation nobody tests is validation that quietly stops working.
/// </summary>
internal static class FixtureFile
{
    private static ReadOnlySpan<byte> Magic =>
        new byte[] { (byte)'L', (byte)'C', (byte)'L', (byte)'R', (byte)'F', (byte)'I', (byte)'X', 0x1A };

    public static byte[] Build(
        IReadOnlyList<(ulong Address, byte[] Bytes)> regions,
        bool is64Bit = true,
        string description = "hand-written",
        uint version = 1,
        uint flags = 0xffff_ffff,
        int? regionCountOverride = null,
        long? totalBytesOverride = null)
    {
        using var ms = new MemoryStream();
        using (var w = new BinaryWriter(ms, Encoding.UTF8, leaveOpen: true))
        {
            w.Write(Magic);
            w.Write(version);
            w.Write(flags == 0xffff_ffff ? (is64Bit ? 1u : 0u) : flags);
            w.Write(description);
            w.Write(regionCountOverride ?? regions.Count);
            w.Write(totalBytesOverride ?? regions.Sum(r => (long)r.Bytes.Length));

            foreach (var (address, bytes) in regions)
            {
                w.Write(address);
                w.Write(bytes.Length);
                w.Write(bytes);
            }
        }

        return ms.ToArray();
    }
}
