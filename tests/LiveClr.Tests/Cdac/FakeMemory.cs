namespace LiveClr.Tests.Cdac;

using LiveClr.Memory;

/// <summary>
/// An <see cref="IMemoryReader"/> over explicitly mapped regions.
/// </summary>
/// <remarks>
/// Unmapped ranges fail, and — this is the point — a read that <em>straddles</em> the end
/// of a region fails too, exactly as <c>ReadProcessMemory</c> does at a page boundary.
/// A fake that quietly zero-fills would hide the bulk-read failure modes the real
/// parsers must survive.
/// </remarks>
internal sealed class FakeMemory : IMemoryReader
{
    private readonly List<(ulong Start, byte[] Data)> _regions = [];

    public FakeMemory(bool is64Bit = true) => Is64Bit = is64Bit;

    public bool Is64Bit { get; }

    /// <summary>Number of reads that failed. Lets a test assert a probe stayed cheap.</summary>
    public int FailedReads { get; private set; }

    public FakeMemory Map(ulong address, byte[] data)
    {
        _regions.Add((address, data));
        return this;
    }

    public bool TryRead(ulong address, Span<byte> buffer)
    {
        foreach ((ulong start, byte[] data) in _regions)
        {
            if (address < start) continue;

            ulong offset = address - start;
            if (offset >= (ulong)data.Length) continue;
            if ((ulong)buffer.Length > (ulong)data.Length - offset) continue;

            data.AsSpan((int)offset, buffer.Length).CopyTo(buffer);
            return true;
        }

        FailedReads++;
        return false;
    }

    public void Dispose()
    {
        // Nothing owned.
    }
}
