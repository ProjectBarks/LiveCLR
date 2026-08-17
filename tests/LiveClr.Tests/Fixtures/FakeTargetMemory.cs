namespace LiveClr.Tests.Fixtures;

using LiveClr.Memory;

/// <summary>
/// Stands in for a live process in the recorder tests: one mapped range, everything else
/// unreadable. Mutable, so a test can prove last-write-wins on a re-read.
/// </summary>
internal sealed class FakeTargetMemory : IMemoryReader
{
    private readonly ulong _base;
    private readonly byte[] _bytes;

    public FakeTargetMemory(ulong baseAddress, byte[] bytes, bool is64Bit = true)
    {
        _base = baseAddress;
        _bytes = bytes;
        Is64Bit = is64Bit;
    }

    public bool Is64Bit { get; }

    public int SuccessfulReads { get; private set; }
    public int RejectedReads { get; private set; }
    public bool Disposed { get; private set; }

    /// <summary>Overwrite backing bytes, simulating the target mutating between reads.</summary>
    public void Poke(ulong address, ReadOnlySpan<byte> data) => data.CopyTo(_bytes.AsSpan((int)(address - _base)));

    public bool TryRead(ulong address, Span<byte> buffer)
    {
        if (address < _base || (ulong)buffer.Length > ulong.MaxValue - address ||
            address + (ulong)buffer.Length > _base + (ulong)_bytes.Length)
        {
            RejectedReads++;
            return false;
        }

        _bytes.AsSpan((int)(address - _base), buffer.Length).CopyTo(buffer);
        SuccessfulReads++;
        return true;
    }

    public void Dispose() => Disposed = true;

    /// <summary>Deterministic junk so no test depends on a lucky zero page.</summary>
    public static byte[] Junk(int length, int seed)
    {
        var bytes = new byte[length];
        uint state = (uint)seed | 1u;
        for (int i = 0; i < length; i++)
        {
            state = state * 1664525u + 1013904223u;
            bytes[i] = (byte)(state >> 16);
        }
        return bytes;
    }
}
