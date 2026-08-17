namespace LiveClr.Tests.Memory;

using LiveClr.Memory;

/// <summary>
/// An in-memory <see cref="IMemoryReader"/> standing in for a live process.
/// Lets the page cache be tested for the property that actually matters — that
/// it serves one frozen image — by letting the "process" mutate underneath it
/// on demand, which is exactly what §12.4e observed and what no live test can
/// reproduce deterministically.
/// </summary>
internal sealed class FakeMemoryReader : IMemoryReader, IMemoryReadDiagnostics
{
    private readonly Dictionary<ulong, byte[]> _regions = [];

    public FakeMemoryReader(bool is64Bit = true) => Is64Bit = is64Bit;

    public bool Is64Bit { get; }

    /// <summary>Win32 error this reader reports for a failed read. 998 = ERROR_NOACCESS.</summary>
    public int FailureErrorCode { get; set; } = 998;

    /// <inheritdoc/>
    public int LastNativeErrorCode { get; private set; }

    /// <summary>Every <see cref="TryRead"/> call reaching this reader, including failed ones.</summary>
    public int ReadCalls { get; private set; }

    /// <summary>Byte offsets whose reads should fail, simulating an unmapped page.</summary>
    public HashSet<ulong> UnreadableAddresses { get; } = [];

    public bool IsDisposed { get; private set; }

    /// <summary>Maps <paramref name="data"/> at <paramref name="address"/>.</summary>
    public FakeMemoryReader Map(ulong address, params byte[] data)
    {
        _regions[address] = data;
        return this;
    }

    /// <summary>Overwrites already-mapped bytes, simulating the target mutating mid-traversal.</summary>
    public void Poke(ulong address, params byte[] data)
    {
        foreach (var (start, region) in _regions)
        {
            if (address >= start && address + (ulong)data.Length <= start + (ulong)region.Length)
            {
                data.CopyTo(region.AsSpan((int)(address - start)));
                return;
            }
        }
        throw new InvalidOperationException($"No mapped region covers {address:X}.");
    }

    public bool TryRead(ulong address, Span<byte> buffer)
    {
        ReadCalls++;
        if (buffer.Length == 0) return Succeed();
        if (address == 0) return Fail();

        foreach (var (start, region) in _regions)
        {
            if (address < start || address + (ulong)buffer.Length > start + (ulong)region.Length) continue;

            // Whole-buffer or nothing: mirrors the fail-closed contract of the
            // real reader, so a partly-unreadable range fails rather than
            // returning a partly-filled buffer.
            for (ulong a = address; a < address + (ulong)buffer.Length; a++)
            {
                if (UnreadableAddresses.Contains(a)) return Fail();
            }

            region.AsSpan((int)(address - start), buffer.Length).CopyTo(buffer);
            return Succeed();
        }

        return Fail();

        bool Succeed()
        {
            LastNativeErrorCode = 0;
            return true;
        }

        bool Fail()
        {
            LastNativeErrorCode = FailureErrorCode;
            return false;
        }
    }

    public void Dispose() => IsDisposed = true;
}
