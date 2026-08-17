namespace LiveClr.Fixtures;

/// <summary>
/// Builds a <see cref="RecordedMemory"/> from bytes you supply directly, without a live process.
/// </summary>
/// <remarks>
/// Two uses. First, synthetic fixtures: a test can lay out a struct with a known layout and
/// prove that, say, <see cref="Calibration.StructuralProbe"/> rediscovers the offsets — the
/// whole point of §8.8's fixture provider is that such a test needs no game running. Second,
/// hand-assembling a fixture from a capture taken by other means.
/// </remarks>
public sealed class RecordedMemoryBuilder
{
    private readonly RegionMap _map = new();

    /// <param name="is64Bit">Pointer width of the simulated target. Drives <see cref="LiveClr.Memory.IMemoryReader.Is64Bit"/>.</param>
    /// <param name="description">Provenance text stored in the fixture header.</param>
    public RecordedMemoryBuilder(bool is64Bit = true, string description = "")
    {
        Is64Bit = is64Bit;
        Description = description;
    }

    /// <summary>Pointer width of the simulated target.</summary>
    public bool Is64Bit { get; set; }

    /// <summary>Provenance text stored in the fixture header.</summary>
    public string Description { get; set; }

    /// <summary>Add a byte range. Overlapping adds are last-write-wins; adjacent ranges coalesce.</summary>
    public RecordedMemoryBuilder Add(ulong address, ReadOnlySpan<byte> data)
    {
        _map.Add(address, data);
        return this;
    }

    /// <summary>Add a single unmanaged value at <paramref name="address"/>, laid out as the target would.</summary>
    public RecordedMemoryBuilder Add<T>(ulong address, T value) where T : unmanaged
    {
        Span<byte> buf = stackalloc byte[System.Runtime.CompilerServices.Unsafe.SizeOf<T>()];
        System.Runtime.InteropServices.MemoryMarshal.Write(buf, in value);
        return Add(address, buf);
    }

    /// <summary>Materialise the fixture. The builder may be reused and extended afterwards.</summary>
    public RecordedMemory Build()
    {
        var copy = new RegionMap();
        foreach (var entry in _map.Entries)
            copy.Add(entry.Start, entry.Data.Span);
        return new RecordedMemory(copy, Is64Bit, Description);
    }
}
