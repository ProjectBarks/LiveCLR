namespace LiveClr.Tests.Runtime;

using System.Buffers.Binary;
using LiveClr.Memory;

/// <summary>
/// A reader over a fixed fixture whose bytes a test can change between snapshots.
/// </summary>
/// <remarks>
/// <see cref="LiveClr.Fixtures.RecordedMemory"/> is immutable by design — a fixture must never
/// invent bytes it did not capture. But the whole point of §6.4's agree-twice guard is to catch
/// a structure that CHANGED, and a target that never changes cannot exercise it. This overlays
/// a small set of writes so a test can play the part of the running game.
/// </remarks>
internal sealed class MutableMemoryOverlay : IMemoryReader
{
    private readonly IMemoryReader _inner;
    private readonly Dictionary<ulong, byte> _overrides = [];
    private readonly List<(ulong Start, ulong End)> _holes = [];

    public MutableMemoryOverlay(IMemoryReader inner) => _inner = inner;

    public bool Is64Bit => _inner.Is64Bit;

    /// <summary>
    /// Make every read that touches <paramref name="length"/> bytes at
    /// <paramref name="address"/> fail, as an unmapped or torn-away range would.
    /// </summary>
    /// <remarks>
    /// Byte-granular rather than page-granular on purpose: the reads under test sit inside a
    /// structure whose other fields must stay readable, so removing the page would fail the
    /// validation that has to succeed first.
    /// </remarks>
    public void Unreadable(ulong address, int length) => _holes.Add((address, address + (ulong)length));

    /// <summary>Change a 32-bit value as the target would while it runs.</summary>
    public void WriteI32(ulong address, int value)
    {
        Span<byte> buffer = stackalloc byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(buffer, value);
        for (int i = 0; i < buffer.Length; i++) _overrides[address + (ulong)i] = buffer[i];
    }

    public bool TryRead(ulong address, Span<byte> buffer)
    {
        ulong end = address + (ulong)buffer.Length;
        foreach ((ulong holeStart, ulong holeEnd) in _holes)
        {
            if (address < holeEnd && holeStart < end) return false;
        }

        if (!_inner.TryRead(address, buffer)) return false;
        if (_overrides.Count == 0) return true;

        for (int i = 0; i < buffer.Length; i++)
        {
            if (_overrides.TryGetValue(address + (ulong)i, out byte value)) buffer[i] = value;
        }

        return true;
    }

    public void Dispose()
    {
        // The inner reader is owned by the fixture.
    }
}
