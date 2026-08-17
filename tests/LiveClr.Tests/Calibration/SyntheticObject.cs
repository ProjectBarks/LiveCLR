namespace LiveClr.Tests.Calibration;

using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using LiveClr.Fixtures;
using LiveClr.Tests.Fixtures;

/// <summary>
/// A struct with a layout the test knows and the probe does not: junk everywhere, known values
/// at chosen offsets. Exactly the setup analysis doc §12.5 had, minus the game.
/// </summary>
internal sealed class SyntheticObject
{
    private readonly byte[] _bytes;

    public SyntheticObject(ulong address, int size, int junkSeed)
    {
        Address = address;
        // Junk, not zeroes: a zero-filled object makes every probe look unrealistically precise.
        _bytes = FakeTargetMemory.Junk(size, junkSeed);
    }

    public ulong Address { get; }

    public SyntheticObject Put<T>(int offset, T value) where T : unmanaged
    {
        MemoryMarshal.Write(_bytes.AsSpan(offset, Unsafe.SizeOf<T>()), in value);
        return this;
    }

    public SyntheticObject PutPair<T>(int offset, T first, T second) where T : unmanaged
    {
        int size = Unsafe.SizeOf<T>();
        return Put(offset, first).Put(offset + size, second);
    }

    public RecordedMemoryBuilder AddTo(RecordedMemoryBuilder builder)
    {
        builder.Add(Address, _bytes);
        return builder;
    }
}
