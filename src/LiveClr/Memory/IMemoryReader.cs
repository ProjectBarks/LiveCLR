namespace LiveClr.Memory;

/// <summary>
/// The single primitive every layer above is built on: read bytes from a target
/// address space. Implementations must never write, inject, hook, or suspend.
/// </summary>
/// <remarks>
/// Deliberately minimal. A reader either fills the whole buffer or fails —
/// partial reads are reported as failure so callers cannot silently act on
/// half a pointer. See the analysis doc §4.8 / §6.4: reads that "succeed"
/// with garbage are the failure mode that costs the most to debug.
/// </remarks>
public interface IMemoryReader : IDisposable
{
    /// <summary>True if the target is 64-bit. Pointer width follows from this.</summary>
    bool Is64Bit { get; }

    /// <summary>
    /// Fill <paramref name="buffer"/> from <paramref name="address"/>.
    /// Returns false on any failure, including a short read.
    /// </summary>
    bool TryRead(ulong address, Span<byte> buffer);
}

/// <summary>Convenience reads layered over <see cref="IMemoryReader.TryRead"/>.</summary>
public static class MemoryReaderExtensions
{
    public static bool TryRead<T>(this IMemoryReader r, ulong address, out T value)
        where T : unmanaged
    {
        value = default;
        Span<byte> buf = stackalloc byte[System.Runtime.CompilerServices.Unsafe.SizeOf<T>()];
        if (!r.TryRead(address, buf)) return false;
        value = System.Runtime.InteropServices.MemoryMarshal.Read<T>(buf);
        return true;
    }

    public static T Read<T>(this IMemoryReader r, ulong address) where T : unmanaged =>
        r.TryRead(address, out T v)
            ? v
            : throw new MemoryAccessException(address, System.Runtime.CompilerServices.Unsafe.SizeOf<T>());

    public static bool TryReadPointer(this IMemoryReader r, ulong address, out ulong value)
    {
        if (r.Is64Bit) return r.TryRead(address, out value);
        value = 0;
        if (!r.TryRead(address, out uint v32)) return false;
        value = v32;
        return true;
    }

    public static ulong ReadPointer(this IMemoryReader r, ulong address) =>
        r.TryReadPointer(address, out var v)
            ? v
            : throw new MemoryAccessException(address, r.Is64Bit ? 8 : 4);

    public static byte[] ReadBytes(this IMemoryReader r, ulong address, int count)
    {
        var buf = new byte[count];
        if (!r.TryRead(address, buf)) throw new MemoryAccessException(address, count);
        return buf;
    }
}

/// <summary>
/// A read that could not be satisfied. Mirrors the error contract the existing
/// TypeScript consumer keys off (analysis doc §4.8): the message must name the
/// byte count and the remote address so transient-vs-fatal can be distinguished.
/// </summary>
public sealed class MemoryAccessException : Exception
{
    public ulong Address { get; }
    public int Length { get; }

    public MemoryAccessException(ulong address, int length)
        : base($"Failed to read {length} bytes from remote address {address:X}")
    {
        Address = address;
        Length = length;
    }
}
