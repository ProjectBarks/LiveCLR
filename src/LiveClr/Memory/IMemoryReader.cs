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
/// A read that could not be satisfied.
/// </summary>
/// <remarks>
/// The message shape is a CONTRACT, not cosmetic. The existing TypeScript consumer
/// (<c>scryObject.ts</c> <c>isTransientRead</c>) classifies retryable failures like this:
/// <code>
///   if (/remote address 0+:/.test(m)) return false          // null deref: never retry
///   return m.includes('Invalid access to memory location')
///       || m.includes('Only part of a Read')                 // torn/unmapped: retry
/// </code>
/// Two consequences, both learned the hard way:
/// <list type="number">
/// <item>The <b>trailing colon after the address is load-bearing</b> — it terminates the
/// address in the <c>0+:</c> pattern. Without it the address-zero exclusion never matches and
/// null-pointer reads get retried, which §6.4 says must not happen.</item>
/// <item>The colon is a <b>separator before the underlying Win32 error text</b>, which is the
/// substring the classifier actually keys on. A message ending at the address matches NEITHER
/// arm, so <c>isTransientRead</c> returns false for everything and retry silently never fires.</item>
/// </list>
/// Hence: <c>Failed to read {N} bytes from remote address {ADDR:X}: {win32 message}</c>.
/// See analysis doc §4.8.
/// </remarks>
public sealed class MemoryAccessException : Exception
{
    public ulong Address { get; }
    public int Length { get; }

    /// <summary>Win32 error code from the failed read, or 0 if unknown.</summary>
    public int NativeErrorCode { get; }

    public MemoryAccessException(ulong address, int length, int nativeErrorCode = 0)
        : base(Format(address, length, nativeErrorCode))
    {
        Address = address;
        Length = length;
        NativeErrorCode = nativeErrorCode;
    }

    private static string Format(ulong address, int length, int nativeErrorCode)
    {
        // MEASURED: ReadProcessMemory returns ERROR_PARTIAL_COPY (299) for a WHOLLY unmapped
        // address as well as a straddling one — the Win32 error does NOT distinguish "torn read"
        // from "bad pointer". Do not build anything on "299 means torn". Both are retryable, so
        // §4.8's behaviour is unaffected, but only pre-syscall rejections (998) can be labelled
        // precisely.
        var detail = nativeErrorCode switch
        {
            299 => "Only part of a ReadProcessMemory or WriteProcessMemory request was completed.",
            998 => "Invalid access to memory location.",
            0 => "Invalid access to memory location.",
            _ => new System.ComponentModel.Win32Exception(nativeErrorCode).Message,
        };
        return $"Failed to read {length} bytes from remote address {address:X}: {detail}";
    }
}
