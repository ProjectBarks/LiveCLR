namespace LiveClr.Memory;

using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

/// <summary>
/// A region of the target's address space as reported by <c>VirtualQueryEx</c>.
/// </summary>
/// <remarks>
/// Exposed because "is this address even mapped?" is the cheapest way to tell a
/// genuinely bad pointer from a transient read failure, and §4.8's retry contract
/// depends on that distinction being makeable.
/// </remarks>
public readonly record struct MemoryRegion(ulong BaseAddress, ulong Size, uint State, uint Protect, uint Type)
{
    /// <summary>True when the region is backed by committed pages.</summary>
    public bool IsCommitted => State == NativeMethods.MEM_COMMIT;

    /// <summary>
    /// True when a read of this region can be expected to succeed. Guard pages
    /// are excluded: touching one from outside still fails, and would be
    /// disruptive to the target if it did not.
    /// </summary>
    public bool IsReadable =>
        IsCommitted &&
        (Protect & NativeMethods.PAGE_READABLE_MASK) != 0 &&
        (Protect & NativeMethods.PAGE_GUARD) == 0;

    /// <summary>One past the last byte of the region.</summary>
    public ulong EndAddress => BaseAddress + Size;
}

/// <summary>
/// The Win32 implementation of <see cref="IMemoryReader"/>: <c>OpenProcess</c>
/// for read + query, and <c>ReadProcessMemory</c> for everything above.
/// </summary>
/// <remarks>
/// This is the §4.1 primitive set, reduced to what §6.2 says we actually need.
/// The handle is opened with <c>PROCESS_VM_READ | PROCESS_QUERY_INFORMATION</c>
/// and nothing else — no <c>PROCESS_VM_WRITE</c>, no <c>PROCESS_VM_OPERATION</c>,
/// no <c>PROCESS_SUSPEND_RESUME</c>. The target therefore cannot be modified or
/// stopped by this class even by mistake, which is the property that lets the
/// library be pointed at a running game.
/// <para>
/// <b>Reads fail closed.</b> <c>ReadProcessMemory</c> can return
/// <c>ERROR_PARTIAL_COPY</c> having filled part of the buffer; that is reported
/// as failure and the buffer is zeroed. §4.8 and §6.4: a read that "succeeds"
/// with half a pointer is the failure mode that costs the most to debug, and it
/// is precisely what happens when a traversal races the target's allocator.
/// </para>
/// <para>
/// Instances are process-lifetime (§8.8 lifetime tiers) and safe for concurrent
/// reads — <c>ReadProcessMemory</c> carries no per-handle state.
/// </para>
/// </remarks>
public sealed class WindowsProcessMemory : IMemoryReader, IMemoryReadDiagnostics
{
    private readonly SafeProcessHandle _handle;
    private ModuleTable? _modules;
    private int _lastNativeErrorCode;
    private bool _disposed;

    private WindowsProcessMemory(int processId, SafeProcessHandle handle, bool is64Bit)
    {
        ProcessId = processId;
        _handle = handle;
        Is64Bit = is64Bit;
    }

    /// <summary>Process id of the attached target.</summary>
    public int ProcessId { get; }

    /// <inheritdoc/>
    public bool Is64Bit { get; }

    /// <inheritdoc/>
    public int LastNativeErrorCode => _lastNativeErrorCode;

    /// <summary>
    /// Modules loaded in the target, enumerated on first access and then cached.
    /// Caching is correct per §8.8: module info sits in the process lifetime tier.
    /// Call <see cref="RefreshModules"/> if a late-loading image is expected.
    /// </summary>
    /// <remarks>
    /// A failed enumeration throws and is <b>not</b> cached, so one transient
    /// failure at attach cannot poison every later lookup with a misleading
    /// "module is not loaded".
    /// </remarks>
    /// <exception cref="Win32Exception">Module enumeration failed.</exception>
    public ModuleTable Modules
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _modules ??= ModuleTable.Enumerate(_handle);
        }
    }

    /// <summary>Opens the target for reading.</summary>
    /// <exception cref="Win32Exception">The process does not exist or access was denied.</exception>
    public static WindowsProcessMemory Open(int processId)
    {
        var handle = NativeMethods.OpenProcess(
            NativeMethods.PROCESS_VM_READ | NativeMethods.PROCESS_QUERY_INFORMATION,
            false,
            processId);

        if (handle.IsInvalid)
        {
            int error = Marshal.GetLastWin32Error();
            handle.Dispose();
            throw new Win32Exception(error, $"OpenProcess failed for pid {processId} (win32 error {error}).");
        }

        return new WindowsProcessMemory(processId, handle, DetectIs64Bit(handle));
    }

    /// <summary>Non-throwing form of <see cref="Open"/>.</summary>
    public static bool TryOpen(int processId, [NotNullWhen(true)] out WindowsProcessMemory? memory)
    {
        try
        {
            memory = Open(processId);
            return true;
        }
        catch (Win32Exception)
        {
            memory = null;
            return false;
        }
    }

    /// <inheritdoc/>
    public bool TryRead(ulong address, Span<byte> buffer)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (buffer.Length == 0)
        {
            _lastNativeErrorCode = 0;
            return true;
        }

        // Address zero is never a legitimate target. §6.4 calls out the
        // deliberate exclusion of address-zero reads from retry: they are a null
        // deref in the walk, not a transient condition worth re-attempting.
        if (address == 0) return Reject(buffer);

        // A wrap past the end of the address space cannot be a real object.
        if (ulong.MaxValue - address < (ulong)(buffer.Length - 1)) return Reject(buffer);

        // The host must be able to express the target address at all; a 32-bit
        // host cannot read a 64-bit target and must say so rather than truncate.
        if (nuint.Size < sizeof(ulong) && address > uint.MaxValue) return Reject(buffer);

        bool ok = NativeMethods.ReadProcessMemory(
            _handle,
            (nuint)address,
            ref MemoryMarshal.GetReference(buffer),
            (nuint)buffer.Length,
            out nuint read);

        // Capture the error before anything else can clobber it. ERROR_PARTIAL_COPY
        // here is what tells §4.8's classifier the failure is worth retrying.
        int error = ok ? 0 : Marshal.GetLastWin32Error();

        if (ok && read == (nuint)buffer.Length)
        {
            _lastNativeErrorCode = 0;
            return true;
        }

        // Fail closed. A short read leaves the tail of the buffer untouched, so
        // zero it: a caller that ignores the return value must not be handed a
        // convincing-looking half-object.
        _lastNativeErrorCode = error != 0 ? error : NativeMethods.ERROR_NOACCESS;
        buffer.Clear();
        return false;

        bool Reject(Span<byte> b)
        {
            _lastNativeErrorCode = NativeMethods.ERROR_NOACCESS;
            b.Clear();
            return false;
        }
    }

    /// <summary>
    /// Queries the region containing <paramref name="address"/>. Read-only; the
    /// allowed primitive set in §4.1 includes query but not protect or allocate.
    /// </summary>
    public bool TryQueryRegion(ulong address, out MemoryRegion region)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        region = default;

        if (nuint.Size < sizeof(ulong) && address > uint.MaxValue) return false;

        nuint written = NativeMethods.VirtualQueryEx(
            _handle,
            (nuint)address,
            out var mbi,
            (nuint)Marshal.SizeOf<NativeMethods.MEMORY_BASIC_INFORMATION>());

        if (written == 0) return false;

        region = new MemoryRegion(mbi.BaseAddress, mbi.RegionSize, mbi.State, mbi.Protect, mbi.Type);
        return true;
    }

    /// <summary>Re-enumerates modules, discarding the cached table.</summary>
    public ModuleTable RefreshModules()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _modules = ModuleTable.Enumerate(_handle);
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _modules = null;
        _handle.Dispose();
    }

    /// <summary>
    /// <c>IsWow64Process</c> answers "is this a 32-bit process on 64-bit Windows".
    /// Combined with the OS bitness that is the whole pointer-width question, and
    /// §4.1 notes pointer width is the only thing that needs to vary between
    /// targets.
    /// </summary>
    private static bool DetectIs64Bit(SafeProcessHandle handle)
    {
        if (!Environment.Is64BitOperatingSystem) return false;
        if (!NativeMethods.IsWow64Process(handle, out bool isWow64))
        {
            int error = Marshal.GetLastWin32Error();
            handle.Dispose();
            throw new Win32Exception(error, $"IsWow64Process failed (win32 error {error}); target bitness is unknown.");
        }
        return !isWow64;
    }
}
