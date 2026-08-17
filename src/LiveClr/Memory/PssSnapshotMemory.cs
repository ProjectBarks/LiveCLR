namespace LiveClr.Memory;

using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

/// <summary>
/// A coherent, point-in-time view of a target's address space, backed by a
/// Process Snapshotting (PSS) VA clone.
/// </summary>
/// <remarks>
/// Analysis doc §8.8's <c>SnapshotMode.ProcessSnapshot</c>. Its first job is as a
/// <b>correctness oracle</b>: diffing a <c>LiveValidated</c> traversal against a
/// PSS-coherent read of the same moment is what turns the §12.4e tearing class —
/// silent, no failed reads, ~4% of mutating samples — into something a
/// randomized test can catch. §8.8 also asks for it to be benchmarked as a
/// product mode, since PSS is copy-on-write and, if cheap enough at 4 Hz, would
/// eliminate that bug class rather than merely detect it.
/// <para>
/// <b>How it reads.</b> A snapshot handle (<c>HPSS</c>) is not itself readable.
/// <c>PssCaptureSnapshot</c> with <c>PSS_CAPTURE_VA_CLONE</c> produces a
/// copy-on-write clone of the target's virtual address space, exposed as a
/// process handle via <c>PssQuerySnapshot</c>; ordinary
/// <c>ReadProcessMemory</c> against that handle is what actually returns bytes.
/// This is the same mechanism ClrMD's snapshot attach uses.
/// </para>
/// <para>
/// <b>Two deliberate departures from <see cref="WindowsProcessMemory"/>, both
/// forced by the API.</b> First, the clone handle is unreachable without
/// <c>PssQuerySnapshot</c>. Second, VA cloning requires
/// <c>PROCESS_CREATE_PROCESS</c> and <c>PROCESS_VM_OPERATION</c> on top of read
/// and query. Both are confined to this class so the product read path keeps the
/// minimal rights. The target is still never written to, injected into, or
/// suspended: cloning is copy-on-write and the original keeps running.
/// </para>
/// <para>
/// <b>Not always available.</b> Cloning requires matching bitness between host
/// and target, Windows 8.1 or later, and sufficient rights; a protected process
/// can never be cloned. Every one of those surfaces as
/// <see cref="NotSupportedException"/> at capture time rather than as a reader
/// that quietly returns wrong bytes.
/// </para>
/// </remarks>
public sealed class PssSnapshotMemory : IMemoryReader, IMemoryReadDiagnostics
{
    private const int CaptureAccess =
        NativeMethods.PROCESS_VM_READ |
        NativeMethods.PROCESS_QUERY_INFORMATION |
        NativeMethods.PROCESS_VM_OPERATION |
        NativeMethods.PROCESS_CREATE_PROCESS;

    private readonly SafeProcessHandle _target;
    private readonly SafeProcessHandle _clone;
    private nint _snapshot;
    private int _lastNativeErrorCode;
    private bool _disposed;

    private PssSnapshotMemory(
        int processId,
        SafeProcessHandle target,
        nint snapshot,
        SafeProcessHandle clone,
        int cloneProcessId,
        bool is64Bit,
        ModuleTable modules)
    {
        ProcessId = processId;
        _target = target;
        _snapshot = snapshot;
        _clone = clone;
        CloneProcessId = cloneProcessId;
        Is64Bit = is64Bit;
        Modules = modules;
    }

    /// <summary>Process id of the snapshotted target.</summary>
    public int ProcessId { get; }

    /// <summary>
    /// Process id of the VA clone, or 0 if it could not be determined. Exposed
    /// so that clone cleanup is observable — a leaked clone pins the target's
    /// copy-on-write pages and is otherwise invisible.
    /// </summary>
    public int CloneProcessId { get; }

    /// <inheritdoc/>
    public bool Is64Bit { get; }

    /// <inheritdoc/>
    public int LastNativeErrorCode => _lastNativeErrorCode;

    /// <summary>
    /// Whether <see cref="Dispose"/> released the snapshot cleanly. False means
    /// the VA clone may still be running; see the remarks on <see cref="Dispose"/>.
    /// </summary>
    public bool ReleasedCleanly { get; private set; }

    /// <summary>
    /// Modules of the <em>original</em> process, enumerated during
    /// <see cref="Capture"/>.
    /// </summary>
    /// <remarks>
    /// Eager, not lazy: this class advertises a point-in-time view, and
    /// enumerating the live target later would mix a fresh module list into a
    /// frozen memory image — the exact §12.4e mixed-moment failure the snapshot
    /// exists to rule out. Enumeration reads the original rather than the clone
    /// because a VA clone has no loader running in it; image bases are identical
    /// between the two, which is all §4.2 and §4.3 need.
    /// </remarks>
    public ModuleTable Modules { get; }

    /// <summary>
    /// Captures a snapshot of <paramref name="processId"/>.
    /// </summary>
    /// <exception cref="Win32Exception">The process could not be opened with the rights cloning needs, or its modules could not be enumerated.</exception>
    /// <exception cref="NotSupportedException">
    /// PSS is unavailable for this target — wrong bitness, protected process,
    /// unsupported OS, or capture otherwise refused. The inner exception carries
    /// the Win32 error so a caller can tell "not permitted" from "not supported".
    /// </exception>
    public static PssSnapshotMemory Capture(int processId)
    {
        var target = NativeMethods.OpenProcess(CaptureAccess, false, processId);
        if (target.IsInvalid)
        {
            int error = Marshal.GetLastWin32Error();
            target.Dispose();
            throw new Win32Exception(
                error,
                $"OpenProcess failed for pid {processId} with the rights PSS VA cloning requires " +
                $"(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_CREATE_PROCESS); win32 error {error}.");
        }

        int rc = NativeMethods.PssCaptureSnapshot(target, NativeMethods.PSS_CAPTURE_VA_CLONE, 0, out nint snapshot);
        if (rc != NativeMethods.ERROR_SUCCESS)
        {
            target.Dispose();
            throw new NotSupportedException(
                $"PssCaptureSnapshot(PSS_CAPTURE_VA_CLONE) failed for pid {processId} with win32 error {rc}. " +
                "VA cloning requires Windows 8.1+, a target of the same bitness as this process, and a non-protected target.",
                new Win32Exception(rc));
        }

        try
        {
            rc = NativeMethods.PssQuerySnapshot(snapshot, NativeMethods.PSS_QUERY_VA_CLONE_INFORMATION, out nint cloneHandle, nint.Size);
            if (rc != NativeMethods.ERROR_SUCCESS || cloneHandle == 0)
            {
                throw new NotSupportedException(
                    $"PssQuerySnapshot(PSS_QUERY_VA_CLONE_INFORMATION) failed for pid {processId} with win32 error {rc}. " +
                    "Without the VA clone handle the snapshot cannot be read.",
                    new Win32Exception(rc));
            }

            // ownsHandle: false. PssFreeSnapshot closes the clone handle itself —
            // measured, see the Dispose remarks — so closing it here as well would
            // be a double close onto a recycled handle value.
            var clone = new SafeProcessHandle(cloneHandle, ownsHandle: false);
            int clonePid = NativeMethods.GetProcessId(cloneHandle);

            // Bitness comes from the original handle, not the clone. Failing to
            // determine it must not silently default to 32-bit: every pointer read
            // above this layer would then be truncated.
            bool is64Bit = false;
            if (Environment.Is64BitOperatingSystem)
            {
                if (!NativeMethods.IsWow64Process(target, out bool isWow64))
                {
                    int error = Marshal.GetLastWin32Error();
                    throw new Win32Exception(error, $"IsWow64Process failed (win32 error {error}); target bitness is unknown.");
                }
                is64Bit = !isWow64;
            }

            var modules = ModuleTable.Enumerate(target);

            return new PssSnapshotMemory(processId, target, snapshot, clone, clonePid, is64Bit, modules);
        }
        catch
        {
            // Every failure past a successful capture must still release the
            // snapshot, or the clone survives as an orphaned suspended process.
            NativeMethods.PssFreeSnapshot(NativeMethods.GetCurrentProcess(), snapshot);
            target.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Non-throwing form of <see cref="Capture"/>, for callers that treat PSS as
    /// an optional oracle rather than a requirement.
    /// </summary>
    public static bool TryCapture(int processId, [NotNullWhen(true)] out PssSnapshotMemory? snapshot)
    {
        try
        {
            snapshot = Capture(processId);
            return true;
        }
        catch (Exception e) when (e is Win32Exception or NotSupportedException)
        {
            snapshot = null;
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

        if (address == 0) return Reject(buffer);
        if (ulong.MaxValue - address < (ulong)(buffer.Length - 1)) return Reject(buffer);
        if (nuint.Size < sizeof(ulong) && address > uint.MaxValue) return Reject(buffer);

        bool ok = NativeMethods.ReadProcessMemory(
            _clone,
            (nuint)address,
            ref MemoryMarshal.GetReference(buffer),
            (nuint)buffer.Length,
            out nuint read);

        int error = ok ? 0 : Marshal.GetLastWin32Error();

        if (ok && read == (nuint)buffer.Length)
        {
            _lastNativeErrorCode = 0;
            return true;
        }

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
    /// Releases the snapshot, which also terminates and closes the VA clone.
    /// </summary>
    /// <remarks>
    /// <b>The first argument to <c>PssFreeSnapshot</c> is the process
    /// <i>containing the snapshot</i> — always ours, never the target.</b> This
    /// is easy to get backwards because every other PSS call takes the target,
    /// and self-capture hides the mistake completely (there the two handles name
    /// the same process). Measured against a separate child process:
    /// <code>
    ///   PssFreeSnapshot(target handle)      rc=299 ERROR_PARTIAL_COPY, clone still alive
    ///   PssFreeSnapshot(GetCurrentProcess)  rc=0,                      clone terminated
    /// </code>
    /// Passing the target leaks the PSS structure, the clone process and its
    /// pinned copy-on-write pages, once per capture — at §8.8's 4 Hz that is
    /// thousands of suspended zombie processes an hour. Worse, rc=299 is a
    /// <em>memory</em> error: given a handle carrying <c>PROCESS_VM_OPERATION</c>,
    /// the API reached into the target's address space with a pointer that is
    /// only meaningful in ours. That is the one call in this library capable of
    /// mutating the target, and §2's promise is that it never does.
    /// <para>
    /// Two follow-on details, both measured rather than assumed:
    /// <c>PssFreeSnapshot</c> <b>closes the clone handle</b> (a subsequent
    /// <c>GetProcessId</c> fails with ERROR_INVALID_HANDLE), so this class must
    /// not close it — hence <c>ownsHandle: false</c>. And the clone handle does
    /// <b>not</b> carry <c>PROCESS_TERMINATE</c>, so an explicit
    /// <c>TerminateProcess</c> would fail with ERROR_ACCESS_DENIED; it is also
    /// unnecessary, since a correct free terminates the clone by itself.
    /// </para>
    /// </remarks>
    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        if (_snapshot != 0)
        {
            int rc = NativeMethods.PssFreeSnapshot(NativeMethods.GetCurrentProcess(), _snapshot);
            ReleasedCleanly = rc == NativeMethods.ERROR_SUCCESS;
            _snapshot = 0;
        }
        else
        {
            ReleasedCleanly = true;
        }

        // No-op by construction (ownsHandle: false); PssFreeSnapshot owns it.
        _clone.Dispose();
        _target.Dispose();
    }
}
