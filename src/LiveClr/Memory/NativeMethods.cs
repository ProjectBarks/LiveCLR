namespace LiveClr.Memory;

using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

// Interop structs are populated by the marshaller, never by C# code.
#pragma warning disable CS0649

/// <summary>
/// The complete native surface of the memory layer. Analysis doc §6.3 makes
/// "documented Win32" the source of truth here, and §4.1 fixes the primitive set
/// at read + query only. Keeping every P/Invoke in one small file is the point:
/// the absence of <c>WriteProcessMemory</c>, <c>CreateRemoteThread</c>,
/// <c>SuspendThread</c> and friends is then a reviewable property of the file
/// rather than a promise in a README.
/// </summary>
internal static class NativeMethods
{
    internal const int PROCESS_QUERY_INFORMATION = 0x0400;
    internal const int PROCESS_VM_READ = 0x0010;
    internal const int PROCESS_VM_OPERATION = 0x0008;
    internal const int PROCESS_CREATE_PROCESS = 0x0080;

    internal const int LIST_MODULES_ALL = 0x03;

    internal const uint MEM_COMMIT = 0x1000;
    internal const uint PAGE_GUARD = 0x100;

    /// <summary>PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY.</summary>
    internal const uint PAGE_READABLE_MASK = 0x02 | 0x04 | 0x08 | 0x20 | 0x40 | 0x80;

    internal const uint PSS_CAPTURE_VA_CLONE = 0x0001;
    internal const int PSS_QUERY_VA_CLONE_INFORMATION = 1;

    internal const int ERROR_SUCCESS = 0;

    /// <summary>Rendered by <see cref="MemoryAccessException"/> as "Invalid access to memory location" — the substring §4.8's classifier keys on. Used for failures we reject before issuing a syscall.</summary>
    internal const int ERROR_NOACCESS = 998;

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    internal static extern SafeProcessHandle OpenProcess(
        int dwDesiredAccess,
        [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle,
        int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool ReadProcessMemory(
        SafeProcessHandle hProcess,
        nuint lpBaseAddress,
        ref byte lpBuffer,
        nuint nSize,
        out nuint lpNumberOfBytesRead);

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    internal static extern nuint VirtualQueryEx(
        SafeProcessHandle hProcess,
        nuint lpAddress,
        out MEMORY_BASIC_INFORMATION lpBuffer,
        nuint dwLength);

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool IsWow64Process(
        SafeProcessHandle hProcess,
        [MarshalAs(UnmanagedType.Bool)] out bool Wow64Process);

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool K32EnumProcessModulesEx(
        SafeProcessHandle hProcess,
        [Out] nint[]? lphModule,
        int cb,
        out int lpcbNeeded,
        int dwFilterFlag);

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true, CharSet = CharSet.Unicode)]
    internal static extern int K32GetModuleBaseNameW(
        SafeProcessHandle hProcess,
        nint hModule,
        ref char lpBaseName,
        int nSize);

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool K32GetModuleInformation(
        SafeProcessHandle hProcess,
        nint hModule,
        out MODULEINFO lpmodinfo,
        int cb);

    // PSS returns a Win32 error code directly, not BOOL — ERROR_SUCCESS means captured.
    [DllImport("kernel32.dll", ExactSpelling = true)]
    internal static extern int PssCaptureSnapshot(
        SafeProcessHandle ProcessHandle,
        uint CaptureFlags,
        uint ThreadContextFlags,
        out nint SnapshotHandle);

    /// <summary>
    /// Required to obtain the VA clone's process handle, which is the only thing
    /// a snapshot is readable through. See <see cref="PssSnapshotMemory"/>.
    /// </summary>
    [DllImport("kernel32.dll", ExactSpelling = true)]
    internal static extern int PssQuerySnapshot(
        nint SnapshotHandle,
        int InformationClass,
        out nint Buffer,
        int BufferLength);

    /// <summary>
    /// <paramref name="ProcessHandle"/> is the process <b>containing the snapshot</b>,
    /// which is always ours — never the target. Raw <c>nint</c> rather than
    /// <see cref="SafeProcessHandle"/> because the only correct argument is the
    /// current-process pseudo-handle, which must never be closed.
    /// See <see cref="PssSnapshotMemory"/> for the measurements behind this.
    /// </summary>
    [DllImport("kernel32.dll", ExactSpelling = true)]
    internal static extern int PssFreeSnapshot(nint ProcessHandle, nint SnapshotHandle);

    /// <summary>Returns the pseudo-handle <c>(HANDLE)-1</c>. Not a real handle; must not be closed.</summary>
    [DllImport("kernel32.dll", ExactSpelling = true)]
    internal static extern nint GetCurrentProcess();

    /// <summary>Read-only. Used only to record the VA clone's pid so its cleanup is observable.</summary>
    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    internal static extern int GetProcessId(nint Process);

    /// <summary>Native-width layout: <c>nuint</c> members reproduce both the x86 (28 byte) and x64 (48 byte) forms.</summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct MEMORY_BASIC_INFORMATION
    {
        public nuint BaseAddress;
        public nuint AllocationBase;
        public uint AllocationProtect;
        public nuint RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MODULEINFO
    {
        public nint lpBaseOfDll;
        public uint SizeOfImage;
        public nint EntryPoint;
    }
}

#pragma warning restore CS0649
