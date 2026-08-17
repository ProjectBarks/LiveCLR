namespace LiveClr.Memory;

using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

/// <summary>
/// One loaded image in the target: where it starts, how big it is, and the name
/// callers actually refer to it by.
/// </summary>
/// <remarks>
/// <see cref="BaseAddress"/> is the anchor for everything above this layer.
/// Analysis doc §4.3 resolves exports by reading the target's own PE headers
/// starting from this address, which is what makes the whole design ASLR-immune
/// and removes any need to load a local copy of the DLL.
/// </remarks>
public sealed record ModuleInfo
{
    /// <param name="fileName">Base name as the loader reports it, e.g. <c>coreclr.dll</c>.</param>
    /// <param name="baseAddress">Value of <c>MODULEINFO.lpBaseOfDll</c>.</param>
    /// <param name="size">Value of <c>MODULEINFO.SizeOfImage</c>.</param>
    /// <param name="entryPoint">Value of <c>MODULEINFO.EntryPoint</c>; diagnostic only.</param>
    public ModuleInfo(string fileName, ulong baseAddress, uint size, ulong entryPoint = 0)
    {
        ArgumentNullException.ThrowIfNull(fileName);
        FileName = fileName;
        Name = ModuleTable.SimpleName(fileName);
        BaseAddress = baseAddress;
        Size = size;
        EntryPoint = entryPoint;
    }

    /// <summary>Base name including extension, e.g. <c>coreclr.dll</c>.</summary>
    public string FileName { get; }

    /// <summary>
    /// Name with a trailing <c>.dll</c> or <c>.exe</c> removed, e.g. <c>coreclr</c>
    /// or <c>sts2</c>. This is the form §4.2 and §4.4 match on: scry compares
    /// against <c>L"coreclr.dll"</c> for the runtime but against bare
    /// <c>"sts2"</c> for the game assembly, and a caller should not have to know
    /// which spelling a given image uses.
    /// </summary>
    /// <remarks>
    /// Only image extensions are stripped, never an arbitrary final dot-segment:
    /// <c>System.Private.CoreLib.dll</c> keeps its dotted namespace, and a module
    /// genuinely named <c>MegaCrit.Sts2.dll</c> does not collapse onto
    /// <c>MegaCrit</c>.
    /// </remarks>
    public string Name { get; }

    /// <summary>Image base in the target's address space.</summary>
    public ulong BaseAddress { get; }

    /// <summary>Virtual size of the mapped image.</summary>
    public uint Size { get; }

    /// <summary>Image entry point. Recorded for diagnostics; nothing in LiveClr calls it.</summary>
    public ulong EntryPoint { get; }

    /// <summary>One past the last byte of the mapped image.</summary>
    public ulong EndAddress => BaseAddress + Size;

    /// <summary>
    /// Whether <paramref name="address"/> falls inside this image. Useful for
    /// deciding whether a pointer is a static/native address rather than a
    /// managed one — the distinction §7b.1 turns on.
    /// </summary>
    public bool Contains(ulong address) => address >= BaseAddress && address < EndAddress;

    /// <inheritdoc/>
    public override string ToString() => $"{FileName} @ {BaseAddress:X} ({Size:X} bytes)";
}

/// <summary>
/// The loaded-module set of a target process, with case-insensitive lookup by
/// simple name.
/// </summary>
/// <remarks>
/// This is the §4.2 walk: <c>K32EnumProcessModulesEx</c>, then
/// <c>K32GetModuleBaseNameW</c> and <c>K32GetModuleInformation</c> per handle.
/// Documented Win32, nothing injected, nothing loaded locally.
/// <para>
/// The table is a snapshot of a moment. Analysis doc §8.8 puts module info in
/// the <em>process</em> lifetime tier, so building it once at attach is correct
/// for the runtime and game images; anything that can be unloaded mid-session
/// needs a fresh enumeration instead.
/// </para>
/// </remarks>
public sealed class ModuleTable
{
    /// <summary>The only suffixes treated as extensions. A ".pdb" or a ".Sts2" is part of the name.</summary>
    private static readonly string[] ImageExtensions = [".dll", ".exe"];

    private readonly ModuleInfo[] _modules;
    private readonly Dictionary<string, ModuleInfo> _byFileName;
    private readonly Dictionary<string, ModuleInfo> _bySimpleName;

    /// <summary>
    /// Builds a table over an explicit module list. Exists so name matching can
    /// be exercised without a live process, and so recorded fixtures (§8.8) can
    /// replay a module set in CI.
    /// </summary>
    public ModuleTable(IEnumerable<ModuleInfo> modules)
    {
        ArgumentNullException.ThrowIfNull(modules);
        _modules = modules.ToArray();
        _byFileName = new Dictionary<string, ModuleInfo>(StringComparer.OrdinalIgnoreCase);
        _bySimpleName = new Dictionary<string, ModuleInfo>(StringComparer.OrdinalIgnoreCase);

        // First occurrence wins: EnumProcessModules returns load order, and the
        // first image to claim a name is the one the loader actually resolved.
        foreach (var m in _modules)
        {
            _byFileName.TryAdd(m.FileName, m);
            _bySimpleName.TryAdd(m.Name, m);
        }
    }

    /// <summary>Every module, in enumeration (load) order.</summary>
    public IReadOnlyList<ModuleInfo> Modules => _modules;

    /// <summary>Simple names of every module, suitable for <c>ILiveProcess.ModuleNames</c>.</summary>
    public IReadOnlyCollection<string> Names => _bySimpleName.Keys;

    /// <summary>Number of modules enumerated.</summary>
    public int Count => _modules.Length;

    /// <summary>
    /// Looks up by file name or simple name, case-insensitively —
    /// <c>"coreclr"</c>, <c>"CoreCLR"</c> and <c>"coreclr.dll"</c> all resolve to
    /// the same image.
    /// </summary>
    /// <remarks>
    /// Matching is exact on one of the two indexes; it never rewrites the query.
    /// That matters in the false-positive direction:
    /// <list type="bullet">
    /// <item>A query carrying an explicit extension is a requirement, so
    /// <c>"sts2.dll"</c> resolves to <c>sts2.dll</c> even when <c>sts2.exe</c> is
    /// also loaded, and to nothing when only the EXE is.</item>
    /// <item><c>"coreclr.pdb"</c> does not resolve to <c>coreclr.dll</c> — a
    /// debug file is not the image.</item>
    /// <item><c>"MegaCrit.Sts2"</c> does not resolve to a loaded
    /// <c>MegaCrit.dll</c>. Silently answering with the wrong module is the
    /// worst outcome here: every offset read from it would be plausible and
    /// wrong.</item>
    /// </list>
    /// </remarks>
    public bool TryGet(string name, [NotNullWhen(true)] out ModuleInfo? module)
    {
        ArgumentNullException.ThrowIfNull(name);

        return _byFileName.TryGetValue(name, out module)
            || _bySimpleName.TryGetValue(name, out module);
    }

    /// <summary>Non-throwing lookup; null when absent.</summary>
    public ModuleInfo? Find(string name) => TryGet(name, out var m) ? m : null;

    /// <summary>Lookup that throws when the image is not loaded.</summary>
    /// <exception cref="KeyNotFoundException">No module matches.</exception>
    public ModuleInfo this[string name] =>
        TryGet(name, out var m)
            ? m
            : throw new KeyNotFoundException($"Module '{name}' is not loaded in the target.");

    /// <summary>
    /// The image containing <paramref name="address"/>, if any. Linear because
    /// module counts are in the hundreds and this runs off the hot path.
    /// </summary>
    public ModuleInfo? FindContaining(ulong address)
    {
        foreach (var m in _modules)
        {
            if (m.Contains(address)) return m;
        }
        return null;
    }

    /// <summary>
    /// Strips a trailing <c>.dll</c>/<c>.exe</c> and nothing else. Stripping any
    /// final dot-segment would fold <c>MegaCrit.Sts2</c> onto <c>MegaCrit</c> and
    /// <c>coreclr.pdb</c> onto <c>coreclr</c>.
    /// </summary>
    internal static string SimpleName(string fileName)
    {
        foreach (var extension in ImageExtensions)
        {
            if (fileName.Length > extension.Length &&
                fileName.EndsWith(extension, StringComparison.OrdinalIgnoreCase))
            {
                return fileName[..^extension.Length];
            }
        }
        return fileName;
    }

    /// <summary>
    /// The §4.2 walk against a live handle. Modules that vanish between
    /// enumeration and query are skipped rather than failing the whole table —
    /// a DLL unloading mid-walk is normal, not an error.
    /// </summary>
    /// <remarks>
    /// Failure of the enumeration itself throws. An empty table is not a valid
    /// answer for a live process, and returning one would be indistinguishable
    /// from a genuine result — the caller would then be told "coreclr is not
    /// loaded" when the truth is that the process exited or the handle lacks
    /// rights.
    /// </remarks>
    /// <exception cref="Win32Exception"><c>K32EnumProcessModulesEx</c> failed.</exception>
    internal static ModuleTable Enumerate(SafeProcessHandle handle)
    {
        var handles = EnumerateModuleHandles(handle);
        var list = new List<ModuleInfo>(handles.Length);
        Span<char> nameBuffer = stackalloc char[512];

        foreach (var h in handles)
        {
            if (!NativeMethods.K32GetModuleInformation(handle, h, out var info, Marshal.SizeOf<NativeMethods.MODULEINFO>()))
                continue;

            int len = NativeMethods.K32GetModuleBaseNameW(handle, h, ref MemoryMarshal.GetReference(nameBuffer), nameBuffer.Length);
            if (len <= 0) continue;

            list.Add(new ModuleInfo(
                new string(nameBuffer[..len]),
                (ulong)info.lpBaseOfDll,
                info.SizeOfImage,
                (ulong)info.EntryPoint));
        }

        // An exited process does NOT fail enumeration — measured:
        // K32EnumProcessModulesEx returns TRUE with a byte count of zero once the
        // target is gone, so a rights or liveness problem arrives disguised as a
        // successful empty result. No live process has zero modules, so treat it
        // as the failure it is rather than caching "coreclr is not loaded".
        if (list.Count == 0)
        {
            throw new Win32Exception(
                "K32EnumProcessModulesEx returned no modules. A live process always has at least its own image, " +
                "so the target has most likely exited or the handle lacks PROCESS_QUERY_INFORMATION.");
        }

        return new ModuleTable(list);
    }

    private static nint[] EnumerateModuleHandles(SafeProcessHandle handle)
    {
        // Sizing call first: the module set can grow between the two calls, so
        // loop until the returned byte count fits the buffer we passed.
        if (!NativeMethods.K32EnumProcessModulesEx(handle, null, 0, out int needed, NativeMethods.LIST_MODULES_ALL))
            throw EnumerationFailed();

        for (int attempt = 0; attempt < 4; attempt++)
        {
            int capacity = Math.Max(needed / nint.Size, 1) + 64;
            var buffer = new nint[capacity];
            if (!NativeMethods.K32EnumProcessModulesEx(handle, buffer, capacity * nint.Size, out needed, NativeMethods.LIST_MODULES_ALL))
                throw EnumerationFailed();

            int count = needed / nint.Size;
            if (count <= capacity) return buffer[..count];
        }

        throw new Win32Exception(
            "K32EnumProcessModulesEx did not converge: the target's module set kept growing across four attempts.");
    }

    private static Win32Exception EnumerationFailed()
    {
        int error = Marshal.GetLastWin32Error();
        return new Win32Exception(error, $"K32EnumProcessModulesEx failed (win32 error {error}); the target's module list is unknown.");
    }
}
