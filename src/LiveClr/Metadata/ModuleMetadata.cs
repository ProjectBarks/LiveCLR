namespace LiveClr.Metadata;

using System.Reflection.Metadata;
using System.Runtime.InteropServices;
using LiveClr.Memory;

/// <summary>Why a module did or did not yield ECMA-335 metadata.</summary>
/// <remarks>
/// The distinction that matters is <see cref="NoCliHeader"/> (a native DLL — completely
/// ordinary, the caller should move on) versus <see cref="MalformedMetadata"/> (the image
/// claimed to be managed and then failed validation — that is a real signal, usually a stale
/// or wrong module base, and it deserves to be logged rather than swallowed).
/// </remarks>
public enum ModuleMetadataStatus
{
    /// <summary>Metadata was located, bounds-checked, and parsed.</summary>
    Loaded,

    /// <summary>No <c>MZ</c>/<c>PE\0\0</c> at the given base — not a mapped PE image at all.</summary>
    NotAPeImage,

    /// <summary>A valid PE image with no CLI data directory: a native DLL. Not an error.</summary>
    NoCliHeader,

    /// <summary>Headers were readable but the metadata blob itself could not be copied out.</summary>
    MetadataUnreadable,

    /// <summary>The blob was copied but failed validation and was NOT handed to MetadataReader.</summary>
    MalformedMetadata,
}

/// <summary>
/// The ECMA-335 metadata of one module in the target process, copied out once and parsed
/// locally.
/// </summary>
/// <remarks>
/// <para>
/// <b>The route (analysis doc §12.4d, proven live).</b> A managed object's
/// <c>MethodTable</c> (low bits masked with <c>ObjectToMethodTableUnmask=0x7</c>) yields
/// <c>MethodTable.Module</c> at offset 24, whose <c>Module.Base</c> at offset 192 (§5.2) is
/// the PE image in the target. From there this type walks <c>e_lfanew</c> → <c>PE\0\0</c> →
/// data directory 14 → CLI header → metadata RVA/size. Every offset in that chain is
/// published by the runtime's own cDAC descriptor, so nothing here is hardcoded CLR layout.
/// </para>
/// <para>
/// <b>Why one bulk copy (§7b.3).</b> The blob is 4,967,924 bytes for <c>sts2.dll</c>. Walking
/// it remotely field-by-field would be thousands of round trips per lookup. It is copied once,
/// at connect, and every subsequent name lookup is a local read. This also removes an entire
/// class of consistency bug: metadata lives in the module image, which does not move, so a
/// snapshot of it is coherent by construction — unlike the managed heap (§7b.1).
/// </para>
/// <para>
/// <b>Why <c>System.Reflection.Metadata</c> (§8.1, §8.8).</b> "Never hand-roll." The library
/// ships in the shared framework, adds no dependency, and gives typed table/heap access
/// instead of a bespoke <c>#~</c>/<c>#Strings</c>/<c>#Blob</c> parser.
/// </para>
/// <para>
/// <b>What validation does and does NOT buy.</b> <see cref="MetadataBlobValidator"/> runs
/// before the blob reaches SRM, but it is a STRUCTURAL check only — signature, version block,
/// and stream bounds. It never reads a table row, so a blob can pass validation, construct a
/// <c>MetadataReader</c> without complaint, and still contain rows whose heap handles point
/// nowhere: SRM bounds-checks those lazily, at access time. A successful
/// <see cref="TryLoad(IMemoryReader, ulong)"/> therefore means "this is shaped like metadata",
/// not "this is valid metadata". Surviving the rest is <see cref="TypeResolver"/>'s job, and it
/// is written for hostile tables accordingly.
/// </para>
/// <para>
/// <b>Lifetime: PROCESS tier (§8.8).</b> Module images do not move and are not collected while
/// the process lives, so this instance is safe to hold for the whole connection and must not
/// be rebuilt per snapshot. Use <see cref="ModuleMetadataCache"/> to enforce that.
/// </para>
/// </remarks>
public sealed class ModuleMetadata : IDisposable
{
    /// <summary>
    /// Fallback granularity when one large <c>ReadProcessMemory</c> fails. A single 5 MB read
    /// fails atomically if it straddles even one unreadable page, so retrying in chunks
    /// distinguishes "one bad page" from "the whole region is gone".
    /// </summary>
    private const int ChunkSize = 64 * 1024;

    private readonly MetadataReaderProvider _provider;
    private readonly byte[] _blob;
    private readonly Lazy<TypeResolver> _types;
    private bool _disposed;

    private ModuleMetadata(
        ulong moduleBase,
        uint metadataRva,
        byte[] blob,
        MetadataRootInfo root,
        MetadataReaderProvider provider,
        MetadataReader reader)
    {
        ModuleBase = moduleBase;
        MetadataRva = metadataRva;
        _blob = blob;
        Root = root;
        _provider = provider;
        Reader = reader;

        // Process-tier objects are shared, so an unsynchronized `??=` would let two threads
        // each build a full name index over a multi-megabyte blob.
        _types = new Lazy<TypeResolver>(
            () => new TypeResolver(Reader),
            LazyThreadSafetyMode.ExecutionAndPublication);
    }

    /// <summary>Address of the mapped PE image in the target — i.e. <c>Module.Base</c> (§5.2).</summary>
    public ulong ModuleBase { get; }

    /// <summary>RVA of the metadata root, from the CLI header (+8).</summary>
    public uint MetadataRva { get; }

    /// <summary>Size of the copied blob in bytes.</summary>
    public int MetadataSize => _blob.Length;

    /// <summary>Validated metadata root header: version string and stream table.</summary>
    public MetadataRootInfo Root { get; }

    /// <summary>
    /// Typed reader over the local copy. Valid only until <see cref="Dispose"/>; the backing
    /// buffer belongs to this instance.
    /// </summary>
    public MetadataReader Reader { get; }

    /// <summary>Name-side resolution over <see cref="Reader"/>. Created once, on first use.</summary>
    public TypeResolver Types => _types.Value;

    /// <summary>
    /// Locate and load the metadata of the module mapped at <paramref name="moduleBase"/>.
    /// Returns <see langword="null"/> — never throws — when the module is native or the blob
    /// fails validation.
    /// </summary>
    public static ModuleMetadata? TryLoad(IMemoryReader memory, ulong moduleBase) =>
        TryLoad(memory, moduleBase, out _, out _);

    /// <summary>
    /// As <see cref="TryLoad(IMemoryReader, ulong)"/>, reporting why the load failed.
    /// </summary>
    /// <param name="memory">Reader for the target address space.</param>
    /// <param name="moduleBase">The module's <c>Base</c> (§5.2, offset 192 in <c>Module</c>).</param>
    /// <param name="status">Outcome; see <see cref="ModuleMetadataStatus"/>.</param>
    /// <param name="detail">Human-readable explanation when <paramref name="status"/> is not
    /// <see cref="ModuleMetadataStatus.Loaded"/>.</param>
    public static ModuleMetadata? TryLoad(
        IMemoryReader memory,
        ulong moduleBase,
        out ModuleMetadataStatus status,
        out string? detail)
    {
        ArgumentNullException.ThrowIfNull(memory);

        if (!PeImage.TryLocateMetadata(memory, moduleBase, out uint rva, out uint size, out status, out detail))
        {
            return null;
        }

        var blob = new byte[size];
        if (!TryReadBlock(memory, moduleBase + rva, blob))
        {
            status = ModuleMetadataStatus.MetadataUnreadable;
            detail = $"could not copy {size} bytes of metadata from 0x{moduleBase + rva:X}";
            return null;
        }

        // MUST run before the blob reaches MetadataReader — see MetadataBlobValidator.
        if (!MetadataBlobValidator.TryValidate(blob, out MetadataRootInfo? root, out string? validationError))
        {
            status = ModuleMetadataStatus.MalformedMetadata;
            detail = validationError;
            return null;
        }

        // AsImmutableArray wraps the array we already own with no second 5 MB copy. Safe
        // because nothing else holds a reference to `blob` and this class never mutates it.
        var image = ImmutableCollectionsMarshal.AsImmutableArray(blob);

        MetadataReaderProvider? provider = null;
        try
        {
            provider = MetadataReaderProvider.FromMetadataImage(image);
            MetadataReader reader = provider.GetMetadataReader();
            status = ModuleMetadataStatus.Loaded;
            detail = null;
            return new ModuleMetadata(moduleBase, rva, blob, root!, provider, reader);
        }
        catch (BadImageFormatException ex)
        {
            // Defence in depth: our validation is structural, and the library can still
            // reject a table stream we deliberately did not parse.
            provider?.Dispose();
            status = ModuleMetadataStatus.MalformedMetadata;
            detail = ex.Message;
            return null;
        }
    }

    /// <summary>
    /// One read for the whole region (§7b.3), degrading to <see cref="ChunkSize"/> (64 KiB)
    /// chunks rather than failing outright if the single large read is rejected.
    /// </summary>
    private static bool TryReadBlock(IMemoryReader memory, ulong address, byte[] buffer)
    {
        if (memory.TryRead(address, buffer)) return true;

        for (int offset = 0; offset < buffer.Length; offset += ChunkSize)
        {
            int length = Math.Min(ChunkSize, buffer.Length - offset);
            if (!memory.TryRead(address + (ulong)offset, buffer.AsSpan(offset, length))) return false;
        }

        return true;
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _provider.Dispose();
    }
}

/// <summary>
/// Process-lifetime cache of <see cref="ModuleMetadata"/>, keyed by module base.
/// </summary>
/// <remarks>
/// §8.8 places "ECMA-335 blob + parsed tables" in the <b>Process</b> tier, alongside module
/// info and the cDAC descriptor: unlike managed addresses, a module base is stable for the
/// life of the target. Caching is not merely an optimisation — §12.4 (API fact 1) records
/// that repeated per-object name resolution is "the single biggest cost in a naive traversal".
/// <para>
/// Negative results are cached too: a native DLL will still be native next time, and the PE
/// walk that proves it costs several remote reads.
/// </para>
/// </remarks>
public sealed class ModuleMetadataCache : IDisposable
{
    private readonly IMemoryReader _memory;
    private readonly Dictionary<ulong, ModuleMetadata?> _byBase = [];
    private readonly Lock _gate = new();
    private bool _disposed;

    public ModuleMetadataCache(IMemoryReader memory)
    {
        ArgumentNullException.ThrowIfNull(memory);
        _memory = memory;
    }

    /// <summary>
    /// Metadata for the module at <paramref name="moduleBase"/>, loading it on first request.
    /// Returns <see langword="null"/> for a native module. The returned instance is owned by
    /// this cache and must not be disposed by the caller.
    /// </summary>
    public ModuleMetadata? GetOrLoad(ulong moduleBase)
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (_byBase.TryGetValue(moduleBase, out ModuleMetadata? cached)) return cached;
        }

        // Loaded outside the lock: a 5 MB remote copy should not serialise other modules.
        ModuleMetadata? loaded = ModuleMetadata.TryLoad(_memory, moduleBase);

        lock (_gate)
        {
            // Dispose can have run during the load above. Inserting now would leak the entry
            // into a dead cache AND hand the caller a live-looking object nobody will free.
            if (_disposed)
            {
                loaded?.Dispose();
                throw new ObjectDisposedException(nameof(ModuleMetadataCache));
            }

            if (_byBase.TryGetValue(moduleBase, out ModuleMetadata? raced))
            {
                loaded?.Dispose();
                return raced;
            }

            _byBase[moduleBase] = loaded;
            return loaded;
        }
    }

    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed) return;
            _disposed = true;
            foreach (ModuleMetadata? entry in _byBase.Values) entry?.Dispose();
            _byBase.Clear();
        }
    }
}
