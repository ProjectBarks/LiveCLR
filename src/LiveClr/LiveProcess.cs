namespace LiveClr;

using System.Diagnostics.CodeAnalysis;
using LiveClr.Cdac;
using LiveClr.Memory;
using LiveClr.Metadata;
using LiveClr.Runtime;
using LiveClr.Snapshots;

/// <summary>Knobs for <see cref="LiveProcess.Attach(int, LiveProcessOptions?)"/>.</summary>
public sealed class LiveProcessOptions
{
    /// <summary>Base name of the runtime image, without extension.</summary>
    public string CoreClrModuleName { get; init; } = "coreclr";

    /// <summary>Page-cache block size for <see cref="SnapshotMode.LiveValidated"/> snapshots.</summary>
    public int PageSize { get; init; } = PageCache.DefaultPageSize;

    /// <summary>
    /// Caller-supplied instance field offsets, consulted when the runtime route cannot answer.
    /// See <see cref="IClrFieldLayoutSource"/> and §5.5 for when that is.
    /// </summary>
    public IClrFieldLayoutSource? FieldLayout { get; init; }

    /// <summary>
    /// Caller-supplied static field slot addresses. There is no descriptor-only route to these
    /// on .NET 9 (see <see cref="IClrStaticRootSource"/>).
    /// </summary>
    public IClrStaticRootSource? StaticRoots { get; init; }

    /// <summary>
    /// Whether to derive the <c>FieldDesc</c> encoding at attach (§12.5's technique applied to
    /// the runtime). Costs a handful of reads once; disable it to rely purely on
    /// <see cref="FieldLayout"/>.
    /// </summary>
    public bool CalibrateFieldOffsets { get; init; } = true;
}

/// <summary>The target could not be prepared for reading. Carries the precise reason.</summary>
public sealed class ClrAttachException : Exception
{
    /// <summary>Create an attach failure with a diagnosable message.</summary>
    public ClrAttachException(string message) : base(message)
    {
    }

    /// <summary>Create an attach failure wrapping an underlying cause.</summary>
    public ClrAttachException(string message, Exception inner) : base(message, inner)
    {
    }
}

/// <summary>
/// An attached .NET process: modules, the parsed contract descriptor, the process-tier type
/// system, and the ability to open snapshots.
/// </summary>
/// <remarks>
/// <para>
/// <b>There is no semantic read API here, by design.</b> No <c>ReadObject(address)</c>, no
/// <c>Field(...)</c>. §8.8 makes that an invariant rather than a style choice: §7b.1 (managed
/// addresses move under a compacting GC) and §12.4e (a traversal can tear while every read
/// succeeds) both produce plausible wrong data rather than errors, and snapshot scoping is how
/// those two findings become type errors instead of documentation. Everything semantic lives on
/// <see cref="ISnapshot"/>.
/// </para>
/// <para>
/// <b>What IS held here is the process tier</b> (§8.8): module info, the cDAC descriptor, the
/// ECMA-335 blobs, and the <c>MethodTable → ClrType</c> map. All of it keyed by addresses that
/// §7b.1 measured stable — loader heaps and mapped images, never the managed heap.
/// </para>
/// </remarks>
public sealed class LiveProcess : ILiveProcess
{
    private readonly bool _ownsMemory;
    private readonly LiveProcessOptions _options;
    private bool _disposed;

    private LiveProcess(
        int processId,
        IMemoryReader memory,
        bool ownsMemory,
        ModuleTable modules,
        ModuleInfo coreClr,
        RuntimeContractTarget target,
        ClrLayouts layouts,
        ModuleMetadataCache metadata,
        ClrTypeSystem typeSystem,
        FieldDescCalibration calibration,
        LiveProcessOptions options)
    {
        ProcessId = processId;
        Memory = memory;
        _ownsMemory = ownsMemory;
        Modules = modules;
        CoreClr = coreClr;
        Runtime = target;
        Layouts = layouts;
        MetadataCache = metadata;
        TypeSystem = typeSystem;
        FieldDescCalibration = calibration;
        _options = options;
    }

    /// <inheritdoc/>
    public int ProcessId { get; }

    /// <inheritdoc/>
    /// <remarks>
    /// The PROCESS-tier reader. Snapshots wrap it; nothing above the snapshot layer should read
    /// through it directly, because reads made here are not part of any consistent image (§4.7).
    /// </remarks>
    public IMemoryReader Memory { get; }

    /// <inheritdoc/>
    public IRuntimeContractTarget Runtime { get; }

    /// <summary>Loaded modules of the target.</summary>
    public ModuleTable Modules { get; }

    /// <summary>The runtime image the descriptor was bootstrapped from.</summary>
    public ModuleInfo CoreClr { get; }

    /// <summary>CLR struct offsets resolved from the descriptor (§5.2).</summary>
    public ClrLayouts Layouts { get; }

    /// <summary>Process-tier ECMA-335 metadata cache (§7b.3).</summary>
    public ModuleMetadataCache MetadataCache { get; }

    /// <summary>Process-tier <c>MethodTable → ClrType</c> map.</summary>
    public ClrTypeSystem TypeSystem { get; }

    /// <summary>
    /// The <c>FieldDesc</c> encoding derivation performed at attach. Inspect
    /// <see cref="Runtime.FieldDescCalibration.Detail"/> at startup: whether instance fields
    /// are readable at all on a given runtime is decided here, and it is far better as a
    /// startup diagnostic than as a null in the middle of a walk (§7b.2 makes the same argument
    /// for the Godot table).
    /// </summary>
    public FieldDescCalibration FieldDescCalibration { get; }

    /// <inheritdoc/>
    public IReadOnlyCollection<string> ModuleNames => Modules.Names;

    /// <summary>
    /// Attach to a running .NET 9+ process by id.
    /// </summary>
    /// <exception cref="ClrAttachException">
    /// The process could not be opened, does not host CoreCLR, does not publish a contract
    /// descriptor, or publishes one too sparse to walk. The message names which.
    /// </exception>
    public static LiveProcess Attach(int processId, LiveProcessOptions? options = null)
    {
        options ??= new LiveProcessOptions();

        WindowsProcessMemory memory;
        try
        {
            memory = WindowsProcessMemory.Open(processId);
        }
        catch (Exception e)
        {
            throw new ClrAttachException($"could not open pid {processId} for reading: {e.Message}", e);
        }

        try
        {
            ModuleTable modules = memory.Modules;
            if (!modules.TryGet(options.CoreClrModuleName, out ModuleInfo? coreClr))
            {
                throw new ClrAttachException(
                    $"pid {processId} has no '{options.CoreClrModuleName}' module loaded; it is not a CoreCLR process.");
            }

            return Create(processId, memory, ownsMemory: true, modules, coreClr, options);
        }
        catch
        {
            memory.Dispose();
            throw;
        }
    }

    /// <summary>Non-throwing form of <see cref="Attach(int, LiveProcessOptions?)"/>.</summary>
    public static bool TryAttach(
        int processId,
        [NotNullWhen(true)] out LiveProcess? process,
        out string? failure,
        LiveProcessOptions? options = null)
    {
        try
        {
            process = Attach(processId, options);
            failure = null;
            return true;
        }
        catch (ClrAttachException e)
        {
            process = null;
            failure = e.Message;
            return false;
        }
    }

    /// <summary>
    /// Attach over an arbitrary reader — a recorded fixture (§8.8) or a capture taken by other
    /// means — instead of a live handle.
    /// </summary>
    /// <remarks>
    /// This is what makes <c>LiveClr.Tests</c> runnable in CI at all: §12's every result
    /// required a live game, and §8.8's first "addition" is a recorded-fixture provider so the
    /// stack can be exercised without one.
    /// </remarks>
    /// <param name="processId">Reported as <see cref="ProcessId"/>; 0 for a fixture.</param>
    /// <param name="memory">Reader for the simulated or captured address space.</param>
    /// <param name="ownsMemory">Whether disposing this process disposes the reader.</param>
    /// <param name="modules">Module table to report.</param>
    /// <param name="coreClr">The runtime image within <paramref name="modules"/>.</param>
    /// <param name="options">Optional configuration.</param>
    public static LiveProcess Create(
        int processId,
        IMemoryReader memory,
        bool ownsMemory,
        ModuleTable modules,
        ModuleInfo coreClr,
        LiveProcessOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(memory);
        ArgumentNullException.ThrowIfNull(modules);
        ArgumentNullException.ThrowIfNull(coreClr);
        options ??= new LiveProcessOptions();

        if (!RuntimeContractTarget.TryCreate(memory, coreClr.BaseAddress, out RuntimeContractTarget? target))
        {
            throw new ClrAttachException(
                $"'{coreClr.FileName}' at 0x{coreClr.BaseAddress:X} does not export a readable " +
                "DotNetRuntimeContractDescriptor; the target predates .NET 9 or its runtime could not be read.");
        }

        if (!ClrLayouts.TryCreate(target, out ClrLayouts? layouts, out string? missing))
        {
            throw new ClrAttachException(
                $"the runtime's contract descriptor (version {target.DescriptorVersion}) does not publish: {missing}. " +
                "Analysis doc §5.5: descriptor coverage is a goal for readers and contracts, not a guarantee " +
                "that every structure a consumer wants is present.");
        }

        var metadata = new ModuleMetadataCache(memory);

        FieldDescCalibration calibration = options.CalibrateFieldOffsets
            ? FieldDescCalibration.Attempt(memory, target, layouts, metadata)
            : FieldDescCalibration.NotAttempted;

        // Runtime first, caller-supplied second: a runtime that can answer is always believed
        // over a hand-maintained table, so a stale profile is corrected rather than trusted
        // (the §7b.2 argument, applied to CLR field offsets).
        IClrFieldLayoutSource fieldLayout = options.FieldLayout is null
            ? new RuntimeFieldLayoutSource(layouts, calibration)
            : new CompositeFieldLayoutSource(new RuntimeFieldLayoutSource(layouts, calibration), options.FieldLayout);

        var typeSystem = new ClrTypeSystem(target, layouts, metadata, fieldLayout);
        typeSystem.Seed(memory);

        return new LiveProcess(
            processId, memory, ownsMemory, modules, coreClr, target, layouts, metadata, typeSystem, calibration, options);
    }

    /// <summary>
    /// Register the application's own managed module by its runtime <c>Module*</c>.
    /// </summary>
    /// <remarks>
    /// Needed because the .NET 9 descriptor omits <c>AppDomain</c>, <c>Assembly</c> and
    /// <c>ArrayListBase</c>, so the assembly list cannot be walked from the root (§5.5). Either
    /// seed the pointer here, or resolve one object with
    /// <see cref="ISnapshot.Object(ulong)"/> — its module registers itself, which is §5.5's
    /// "start from any known managed object and go upward".
    /// </remarks>
    public ClrModuleInfo? RegisterManagedModule(ulong modulePointer)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return TypeSystem.RegisterModule(Memory, modulePointer);
    }

    /// <inheritdoc/>
    /// <exception cref="NotSupportedException">
    /// <see cref="SnapshotMode.ProcessSnapshot"/> was requested for a target that cannot be
    /// VA-cloned — wrong bitness, protected process, or a non-live reader such as a fixture.
    /// </exception>
    public ISnapshot BeginSnapshot(SnapshotMode mode = SnapshotMode.LiveValidated)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        return mode switch
        {
            SnapshotMode.LiveValidated => new LiveSnapshot(
                mode,
                new PageCache(Memory, _options.PageSize),
                ownsReader: true,
                TypeSystem,
                StaticRoots),

            SnapshotMode.ProcessSnapshot => BeginProcessSnapshot(),

            _ => throw new ArgumentOutOfRangeException(nameof(mode), mode, "unknown snapshot mode"),
        };
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        MetadataCache.Dispose();
        if (_ownsMemory) Memory.Dispose();
    }

    private IClrStaticRootSource StaticRoots => _options.StaticRoots ?? EmptyStaticRootSource.Instance;

    /// <summary>
    /// §8.8's correctness oracle: a PSS VA clone gives a coherent image to diff a
    /// <see cref="SnapshotMode.LiveValidated"/> traversal against, which is the only way to
    /// catch §12.4e's tearing class in a test. §8.8 also asks for it to be benchmarked as a
    /// product mode — it is copy-on-write, and if it is cheap enough at 4 Hz it eliminates the
    /// bug class rather than detecting it.
    /// </summary>
    private LiveSnapshot BeginProcessSnapshot()
    {
        if (ProcessId <= 0)
        {
            throw new NotSupportedException(
                "ProcessSnapshot mode needs a live process id; this LiveProcess reads a fixture or a capture.");
        }

        PssSnapshotMemory clone = PssSnapshotMemory.Capture(ProcessId);
        return new LiveSnapshot(SnapshotMode.ProcessSnapshot, clone, ownsReader: true, TypeSystem, StaticRoots);
    }
}
