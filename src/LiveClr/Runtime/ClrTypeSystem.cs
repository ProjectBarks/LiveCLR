namespace LiveClr.Runtime;

using System.Diagnostics.CodeAnalysis;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using LiveClr.Cdac;
using LiveClr.Memory;
using LiveClr.Metadata;

/// <summary>
/// One managed module in the target: its runtime <c>Module*</c>, its mapped image, its
/// metadata, and the two directions of the token ⇄ method-table mapping.
/// </summary>
/// <remarks>
/// Lifetime: PROCESS tier (§8.8). Module pointers live in loader heaps and, unlike managed
/// object addresses (§7b.1), do not move.
/// </remarks>
public sealed class ClrModuleInfo
{
    private readonly ClrLayouts _layouts;
    private readonly Lock _mapGate = new();
    private Dictionary<ulong, int>? _methodTableToRid;
    private Dictionary<int, ulong>? _ridToMethodTable;

    internal ClrModuleInfo(ClrLayouts layouts, ulong modulePointer, ulong moduleBase, ModuleMetadata metadata)
    {
        _layouts = layouts;
        ModulePointer = modulePointer;
        ModuleBase = moduleBase;
        Metadata = metadata;
    }

    /// <summary>The runtime's <c>Module*</c>.</summary>
    public ulong ModulePointer { get; }

    /// <summary><c>Module.Base</c> (§5.2) — the mapped PE image.</summary>
    public ulong ModuleBase { get; }

    /// <summary>Parsed ECMA-335 metadata for this module.</summary>
    public ModuleMetadata Metadata { get; }

    /// <summary>Simple name from the metadata assembly/module row, for diagnostics.</summary>
    public string Name => Metadata.Reader.IsAssembly
        ? Metadata.Reader.GetString(Metadata.Reader.GetAssemblyDefinition().Name)
        : Metadata.Reader.GetString(Metadata.Reader.GetModuleDefinition().Name);

    /// <summary>
    /// Method table for a TypeDef rid, from <c>Module.TypeDefToMethodTableMap</c> (§5.2).
    /// </summary>
    public bool TryGetMethodTable(IMemoryReader memory, int rid, out ulong methodTable)
    {
        EnsureTypeMap(memory);
        return _ridToMethodTable!.TryGetValue(rid, out methodTable);
    }

    /// <summary>The TypeDef rid a method table was created from, if this module defines it.</summary>
    public bool TryGetTypeDefRid(IMemoryReader memory, ulong methodTable, out int rid)
    {
        EnsureTypeMap(memory);
        return _methodTableToRid!.TryGetValue(methodTable, out rid);
    }

    /// <summary>Number of TypeDef rows whose method table has been loaded and mapped.</summary>
    public int MappedTypeCount => _ridToMethodTable?.Count ?? 0;

    /// <summary>
    /// Chunks of the TypeDef map that could not be read, and whose rids are therefore missing.
    /// </summary>
    /// <remarks>
    /// Non-zero means part of the map was unreadable — most plausibly because the map is
    /// segmented and this walk ran past the first segment into unmapped memory (§5.4: neither
    /// <c>Count</c> nor <c>Next</c> is published, so there is no way to stop at the boundary).
    /// The types in the readable chunks still resolve; this is the signal that some do not,
    /// which is strictly better than the whole module silently having no types.
    /// </remarks>
    public int TypeMapGaps { get; private set; }

    /// <summary>
    /// Builds both directions of the TypeDef ⇄ MethodTable map.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The map is the only route from a method table back to a metadata token: the .NET 9
    /// descriptor publishes <c>Module.TypeDefToMethodTableMap</c> but no token field on
    /// <c>MethodTable</c>, so the mapping is inverted here rather than read directly.
    /// </para>
    /// <para>
    /// <b>The walk is bounded by the metadata row count, NOT by the map's own extent.</b> §5.4
    /// describes these maps as segmented, and the descriptor publishes neither <c>Count</c> nor
    /// <c>Next</c>; there is consequently no way to know where the first segment ends. For a
    /// segmented map this walk therefore reads past it, into whatever the runtime allocated
    /// next. Two things stop that becoming wrong data: an entry only enters the map if it
    /// survives <see cref="ClrTypeSystem.IsMethodTable"/>'s round trip when it is later
    /// resolved, and unreadable chunks are skipped rather than believed.
    /// </para>
    /// <para>
    /// <b>Read in chunks, and degrade.</b> A single bulk read is all-or-nothing, so one
    /// unmapped page anywhere in the range would empty the ENTIRE map — every type in the
    /// module would then silently fail to resolve, which is the §12.4b "reports every
    /// collection as empty" failure mode wearing a different hat. Chunking confines the damage
    /// to the pages that are actually missing and records the loss in
    /// <see cref="TypeMapGaps"/>. <c>ModuleMetadata</c> makes the same trade for the same
    /// reason (§7b.3).
    /// </para>
    /// </remarks>
    private void EnsureTypeMap(IMemoryReader memory)
    {
        if (_ridToMethodTable is not null) return;

        // Process tier is shared across snapshots and potentially across threads; publishing
        // one map without the other would hand a caller a half-built index.
        lock (_mapGate)
        {
            if (_ridToMethodTable is null) BuildTypeMap(memory);
        }
    }

    /// <summary>Page-sized: one unreadable page costs one chunk, not the whole table.</summary>
    private const int MapChunkBytes = 4096;

    private void BuildTypeMap(IMemoryReader memory)
    {
        var byRid = new Dictionary<int, ulong>();
        var byMethodTable = new Dictionary<ulong, int>();
        int gaps = 0;

        int typeCount = Metadata.Reader.TypeDefinitions.Count;
        ulong mapAddress = ModulePointer + (ulong)_layouts.ModuleTypeDefMapOffset;
        int stride = _layouts.PointerSize;

        if (memory.TryReadPointer(mapAddress + (ulong)_layouts.LookupMapTableDataOffset, out ulong table) && table != 0)
        {
            var raw = new byte[Math.Max(MapChunkBytes / stride, 1) * stride];

            for (int first = 1; first <= typeCount;)
            {
                ulong address = table + ((ulong)first * (ulong)stride);

                // Clipped to a page so one unmapped page costs exactly the rids on it.
                int count = ClrLayouts.EntriesWithinPage(address, stride, typeCount - first + 1);
                Span<byte> block = raw.AsSpan(0, count * stride);

                if (!memory.TryRead(address, block))
                {
                    gaps++;
                    first += count;
                    continue;
                }

                for (int i = 0; i < count; i++)
                {
                    ulong entry = stride == 8
                        ? BitConverter.ToUInt64(raw, i * 8)
                        : BitConverter.ToUInt32(raw, i * 4);

                    // Low bits carry lookup-map flags (§5.4). Method tables are at least
                    // 8-byte aligned, so clearing three bits cannot damage a real pointer.
                    ulong methodTable = entry & ~7UL;
                    if (methodTable == 0) continue;

                    int rid = first + i;
                    byRid[rid] = methodTable;
                    byMethodTable.TryAdd(methodTable, rid);
                }

                first += count;
            }
        }

        TypeMapGaps = gaps;
        _methodTableToRid = byMethodTable;
        _ridToMethodTable = byRid;
    }
}

/// <summary>
/// A type as the RUNTIME describes it, joined with what metadata says about its name and
/// fields.
/// </summary>
/// <remarks>
/// Lifetime: PROCESS tier (§8.8). §7b.1 measured method-table addresses stable across a
/// session — they live in loader heaps and the GC does not move them — which is precisely
/// what makes the §12.4d name route cheap enough to use per object.
/// </remarks>
public sealed class ClrTypeInfo
{
    private readonly ClrTypeSystem _system;

    // ExecutionAndPublication, matching ModuleMetadata's choice for the same reason: this is a
    // PROCESS-tier object shared across snapshots and threads (§8.8), and a bare ??= would let
    // two callers each build a copy and publish a half-written dictionary between them.
    private readonly Lazy<Dictionary<string, ClrFieldShape>> _shapes;
    private readonly Lazy<string[]> _fieldNames;

    internal ClrTypeInfo(
        ClrTypeSystem system,
        ulong methodTable,
        string name,
        ClrModuleInfo? module,
        TypeDefinitionHandle typeDef,
        ulong parentMethodTable,
        uint baseSize,
        int componentSize,
        ClrElementType elementType,
        ulong elementMethodTable,
        System.Reflection.TypeAttributes? typeAttributes)
    {
        _system = system;
        MethodTable = methodTable;
        Name = name;
        Module = module;
        TypeDefinition = typeDef;
        ParentMethodTable = parentMethodTable;
        BaseSize = baseSize;
        ComponentSize = componentSize;
        ElementType = elementType;
        ElementMethodTable = elementMethodTable;
        TypeAttributes = typeAttributes;

        _shapes = new Lazy<Dictionary<string, ClrFieldShape>>(BuildShapes, LazyThreadSafetyMode.ExecutionAndPublication);
        _fieldNames = new Lazy<string[]>(BuildFieldNames, LazyThreadSafetyMode.ExecutionAndPublication);
    }

    /// <summary>Address of the method table this type was read from.</summary>
    public ulong MethodTable { get; }

    /// <summary>
    /// Full metadata name, or a <c>&lt;mt:0x…&gt;</c> placeholder when the type has no TypeDef
    /// row — arrays and other runtime-constructed types genuinely do not have one, and inventing
    /// a name for them would be a guess.
    /// </summary>
    public string Name { get; }

    /// <summary>True when <see cref="Name"/> came from metadata rather than being a placeholder.</summary>
    public bool HasMetadataName => !TypeDefinition.IsNil;

    /// <summary>The module that defines this type, when it could be identified.</summary>
    public ClrModuleInfo? Module { get; }

    /// <summary>The TypeDef this method table was built from; nil for runtime-constructed types.</summary>
    public TypeDefinitionHandle TypeDefinition { get; }

    /// <summary><c>MethodTable.ParentMethodTable</c> (§5.2: 16). Zero for <c>System.Object</c>.</summary>
    public ulong ParentMethodTable { get; }

    /// <summary><c>MethodTable.BaseSize</c> (§5.2: 4). Bounds every valid instance field offset.</summary>
    public uint BaseSize { get; }

    /// <summary>
    /// Element stride for arrays and strings, or 0 for ordinary objects. Derived from
    /// <c>MethodTable.MTFlags</c> and verified against published globals; see
    /// <see cref="ClrTypeSystem.ComponentSizeIsTrusted"/>.
    /// </summary>
    public int ComponentSize { get; }

    /// <summary><c>EEClass.InternalCorElementType</c> (§5.2: 64).</summary>
    /// <remarks>
    /// <b>This is what the runtime stores, which is not the same as what the ECMA-335 signature
    /// for the type would say.</b> Measured on .NET 9 (§17): across 12,283 loaded method tables
    /// in a live process, <c>ELEMENT_TYPE_STRING</c> appears exactly zero times —
    /// <c>System.String</c>'s own <c>EEClass</c> reports <c>ELEMENT_TYPE_CLASS</c> (0x12). Arrays
    /// do report <c>SZARRAY</c>/<c>ARRAY</c>, so <see cref="IsArray"/> can be read from here;
    /// <see cref="IsString"/> deliberately cannot.
    /// </remarks>
    public ClrElementType ElementType { get; }

    /// <summary>Method table of an array's element type, when it could be identified and validated.</summary>
    public ulong ElementMethodTable { get; }

    /// <summary>
    /// <c>EEClass.CorTypeAttr</c> (§5.2: 56) — the ECMA-335 <c>TypeAttributes</c> the RUNTIME
    /// holds — or null when the descriptor does not publish the field or it could not be read.
    /// </summary>
    /// <remarks>
    /// Null is an ordinary outcome, not an error: this is the one descriptor entry
    /// <see cref="ClrLayouts"/> treats as optional (§5.5), and nothing else in this layer reads
    /// it. Worth having because it is the only source of visibility/abstract/sealed/interface for
    /// a type with no TypeDef row — <see cref="HasMetadataName"/> false — where metadata cannot
    /// be consulted.
    /// </remarks>
    public System.Reflection.TypeAttributes? TypeAttributes { get; }

    /// <summary>True for <c>SZARRAY</c> and multidimensional arrays.</summary>
    /// <remarks>
    /// Unlike <see cref="IsString"/> this one CAN come from the element type, and that is a
    /// measurement rather than an assumption: the published <c>ObjectArrayMethodTable</c> reports
    /// <c>SZARRAY</c> live, and every array reached in a live walk did too (§17).
    /// </remarks>
    public bool IsArray => ElementType is ClrElementType.SzArray or ClrElementType.Array;

    /// <summary>True for <c>System.String</c>.</summary>
    /// <remarks>
    /// <para>
    /// <b>Not <c>ElementType == String</c>, which is dead on every real runtime.</b> That was the
    /// original spelling and it made <see cref="ClrValue.AsString"/> return null for every string
    /// in a live process: CoreCLR does not put the string marker in <c>EEClass</c>'s norm type
    /// (§17 — 0 of 12,283 live method tables report <c>ELEMENT_TYPE_STRING</c>, and
    /// <c>System.String</c>'s own reports <c>ELEMENT_TYPE_CLASS</c>).
    /// </para>
    /// <para>
    /// Identity comes from <see cref="ClrTypeSystem.StringMethodTable"/> instead — the
    /// <c>StringMethodTable</c> global the descriptor publishes (§5.3), which is not a decoded
    /// property of a type but the runtime naming the one method table that IS
    /// <c>System.String</c>. See <see cref="ClrTypeSystem.IsStringType"/> for what happens on a
    /// runtime that does not publish it.
    /// </para>
    /// </remarks>
    public bool IsString => _system.IsStringType(this);

    /// <summary>
    /// True for <c>System.Collections.Generic.List&lt;T&gt;</c>.
    /// </summary>
    /// <remarks>
    /// Matched on the name prefix explicitly. §12.4b records the probe bug this avoids: a
    /// <c>List`1</c> DOES have a class name, so "has a class name ⇒ treat as object" reports
    /// every collection as empty, silently.
    /// </remarks>
    public bool IsList => Name.StartsWith("System.Collections.Generic.List`1", StringComparison.Ordinal);

    /// <summary>The base type, resolved through the runtime chain rather than through metadata.</summary>
    public ClrTypeInfo? Parent(IMemoryReader memory) =>
        ParentMethodTable == 0 ? null : _system.TryGetType(memory, ParentMethodTable, out ClrTypeInfo? parent) ? parent : null;

    /// <summary>This type and every ancestor, base last.</summary>
    public IEnumerable<ClrTypeInfo> WithAncestors(IMemoryReader memory)
    {
        ClrTypeInfo? current = this;
        var seen = new HashSet<ulong>();

        while (current is not null && seen.Add(current.MethodTable))
        {
            yield return current;
            current = current.Parent(memory);
        }
    }

    /// <summary>Fields DECLARED on this type (not inherited), from metadata.</summary>
    public IReadOnlyList<MetadataField> DeclaredFields =>
        Module is null || TypeDefinition.IsNil ? [] : Module.Metadata.Types.GetFields(TypeDefinition);

    /// <summary>Declared field names.</summary>
    public IReadOnlyList<string> DeclaredFieldNames => _fieldNames.Value;

    /// <summary>What a declared field's signature says about its slot.</summary>
    public ClrFieldShape GetFieldShape(string fieldName) =>
        _shapes.Value.TryGetValue(fieldName, out ClrFieldShape shape) ? shape : ClrFieldShape.Unknown;

    /// <summary>Find a declared field's metadata row by name.</summary>
    public bool TryGetDeclaredField(string fieldName, out MetadataField field)
    {
        foreach (MetadataField candidate in DeclaredFields)
        {
            if (string.Equals(candidate.Name, fieldName, StringComparison.Ordinal))
            {
                field = candidate;
                return true;
            }
        }

        field = default;
        return false;
    }

    /// <inheritdoc/>
    public override string ToString() => $"{Name} @ MT 0x{MethodTable:X}";

    private string[] BuildFieldNames()
    {
        IReadOnlyList<MetadataField> declared = DeclaredFields;
        var names = new string[declared.Count];
        for (int i = 0; i < declared.Count; i++) names[i] = declared[i].Name;
        return names;
    }

    private Dictionary<string, ClrFieldShape> BuildShapes()
    {
        var shapes = new Dictionary<string, ClrFieldShape>(StringComparer.Ordinal);
        if (Module is null || TypeDefinition.IsNil) return shapes;

        MetadataReader reader = Module.Metadata.Reader;
        foreach (FieldDefinitionHandle handle in reader.GetTypeDefinition(TypeDefinition).GetFields())
        {
            FieldDefinition field = reader.GetFieldDefinition(handle);
            string name = reader.GetString(field.Name);

            // A malformed signature is a per-field problem, not a per-type one (§5.5).
            try
            {
                shapes[name] = field.DecodeSignature(FieldShapeProvider.Instance, null);
            }
            catch (BadImageFormatException)
            {
                shapes[name] = ClrFieldShape.Unknown;
            }
        }

        return shapes;
    }
}

/// <summary>
/// The process-tier map from live method tables to described types, and from names back to
/// method tables.
/// </summary>
/// <remarks>
/// <para>
/// This is §12.4d's route, generalised: object → <c>MethodTable</c> (masking the low bits with
/// <c>ObjectToMethodTableUnmask</c>) → <c>MethodTable.Module</c> → <c>Module.Base</c> →
/// ECMA-335 → names. Field OFFSETS deliberately do not come from here; metadata does not know
/// them and this class does not pretend otherwise (see <see cref="IClrFieldLayoutSource"/>).
/// </para>
/// <para>
/// <b>Caching is a lifetime statement, not an optimisation.</b> §8.8 puts
/// <c>MethodTable → ClrType</c> in the Process tier and managed addresses in the Snapshot
/// tier. Everything cached here is keyed by a method table or a module pointer — both loader
/// heap, both measured stable in §7b.1 — and nothing keyed by an object address is cached at
/// all.
/// </para>
/// </remarks>
public sealed class ClrTypeSystem
{
    private readonly IRuntimeContractTarget _target;
    private readonly Dictionary<ulong, ClrTypeInfo?> _types = [];
    private readonly Dictionary<ulong, ClrModuleInfo?> _modules = [];
    private readonly Dictionary<ulong, MethodTableFacts?> _validMethodTables = [];
    private readonly Lock _gate = new();
    private bool _seeded;

    /// <summary>
    /// Published method-table globals (§5.3). Each one names a type in CoreLib, so any of them
    /// is enough to register CoreLib's module without walking the assembly list — the route
    /// §5.5 prescribes when the descriptor omits <c>AppDomain</c>.
    /// </summary>
    private static readonly string[] SeedGlobals =
    [
        "ObjectMethodTable",
        "StringMethodTable",
        "ExceptionMethodTable",
        "ObjectArrayMethodTable",
    ];

    internal ClrTypeSystem(
        IRuntimeContractTarget target,
        ClrLayouts layouts,
        ModuleMetadataCache metadata,
        IClrFieldLayoutSource fieldLayout,
        RuntimeStaticFieldSource staticFields)
    {
        _target = target;
        Layouts = layouts;
        MetadataCache = metadata;
        FieldLayout = fieldLayout;
        StaticFields = staticFields;
    }

    /// <summary>Descriptor-resolved CLR offsets.</summary>
    public ClrLayouts Layouts { get; }

    /// <summary>Process-tier metadata cache.</summary>
    public ModuleMetadataCache MetadataCache { get; }

    /// <summary>How named instance fields become offsets.</summary>
    public IClrFieldLayoutSource FieldLayout { get; }

    /// <summary>
    /// How named STATIC fields become addresses, straight out of the target (§14).
    /// </summary>
    /// <remarks>
    /// Refuses on a runtime whose statics chain could not be derived, which is when a
    /// caller-supplied <see cref="IClrStaticRootSource"/> takes over — the same "runtime first,
    /// caller-supplied second" order <see cref="CompositeFieldLayoutSource"/> uses, and for the
    /// same reason: a runtime that can answer is always believed over a hand-maintained table.
    /// </remarks>
    public RuntimeStaticFieldSource StaticFields { get; }

    /// <summary>
    /// Whether <see cref="ClrTypeInfo.ComponentSize"/> can be believed.
    /// </summary>
    /// <remarks>
    /// The array/string element stride lives in <c>MethodTable.MTFlags</c>, which the
    /// descriptor publishes as a field but whose bit meanings it does not publish. Rather than
    /// assume the encoding, it is CHECKED against two independently published globals: the
    /// method table for <c>System.String</c> must report a stride of 2, and the one for
    /// <c>object[]</c> must report a pointer. If either disagrees, this stays false and arrays
    /// degrade to unavailable instead of indexing with a wrong stride.
    /// </remarks>
    public bool ComponentSizeIsTrusted { get; private set; }

    /// <summary>
    /// The method table that IS <c>System.String</c>, from the descriptor's
    /// <c>StringMethodTable</c> global (§5.3), or 0 when the runtime does not publish one.
    /// </summary>
    /// <remarks>
    /// Resolved in <see cref="Seed"/> and validated as a method table before it is believed, so a
    /// stale or garbage global cannot become the identity oracle. This is a published FACT about
    /// the target rather than a property decoded out of a type, which is what makes it a better
    /// answer to "is this a string" than anything in <c>MTFlags</c> or <c>EEClass</c>.
    /// </remarks>
    public ulong StringMethodTable { get; private set; }

    /// <summary>Whether <see cref="StringMethodTable"/> came from the descriptor.</summary>
    /// <remarks>
    /// False means <see cref="IsStringType"/> is running on corroborated evidence rather than on
    /// a published fact, which a diagnostic should be able to say out loud.
    /// </remarks>
    public bool StringIdentityIsPublished => StringMethodTable != 0;

    /// <summary>Modules discovered so far, by <c>Module*</c>.</summary>
    public IReadOnlyCollection<ClrModuleInfo> Modules
    {
        get
        {
            lock (_gate) return _modules.Values.Where(m => m is not null).Select(m => m!).ToArray();
        }
    }

    /// <summary>
    /// Registers a managed module by its runtime <c>Module*</c>, so
    /// <see cref="TryFindType"/> can search it.
    /// </summary>
    /// <remarks>
    /// §5.5's gap in its narrowest form. The descriptor does not publish <c>AppDomain</c>,
    /// <c>Assembly</c> or <c>ArrayListBase</c>, so the assembly list cannot be enumerated from
    /// the root and there is no descriptor-only way to discover the game's own module. §5.5
    /// names the two answers: seed it from ClrMD once at connect, or start from any known
    /// managed object and go upward. Both land here — the second happens automatically, since
    /// resolving any object registers its module.
    /// </remarks>
    public ClrModuleInfo? RegisterModule(IMemoryReader memory, ulong modulePointer)
    {
        ArgumentNullException.ThrowIfNull(memory);
        if (modulePointer == 0) return null;

        lock (_gate)
        {
            if (_modules.TryGetValue(modulePointer, out ClrModuleInfo? cached)) return cached;
        }

        ClrModuleInfo? module = null;
        if (memory.TryReadPointer(modulePointer + (ulong)Layouts.ModuleBaseOffset, out ulong moduleBase) && moduleBase != 0)
        {
            ModuleMetadata? metadata = MetadataCache.GetOrLoad(moduleBase);
            if (metadata is not null) module = new ClrModuleInfo(Layouts, modulePointer, moduleBase, metadata);
        }

        lock (_gate)
        {
            if (_modules.TryGetValue(modulePointer, out ClrModuleInfo? raced)) return raced;
            _modules[modulePointer] = module;
            return module;
        }
    }

    /// <summary>
    /// Seeds the module registry from the method tables the descriptor publishes as globals,
    /// and checks the component-size encoding while it is there.
    /// </summary>
    public void Seed(IMemoryReader memory)
    {
        ArgumentNullException.ThrowIfNull(memory);

        lock (_gate)
        {
            if (_seeded) return;
            _seeded = true;
        }

        foreach (string global in SeedGlobals)
        {
            if (!_target.TryGetGlobalPointer(global, out ulong address)) continue;
            if (!memory.TryReadPointer(address, out ulong methodTable) || methodTable == 0) continue;
            if (!memory.TryReadPointer(methodTable + (ulong)Layouts.MethodTableModuleOffset, out ulong modulePointer)) continue;

            RegisterModule(memory, modulePointer);
        }

        ComponentSizeIsTrusted =
            ComponentSizeAgrees(memory, "StringMethodTable", 2) &&
            ComponentSizeAgrees(memory, "ObjectArrayMethodTable", Layouts.PointerSize);

        // String identity, taken from the runtime naming its own String method table rather than
        // decoded out of a flag word (§17). Validated as a method table first: a global that does
        // not round-trip is not evidence of anything.
        if (_target.TryGetGlobalPointer("StringMethodTable", out ulong stringSlot) &&
            memory.TryReadPointer(stringSlot, out ulong stringMethodTable) &&
            stringMethodTable != 0 &&
            IsMethodTable(memory, stringMethodTable))
        {
            StringMethodTable = stringMethodTable;
        }
    }

    /// <summary>
    /// Whether a type is <c>System.String</c>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Preferred route: the published global.</b> <see cref="StringMethodTable"/> is the
    /// runtime pointing at the one method table that is <c>System.String</c>, so identity is a
    /// pointer comparison against ground truth rather than an inference from a decoded flag.
    /// </para>
    /// <para>
    /// <b>Fallback, when the runtime publishes no such global: two independent signals must
    /// agree.</b> ECMA-335 metadata must name the type <c>System.String</c> — that name is
    /// resolved through <c>Module.TypeDefToMethodTableMap</c> and the mapped image, touching no
    /// runtime flags at all — AND <c>MTFlags</c> must report a component size of 2, which is the
    /// shape CoreCLR's own <c>MethodTable::IsString</c> tests (<c>HasComponentSize</c> and not an
    /// array and stride 2). Measured live, exactly one of 12,283 method tables satisfies each of
    /// those, and it is the same one both times (§17). Neither signal alone is used: a name can
    /// be declared by any assembly, and a stride of 2 on a non-array is a shape rather than an
    /// identity.
    /// </para>
    /// </remarks>
    internal bool IsStringType(ClrTypeInfo type)
    {
        ArgumentNullException.ThrowIfNull(type);

        if (StringMethodTable != 0) return type.MethodTable == StringMethodTable;

        return type.ComponentSize == 2
            && !type.IsArray
            && string.Equals(type.Name, "System.String", StringComparison.Ordinal);
    }

    /// <summary>
    /// Describe the type behind a method table.
    /// </summary>
    /// <remarks>
    /// Returns false for anything that does not validate as a method table. That check is
    /// load-bearing well beyond type naming: it is what lets a pointer-sized slot of unknown
    /// provenance be followed safely, because a slot that does not point at a real object
    /// fails here rather than producing a convincing-looking object (§12.4e).
    /// </remarks>
    public bool TryGetType(IMemoryReader memory, ulong methodTable, [NotNullWhen(true)] out ClrTypeInfo? type)
    {
        ArgumentNullException.ThrowIfNull(memory);
        type = null;
        if (methodTable == 0) return false;

        lock (_gate)
        {
            if (_types.TryGetValue(methodTable, out ClrTypeInfo? cached))
            {
                type = cached;
                return type is not null;
            }
        }

        ClrTypeInfo? built = Build(memory, methodTable);

        // Null from Build means one of two different things and they cache differently. "Not a
        // method table" is permanent — loader-heap structures do not change under us (§7b.1) —
        // so it is worth remembering. A read that FAILED is transient, and caching that verdict
        // for the process lifetime would make one unlucky read hide the type forever: the same
        // §8.8 lifetime mistake as caching a half-read one, just in mirror image.
        if (built is not null || !IsMethodTable(memory, methodTable))
        {
            lock (_gate) _types[methodTable] = built;
        }

        type = built;
        return type is not null;
    }

    /// <summary>Describe the type of the object at <paramref name="objectAddress"/>.</summary>
    public bool TryGetTypeOfObject(IMemoryReader memory, ulong objectAddress, [NotNullWhen(true)] out ClrTypeInfo? type)
    {
        type = null;
        return Layouts.TryReadMethodTableOf(memory, objectAddress, out ulong methodTable)
            && TryGetType(memory, methodTable, out type);
    }

    /// <summary>
    /// Find a type by full name across every registered module.
    /// </summary>
    /// <remarks>
    /// Only registered modules are searched — see <see cref="RegisterModule"/> for why the
    /// application's own module has to be seeded. Search order is registration order, and the
    /// first match wins; a name that exists in two modules is ambiguous and this does not try
    /// to resolve the ambiguity.
    /// </remarks>
    public bool TryFindType(IMemoryReader memory, string fullName, [NotNullWhen(true)] out ClrTypeInfo? type)
    {
        ArgumentNullException.ThrowIfNull(memory);
        ArgumentNullException.ThrowIfNull(fullName);

        type = null;
        foreach (ClrModuleInfo module in Modules)
        {
            if (!module.Metadata.Types.TryResolveType(fullName, out TypeDefinitionHandle handle)) continue;

            int rid = MetadataTokens.GetRowNumber(handle);
            if (!module.TryGetMethodTable(memory, rid, out ulong methodTable)) continue;
            if (!TryGetType(memory, methodTable, out type)) continue;

            return true;
        }

        return false;
    }

    /// <summary>
    /// Resolve a named instance field on <paramref name="type"/> or any of its ancestors.
    /// </summary>
    /// <remarks>
    /// The base-first walk mirrors how the runtime lays objects out and how §12.4b's paths
    /// read (<c>Creature._currentHp</c> is declared on a base, not on the concrete monster).
    /// A derived type that redeclares a name shadows the base, so the walk stops at the first
    /// declaration found from the concrete type upward.
    /// </remarks>
    public bool TryGetFieldLocation(
        IMemoryReader memory,
        ClrTypeInfo type,
        string fieldName,
        out ClrFieldLocation location,
        out ClrTypeInfo declaringType)
    {
        ArgumentNullException.ThrowIfNull(memory);
        ArgumentNullException.ThrowIfNull(type);
        ArgumentNullException.ThrowIfNull(fieldName);

        foreach (ClrTypeInfo candidate in type.WithAncestors(memory))
        {
            if (!candidate.TryGetDeclaredField(fieldName, out MetadataField field)) continue;

            // A const has no storage at all; reporting an offset for one would be fiction.
            if (field.IsLiteral || field.IsStatic) continue;

            if (FieldLayout.TryGetField(memory, candidate, fieldName, out location))
            {
                declaringType = candidate;
                return true;
            }
        }

        location = default;
        declaringType = type;
        return false;
    }

    /// <summary>Every instance field name visible on a type, derived types first.</summary>
    public IReadOnlyCollection<string> GetAllFieldNames(IMemoryReader memory, ClrTypeInfo type)
    {
        ArgumentNullException.ThrowIfNull(memory);
        ArgumentNullException.ThrowIfNull(type);

        var names = new List<string>();
        var seen = new HashSet<string>(StringComparer.Ordinal);

        foreach (ClrTypeInfo candidate in type.WithAncestors(memory))
        {
            foreach (string name in candidate.DeclaredFieldNames)
            {
                if (seen.Add(name)) names.Add(name);
            }
        }

        return names;
    }

    /// <summary>
    /// Whether <paramref name="methodTable"/> really is one.
    /// </summary>
    /// <remarks>
    /// Two independent round trips, both from published offsets: the
    /// <c>EEClassOrCanonMT</c> union must resolve to an <c>EEClass</c> whose
    /// <c>MethodTable</c> back-pointer agrees, and <c>MethodTable.Module</c> must lead to a
    /// non-zero <c>Module.Base</c>. Garbage passes neither.
    /// </remarks>
    public bool IsMethodTable(IMemoryReader memory, ulong methodTable) =>
        TryGetFacts(memory, methodTable, out _);

    /// <summary>
    /// What validating a method table established, cached alongside the verdict.
    /// </summary>
    /// <remarks>
    /// Caching the boolean alone would make <see cref="Build"/> resolve the
    /// <c>EEClassOrCanonMT</c> union a second time — the same three reads, on the hot path of
    /// every first-seen type. The facts are as process-tier as the verdict is: everything here
    /// is a loader-heap pointer (§7b.1).
    /// </remarks>
    private readonly record struct MethodTableFacts(ulong EEClass, ulong CanonicalMethodTable, ulong ModulePointer);

    private bool TryGetFacts(IMemoryReader memory, ulong methodTable, out MethodTableFacts facts)
    {
        ArgumentNullException.ThrowIfNull(memory);
        facts = default;
        if (methodTable == 0 || (methodTable & 3) != 0) return false;

        lock (_gate)
        {
            if (_validMethodTables.TryGetValue(methodTable, out MethodTableFacts? cached))
            {
                if (cached is null) return false;
                facts = cached.Value;
                return true;
            }
        }

        MethodTableFacts? resolved = null;

        if (TryResolveEEClass(memory, methodTable, out ulong eeClass, out ulong canonical) &&
            memory.TryReadPointer(methodTable + (ulong)Layouts.MethodTableModuleOffset, out ulong modulePointer) &&
            modulePointer != 0 &&
            memory.TryReadPointer(modulePointer + (ulong)Layouts.ModuleBaseOffset, out ulong moduleBase) &&
            moduleBase != 0)
        {
            resolved = new MethodTableFacts(eeClass, canonical, modulePointer);
        }

        lock (_gate) _validMethodTables[methodTable] = resolved;

        if (resolved is null) return false;
        facts = resolved.Value;
        return true;
    }

    /// <inheritdoc cref="ClrLayouts.TryResolveEEClass"/>
    public bool TryResolveEEClass(IMemoryReader memory, ulong methodTable, out ulong eeClass, out ulong canonicalMethodTable) =>
        Layouts.TryResolveEEClass(memory, methodTable, out eeClass, out canonicalMethodTable);

    private bool ComponentSizeAgrees(IMemoryReader memory, string global, int expected)
    {
        if (!_target.TryGetGlobalPointer(global, out ulong address)) return false;
        if (!memory.TryReadPointer(address, out ulong methodTable) || methodTable == 0) return false;
        return TryReadComponentSize(memory, methodTable, out int size) && size == expected;
    }

    /// <summary>
    /// Element stride from <c>MethodTable.MTFlags</c>: the low 16 bits, valid only when the
    /// flag word's top bit marks the method table as having one. Verified rather than trusted
    /// — see <see cref="ComponentSizeIsTrusted"/>.
    /// </summary>
    private bool TryReadComponentSize(IMemoryReader memory, ulong methodTable, out int componentSize)
    {
        componentSize = 0;
        if (!memory.TryRead(methodTable + (ulong)Layouts.MethodTableFlagsOffset, out uint flags)) return false;
        if ((flags & 0x8000_0000u) == 0) return false;

        componentSize = (int)(flags & 0xFFFFu);
        return componentSize > 0;
    }

    private ClrTypeInfo? Build(IMemoryReader memory, ulong methodTable)
    {
        if (!TryGetFacts(memory, methodTable, out MethodTableFacts facts)) return null;

        ulong eeClass = facts.EEClass;
        ulong canonicalMethodTable = facts.CanonicalMethodTable;
        ulong modulePointer = facts.ModulePointer;

        // Every read that DEFINES the type must succeed. A ClrTypeInfo is process-tier (§8.8)
        // and there is no invalidation, so a read that failed here would be cached for the
        // lifetime of the attach: the type would lose its base chain permanently, and
        // baseSize 0 silently disables RuntimeFieldLayoutSource's offset bound. Discarding these
        // flags was the one place a process-tier cache was filled from unvalidated reads, which
        // is not what TryGetFacts above demands of itself.
        if (!memory.TryReadPointer(methodTable + (ulong)Layouts.MethodTableParentOffset, out ulong parent)) return null;
        if (!memory.TryRead(methodTable + (ulong)Layouts.MethodTableBaseSizeOffset, out uint baseSize)) return null;
        if (!memory.TryRead(eeClass + (ulong)Layouts.EEClassElementTypeOffset, out byte rawElementType)) return null;

        var elementType = (ClrElementType)rawElementType;
        int componentSize = TryReadComponentSize(memory, methodTable, out int size) ? size : 0;

        // Optional in both directions: unpublished (§5.5) or unreadable both mean "not known",
        // because nothing here acts on the flags.
        System.Reflection.TypeAttributes? typeAttributes = null;
        if (Layouts.HasEEClassTypeAttributes &&
            memory.TryRead(eeClass + (ulong)Layouts.EEClassTypeAttributesOffset, out uint rawAttributes))
        {
            typeAttributes = (System.Reflection.TypeAttributes)rawAttributes;
        }

        ClrModuleInfo? module = RegisterModule(memory, modulePointer);
        TypeDefinitionHandle typeDef = default;
        string name;

        if (module is not null &&
            (module.TryGetTypeDefRid(memory, methodTable, out int rid) ||
             module.TryGetTypeDefRid(memory, canonicalMethodTable, out rid)))
        {
            typeDef = MetadataTokens.TypeDefinitionHandle(rid);
            name = module.Metadata.Types.GetFullName(typeDef);
        }
        else
        {
            name = $"<mt:0x{methodTable:X}>";
        }

        ulong elementMethodTable = 0;
        if (elementType is ClrElementType.SzArray or ClrElementType.Array)
        {
            elementMethodTable = TryReadArrayElementMethodTable(memory, methodTable);
            if (elementMethodTable != 0 && TryGetType(memory, elementMethodTable, out ClrTypeInfo? element))
            {
                name = element.Name + "[]";
            }
        }

        return new ClrTypeInfo(
            this, methodTable, name, module, typeDef, parent, baseSize, componentSize, elementType, elementMethodTable,
            typeAttributes);
    }

    /// <summary>
    /// An array method table's element type handle, taken from <c>MethodTable.PerInstInfo</c>
    /// (§5.2: 48) — a union slot that holds the element handle for array types.
    /// </summary>
    /// <remarks>
    /// The descriptor publishes the offset but not the union's discriminator, so the result is
    /// only used if it validates as a method table in its own right. A handle that is really a
    /// <c>TypeDesc</c> (pointer or by-ref element types) will not, and the array is then
    /// described without an element type rather than with a wrong one.
    /// </remarks>
    private ulong TryReadArrayElementMethodTable(IMemoryReader memory, ulong methodTable)
    {
        if (!_target.TryGetFieldOffset("MethodTable", "PerInstInfo", out int offset)) return 0;
        if (!memory.TryReadPointer(methodTable + (ulong)offset, out ulong handle)) return 0;
        if (handle == 0 || (handle & 3) != 0) return 0;

        return IsMethodTable(memory, handle) ? handle : 0;
    }
}
