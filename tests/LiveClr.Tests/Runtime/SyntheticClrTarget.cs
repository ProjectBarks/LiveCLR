namespace LiveClr.Tests.Runtime;

using System.Reflection.Metadata;
using System.Text;
using System.Text.Json.Nodes;
using LiveClr.Fixtures;
using LiveClr.Memory;
using LiveClr.Metadata;
using LiveClr.Runtime;
using LiveClr.Tests.Cdac;
using LiveClr.Tests.Metadata;

/// <summary>How a synthesised <c>FieldDesc</c> stores its offset and its back-pointer.</summary>
/// <remarks>
/// Two encodings exist so the tests can prove that <see cref="FieldDescCalibration"/> DERIVES a
/// layout rather than recognising a familiar one. A calibrator that only ever sees one encoding
/// is indistinguishable from a hardcoded table; one that handles two unrelated bit positions
/// and two different back-pointer forms is not. This is §12.5's own standard of evidence —
/// intersect across samples that disagree — applied to the test rather than to the target.
/// </remarks>
public enum FieldDescStyle
{
    /// <summary>16 bytes: absolute back-pointer at +0, offset in bits [0,27) of the word at +12.</summary>
    CoreClrLike,

    /// <summary>32 bytes: self-relative back-pointer at +8, offset in bits [5,32) of the word at +20.</summary>
    Alternate,
}

/// <summary>
/// Deliberate degradations the fixture can apply, so refusal paths are exercised rather than
/// assumed.
/// </summary>
/// <remarks>
/// §12.5's lesson is that a confident wrong answer is the worst outcome, so each of these
/// damages one input the reader depends on and the corresponding test asserts that the reader
/// declines rather than producing a single plausible answer.
/// </remarks>
internal sealed record SyntheticTargetOptions
{
    /// <summary>How synthesised <c>FieldDesc</c>s encode their offset.</summary>
    public FieldDescStyle Style { get; init; } = FieldDescStyle.CoreClrLike;

    /// <summary>Lay down at most this many <c>System.Exception</c> field descriptors.</summary>
    public int ExceptionFieldLimit { get; init; } = int.MaxValue;

    /// <summary>Store one <c>System.Exception</c> field at an offset the descriptor disagrees with.</summary>
    public bool CorruptOneExceptionOffset { get; init; }

    /// <summary>Publish an <c>ExceptionMethodTable</c> global that is not a method table.</summary>
    public bool GarbageExceptionMethodTable { get; init; }

    /// <summary>Give <c>System.String</c> a component size that contradicts its published one.</summary>
    public bool BreakComponentSizeEncoding { get; init; }

    /// <summary>Unmap an interior page of CoreLib's TypeDef map, as a segment boundary would.</summary>
    public bool PunchTypeMapHole { get; init; }

    /// <summary>Give the holder a list whose backing array reference is null.</summary>
    public bool NullBackingArray { get; init; }

    /// <summary>
    /// Flag bits to set in the low bits of every <c>FieldDefToDescMap</c> entry, as §5.4 says a
    /// real map carries.
    /// </summary>
    /// <remarks>
    /// Zero writes clean pointers, which is the ONE case where the entry mask cannot matter —
    /// so a fixture that only ever writes zero leaves both the mask derivation and
    /// <see cref="RuntimeFieldLayoutSource"/>'s masking untested on the path that ships.
    /// </remarks>
    public int FieldMapEntryFlags { get; init; }

    /// <summary>
    /// Descriptor entries, in <c>"Type.Field"</c> form, to strip from the published blob before
    /// the fixture writes it (§5.5: coverage is a goal, not a guarantee).
    /// </summary>
    public IReadOnlyList<string> OmitDescriptorEntries { get; init; } = [];
}

/// <summary>
/// A whole CLR-shaped target in recorded memory: a coreclr image exporting the real §5.2
/// contract descriptor, two real managed assemblies mapped as loaded images, synthesised
/// runtime structures for them, and a managed heap.
/// </summary>
/// <remarks>
/// <para>
/// §8.8's first "addition" is a recorded-fixture provider, on the grounds that everything in
/// §12 required a live game and without fixtures <c>LiveClr.Tests</c> cannot run in CI at all.
/// This is that fixture for the Runtime and Snapshots layers.
/// </para>
/// <para>
/// <b>What is real and what is fabricated.</b> The contract descriptor is the verbatim blob
/// from the shipped runtime (§5.2). The metadata is real: <c>System.Private.CoreLib</c> and
/// <c>LiveClr.Tests</c> are mapped exactly as the loader would map them, so every type name,
/// field name and metadata token the reader resolves is genuine. Fabricated are the runtime
/// structures the GC and loader would build — <c>MethodTable</c>, <c>EEClass</c>,
/// <c>Module</c>, the lookup maps, the <c>FieldDesc</c>s and the objects — laid out at exactly
/// the offsets the descriptor publishes.
/// </para>
/// </remarks>
internal sealed class SyntheticClrTarget : IDisposable
{
    // Descriptor-published offsets (§5.2), spelled out here because the fixture WRITES the
    // structures the production code reads; sharing a constant would let a wrong offset agree
    // with itself.
    private const int MtFlags = 0;
    private const int MtBaseSize = 4;
    private const int MtParent = 16;
    private const int MtModule = 24;
    private const int MtEEClassOrCanonMt = 40;
    private const int MtPerInstInfo = 48;
    private const int MtSize = 56;

    private const int EEClassMethodTable = 16;
    private const int EEClassCorTypeAttr = 56;
    private const int EEClassElementType = 64;
    private const int EEClassSize = 80;

    private const int ModuleBase = 192;
    private const int ModuleTypeDefMap = 336;
    private const int ModuleFieldDefMap = 432;
    private const int ModuleSize = 768;

    private const int LookupMapTableData = 8;

    private const int ObjectHeaderSize = 8;
    private const int StringLength = 8;
    private const int StringFirstChar = 12;
    private const int ArrayNumComponents = 8;
    private const int ArrayFirstElement = 16;

    private const ulong CoreLibImageBase = 0x0000_0300_0000_0000;
    private const ulong AppImageBase = 0x0000_0380_0000_0000;
    private const ulong ArenaBase = 0x0000_0400_0000_0000;

    /// <summary>Generous stride so the calibrator's 64-byte window never straddles two descriptors.</summary>
    private const int FieldDescStride = 128;

    private readonly PagedFixtureBuilder _builder = new();
    private readonly SyntheticTargetOptions _options;
    private readonly List<int> _coreLibTypeRids = [];
    private FieldDescStyle Style => _options.Style;
    private ulong _next = ArenaBase;

    private SyntheticClrTarget(SyntheticTargetOptions options) => _options = options;

    /// <summary>The recorded address space.</summary>
    public RecordedMemory Memory { get; private set; } = null!;

    /// <summary>Modules to report from <c>ILiveProcess.ModuleNames</c>.</summary>
    public ModuleTable Modules { get; private set; } = null!;

    /// <summary>The synthesised coreclr image.</summary>
    public ModuleInfo CoreClr { get; private set; } = null!;

    /// <summary>Runtime <c>Module*</c> of the assembly holding the fixture types.</summary>
    public ulong AppModulePointer { get; private set; }

    /// <summary>Runtime <c>Module*</c> of CoreLib.</summary>
    public ulong CoreLibModulePointer { get; private set; }

    /// <summary>Address of a <c>FixtureHolder</c> instance.</summary>
    public ulong HolderAddress { get; private set; }

    /// <summary>Address of a <c>FixtureDerived</c> whose <c>Name</c> is <see cref="ExpectedName"/>.</summary>
    public ulong DerivedAddress { get; private set; }

    /// <summary>Address of a <c>FixtureHolder</c> whose list claims more items than it has.</summary>
    public ulong TornHolderAddress { get; private set; }

    /// <summary>Slot holding the good holder's <c>List&lt;T&gt;._size</c>, so a test can mutate it.</summary>
    public ulong ListSizeSlot { get; private set; }

    /// <summary>Slot holding <c>FixtureHolder.Instance</c>, as a static root source would report it.</summary>
    public ulong StaticInstanceSlot { get; private set; }

    /// <summary>Method table of <c>FixtureDerived</c>, for negative tests.</summary>
    public ulong DerivedMethodTable { get; private set; }

    /// <summary>The string stored in <see cref="DerivedAddress"/>'s <c>Name</c>.</summary>
    public const string ExpectedName = "Necrobinder";

    /// <summary>Live count of the good holder's list; its backing array is deliberately larger.</summary>
    public const int ListCount = 2;

    /// <summary>Capacity of that list's backing array (§12.4, API fact 2).</summary>
    public const int ListCapacity = 4;

    /// <summary><c>_size</c> reported by the torn holder's list, past its capacity.</summary>
    public const int TornListSize = 5;

    /// <summary>Address of a holder whose list has a null backing array.</summary>
    public ulong NullItemsHolderAddress { get; private set; }

    /// <summary>Build the fixture.</summary>
    public static SyntheticClrTarget Build(FieldDescStyle style = FieldDescStyle.CoreClrLike) =>
        Build(new SyntheticTargetOptions { Style = style });

    /// <summary>Build the fixture with one or more deliberate degradations applied.</summary>
    public static SyntheticClrTarget Build(SyntheticTargetOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        var target = new SyntheticClrTarget(options);
        target.Assemble();
        return target;
    }

    /// <summary>Attach a <see cref="LiveProcess"/> over this fixture.</summary>
    public LiveProcess Attach(LiveProcessOptions? options = null) =>
        LiveProcess.Create(0, Memory, ownsMemory: false, Modules, CoreClr, options);

    /// <summary>Static roots as §5.5 says they must be supplied: resolved once, out of band.</summary>
    public ExplicitStaticRootSource StaticRoots() =>
        new ExplicitStaticRootSource().Add(typeof(FixtureHolder).FullName!, nameof(FixtureHolder.Instance), StaticInstanceSlot);

    public void Dispose() => Memory.Dispose();

    private void Assemble()
    {
        MapCoreClrAndDescriptor();

        (byte[] coreLibImage, ModuleMetadata coreLibMetadata) = MapAssembly(typeof(object).Assembly.Location, CoreLibImageBase);
        (byte[] appImage, ModuleMetadata appMetadata) = MapAssembly(typeof(FixtureBase).Assembly.Location, AppImageBase);

        try
        {
            CoreLibModulePointer = DefineModule(CoreLibImageBase, coreLibMetadata);
            AppModulePointer = DefineModule(AppImageBase, appMetadata);

            DefineCoreLibTypes(coreLibMetadata);
            DefineAppTypes(appMetadata);

            // After every write: writing a page recreates it.
            if (_options.PunchTypeMapHole) PunchHoleInTypeMap(coreLibMetadata);
        }
        finally
        {
            coreLibMetadata.Dispose();
            appMetadata.Dispose();
        }

        Memory = _builder.Build("synthetic CLR target (LiveClr.Tests)");

        CoreClr = new ModuleInfo("coreclr.dll", SyntheticPe.DefaultImageBase, 0x50_0000);
        Modules = new ModuleTable(
        [
            CoreClr,
            new ModuleInfo("System.Private.CoreLib.dll", CoreLibImageBase, (uint)coreLibImage.Length),
            new ModuleInfo("LiveClr.Tests.dll", AppImageBase, (uint)appImage.Length),
        ]);
    }

    // ---------------------------------------------------------------- descriptor

    private void MapCoreClrAndDescriptor()
    {
        byte[] json = Encoding.UTF8.GetBytes(WithoutOmittedEntries(DescriptorFixture.Json, _options.OmitDescriptorEntries));

        _builder.Write(SyntheticPe.DefaultImageBase, SyntheticPe.BuildCoreClrLike());
        _builder.Write(SyntheticDescriptor.DescriptorAddress, SyntheticDescriptor.Header64(json.Length));
        _builder.Write(SyntheticDescriptor.JsonAddress, json);
        _builder.Write(SyntheticDescriptor.PointerDataAddress, SyntheticDescriptor.Pointers64(SyntheticDescriptor.PointerData));
    }

    /// <summary>
    /// The shipped descriptor with named entries removed, modelling a runtime that publishes
    /// less than the one §5.2 was read from.
    /// </summary>
    /// <remarks>
    /// Edited as a parsed document rather than as text: the blob is checked in verbatim and a
    /// substring deletion that silently matched nothing would make an omission test pass by
    /// testing the unmodified descriptor.
    /// </remarks>
    private static string WithoutOmittedEntries(string descriptorJson, IReadOnlyList<string> entries)
    {
        if (entries.Count == 0) return descriptorJson;

        JsonNode root = JsonNode.Parse(descriptorJson)
            ?? throw new InvalidOperationException("the descriptor fixture is not JSON.");

        foreach (string entry in entries)
        {
            string[] parts = entry.Split('.', 2);
            JsonObject? type = root["types"]?[parts[0]]?.AsObject();

            if (type is null || parts.Length != 2 || !type.Remove(parts[1]))
            {
                throw new InvalidOperationException($"the descriptor fixture publishes no '{entry}' to omit.");
            }
        }

        return root.ToJsonString();
    }

    /// <summary>Publish a method table through the descriptor's <c>pointer_data</c> indirection (§5.3).</summary>
    private void PublishGlobal(int pointerDataIndex, ulong value) =>
        _builder.WriteU64(SyntheticDescriptor.PointerData[pointerDataIndex], value);

    // ---------------------------------------------------------------- modules

    private (byte[] Image, ModuleMetadata Metadata) MapAssembly(string path, ulong imageBase)
    {
        MappedPeImage mapped = MappedPeImage.FromBytes(File.ReadAllBytes(path));
        _builder.Write(imageBase, mapped.Image);

        using var reader = new FakeImageMemoryReader(mapped.Image, imageBase);
        ModuleMetadata metadata = ModuleMetadata.TryLoad(reader, imageBase)
            ?? throw new InvalidOperationException($"'{path}' produced no metadata; the fixture cannot be built.");

        return (mapped.Image, metadata);
    }

    private ulong DefineModule(ulong imageBase, ModuleMetadata metadata)
    {
        ulong module = Alloc(ModuleSize);
        _builder.WriteU64(module + ModuleBase, imageBase);

        int typeCount = metadata.Reader.TypeDefinitions.Count;
        int fieldCount = metadata.Reader.FieldDefinitions.Count;

        // The lookup maps live inline in Module; only TableData is published, and it points at
        // a rid-indexed array whose slot 0 is unused (§5.4).
        ulong typeTable = Alloc((typeCount + 2) * 8);
        ulong fieldTable = Alloc((fieldCount + 2) * 8);

        _builder.WriteU64(module + ModuleTypeDefMap + LookupMapTableData, typeTable);
        _builder.WriteU64(module + ModuleFieldDefMap + LookupMapTableData, fieldTable);

        _moduleTables[module] = (typeTable, fieldTable, metadata);
        return module;
    }

    private readonly Dictionary<ulong, (ulong TypeTable, ulong FieldTable, ModuleMetadata Metadata)> _moduleTables = [];

    /// <summary>
    /// Removes one interior page of CoreLib's TypeDef map, modelling what a caller sees when the
    /// map is segmented: the first segment is mapped, and whatever the walk reads past its end
    /// is not.
    /// </summary>
    /// <remarks>
    /// The page is chosen to contain none of the fixture's own type rids, so the test can
    /// distinguish "some rids are gone" (correct degradation) from "the whole map is gone"
    /// (the failure being guarded against).
    /// </remarks>
    private void PunchHoleInTypeMap(ModuleMetadata coreLib)
    {
        ulong table = _moduleTables[CoreLibModulePointer].TypeTable;
        int typeCount = coreLib.Reader.TypeDefinitions.Count;
        int pages = (int)(((ulong)(typeCount + 2) * 8) / (ulong)PagedFixtureBuilder.Page);

        for (int page = 1; page < pages - 1; page++)
        {
            ulong pageBase = PagedFixtureBuilder.PageOf(table + ((ulong)page * (ulong)PagedFixtureBuilder.Page));
            bool holdsAFixtureType = _coreLibTypeRids.Exists(
                rid => PagedFixtureBuilder.PageOf(table + ((ulong)rid * 8)) == pageBase);

            if (holdsAFixtureType) continue;

            TypeMapHolePage = pageBase;
            _builder.Unmap(pageBase);
            return;
        }

        throw new InvalidOperationException("CoreLib's TypeDef map has no interior page free of fixture types.");
    }

    /// <summary>The page removed by <see cref="SyntheticTargetOptions.PunchTypeMapHole"/>, or 0.</summary>
    public ulong TypeMapHolePage { get; private set; }

    // ---------------------------------------------------------------- CoreLib

    private ulong _stringMethodTable;
    private ulong _objectMethodTable;
    private ulong _listCanonicalMethodTable;

    private void DefineCoreLibTypes(ModuleMetadata metadata)
    {
        _objectMethodTable = DefineType(CoreLibModulePointer, metadata, "System.Object", 0, 24, 0, ClrElementType.Class);

        // §5.2 fixes System.String's stride at 2 (m_FirstChar is UTF-16). Writing anything else
        // is what a runtime whose MTFlags encoding this reader does not understand looks like.
        int stringStride = _options.BreakComponentSizeEncoding ? 3 : 2;
        _stringMethodTable = DefineType(
            CoreLibModulePointer, metadata, "System.String", _objectMethodTable, 22, stringStride, ClrElementType.String);

        ulong objectArray = DefineArrayType(CoreLibModulePointer, _objectMethodTable, 8, _objectMethodTable);
        ulong exception = DefineType(CoreLibModulePointer, metadata, "System.Exception", _objectMethodTable, 136, 0, ClrElementType.Class);

        PublishGlobal(8, _objectMethodTable);
        PublishGlobal(10, _stringMethodTable);
        PublishGlobal(9, objectArray);

        // A mapped page of zeroes: readable, and nothing like a method table. This is the
        // "the anchor itself is degenerate" case.
        PublishGlobal(6, _options.GarbageExceptionMethodTable ? Alloc(64) : exception);

        // The calibration anchor: give System.Exception's published fields (§5.2) FieldDescs
        // holding exactly the offsets the descriptor advertises, minus the object header.
        DefineExceptionFieldDescs(metadata, exception);

        // List<T> — the canonical, shared-generic method table. Instantiations point at it
        // through the EEClassOrCanonMT union.
        _listCanonicalMethodTable = DefineType(
            CoreLibModulePointer, metadata, "System.Collections.Generic.List`1", _objectMethodTable, 32, 0, ClrElementType.Class);

        DefineFieldDesc(CoreLibModulePointer, metadata, "System.Collections.Generic.List`1", "_items", _listCanonicalMethodTable, 8);
        DefineFieldDesc(CoreLibModulePointer, metadata, "System.Collections.Generic.List`1", "_size", _listCanonicalMethodTable, 16);
    }

    private void DefineExceptionFieldDescs(ModuleMetadata metadata, ulong exceptionMethodTable)
    {
        TypeDefinitionHandle handle = metadata.Types.ResolveType("System.Exception")
            ?? throw new InvalidOperationException("CoreLib defines no System.Exception.");

        PublishedExceptionFields = 0;
        foreach (MetadataField field in metadata.Types.GetFields(handle))
        {
            if (field.IsStatic || field.IsLiteral) continue;
            if (!ExceptionOffsets.TryGetValue(field.Name, out int objectRelative)) continue;
            if (PublishedExceptionFields >= _options.ExceptionFieldLimit) break;

            // One field stored where the descriptor says it is not: no single bitfield position
            // can then reproduce every published offset, which must end in refusal.
            bool corrupt = _options.CorruptOneExceptionOffset && PublishedExceptionFields == 1;

            WriteFieldDesc(CoreLibModulePointer, field.Token, exceptionMethodTable, corrupt ? objectRelative + 4 : objectRelative);
            PublishedExceptionFields++;
        }
    }

    /// <summary>How many calibration samples the fixture actually managed to lay down.</summary>
    public int PublishedExceptionFields { get; private set; }

    /// <summary>
    /// The <c>Exception</c> offsets the shipped descriptor publishes (§5.2). Written into the
    /// fixture verbatim so that a calibrator reading them back reproduces the same numbers.
    /// </summary>
    private static readonly Dictionary<string, int> ExceptionOffsets = new(StringComparer.Ordinal)
    {
        ["_message"] = 16,
        ["_innerException"] = 32,
        ["_stackTrace"] = 48,
        ["_watsonBuckets"] = 56,
        ["_stackTraceString"] = 64,
        ["_remoteStackTraceString"] = 72,
        ["_xcode"] = 104,
        ["_HResult"] = 108,
    };

    // ---------------------------------------------------------------- app types and heap

    private void DefineAppTypes(ModuleMetadata app)
    {
        ulong baseMt = DefineType(AppModulePointer, app, typeof(FixtureBase).FullName!, _objectMethodTable, 24, 0, ClrElementType.Class);
        ulong derivedMt = DefineType(AppModulePointer, app, typeof(FixtureDerived).FullName!, baseMt, 32, 0, ClrElementType.Class);
        ulong holderMt = DefineType(AppModulePointer, app, typeof(FixtureHolder).FullName!, _objectMethodTable, 24, 0, ClrElementType.Class);

        DerivedMethodTable = derivedMt;

        DefineFieldDesc(AppModulePointer, app, typeof(FixtureBase).FullName!, nameof(FixtureBase.Hp), baseMt, 8);
        DefineFieldDesc(AppModulePointer, app, typeof(FixtureDerived).FullName!, nameof(FixtureDerived.Name), derivedMt, 16);
        DefineFieldDesc(AppModulePointer, app, typeof(FixtureDerived).FullName!, nameof(FixtureDerived.Link), derivedMt, 24);
        DefineFieldDesc(AppModulePointer, app, typeof(FixtureHolder).FullName!, nameof(FixtureHolder.Items), holderMt, 8);
        DefineFieldDesc(AppModulePointer, app, typeof(FixtureHolder).FullName!, nameof(FixtureHolder.Numbers), holderMt, 16);

        ulong derivedArrayMt = DefineArrayType(CoreLibModulePointer, _objectMethodTable, 8, derivedMt);
        ulong intArrayMt = DefineArrayType(CoreLibModulePointer, _objectMethodTable, 4, 0);

        // List<FixtureDerived>: a distinct method table whose EEClassOrCanonMT points at the
        // canonical List<T>, which is how a generic instantiation reaches its field layout.
        ulong listMt = DefineInstantiatedType(CoreLibModulePointer, _listCanonicalMethodTable, _objectMethodTable, 32);

        ulong name = DefineString(ExpectedName);
        ulong staleName = DefineString("StaleEntryFromAPreviousState");

        ulong first = DefineDerived(derivedMt, hp: 61, name: name, link: 0);
        ulong second = DefineDerived(derivedMt, hp: 66, name: 0, link: first);
        ulong stale = DefineDerived(derivedMt, hp: -999, name: staleName, link: 0);
        DerivedAddress = first;

        ulong items = DefineArray(derivedArrayMt, elementSize: 8, ListCapacity, [first, second, stale, 0]);
        ulong numbers = DefineIntArray(intArrayMt, [3, 1, 4]);

        ulong list = DefineList(listMt, items, ListCount);
        ListSizeSlot = list + 16;
        HolderAddress = DefineHolder(holderMt, list, numbers);

        // The §12.4e case: every read succeeds, and the structure still disagrees with itself.
        TornHolderAddress = DefineHolder(holderMt, DefineList(listMt, items, TornListSize), numbers);

        // A list caught mid-construction, or a torn _items pointer: no backing array at all.
        NullItemsHolderAddress = DefineHolder(holderMt, DefineList(listMt, items: 0, size: _options.NullBackingArray ? 3 : 0), numbers);

        StaticInstanceSlot = Alloc(8);
        _builder.WriteU64(StaticInstanceSlot, HolderAddress);
    }

    private ulong DefineDerived(ulong methodTable, int hp, ulong name, ulong link)
    {
        ulong obj = Alloc(32);
        _builder.WriteU64(obj, methodTable);
        _builder.WriteI32(obj + 8, hp);
        _builder.WriteU64(obj + 16, name);
        _builder.WriteU64(obj + 24, link);
        return obj;
    }

    private ulong DefineHolder(ulong methodTable, ulong items, ulong numbers)
    {
        ulong obj = Alloc(24);
        _builder.WriteU64(obj, methodTable);
        _builder.WriteU64(obj + 8, items);
        _builder.WriteU64(obj + 16, numbers);
        return obj;
    }

    private ulong DefineList(ulong methodTable, ulong items, int size)
    {
        ulong obj = Alloc(32);
        _builder.WriteU64(obj, methodTable);
        _builder.WriteU64(obj + 8, items);
        _builder.WriteI32(obj + 16, size);
        return obj;
    }

    private ulong DefineArray(ulong methodTable, int elementSize, int count, ulong[] elements)
    {
        ulong obj = Alloc(ArrayFirstElement + (count * elementSize));
        _builder.WriteU64(obj, methodTable);
        _builder.WriteU32(obj + ArrayNumComponents, (uint)count);

        for (int i = 0; i < elements.Length && i < count; i++)
        {
            _builder.WriteU64(obj + (ulong)ArrayFirstElement + ((ulong)i * (ulong)elementSize), elements[i]);
        }

        return obj;
    }

    private ulong DefineIntArray(ulong methodTable, int[] values)
    {
        ulong obj = Alloc(ArrayFirstElement + (values.Length * 4));
        _builder.WriteU64(obj, methodTable);
        _builder.WriteU32(obj + ArrayNumComponents, (uint)values.Length);

        for (int i = 0; i < values.Length; i++) _builder.WriteI32(obj + (ulong)ArrayFirstElement + ((ulong)i * 4), values[i]);

        return obj;
    }

    private ulong DefineString(string value)
    {
        ulong obj = Alloc(StringFirstChar + (value.Length * 2) + 2);
        _builder.WriteU64(obj, _stringMethodTable);
        _builder.WriteI32(obj + StringLength, value.Length);
        _builder.Write(obj + StringFirstChar, Encoding.Unicode.GetBytes(value));
        return obj;
    }

    // ---------------------------------------------------------------- runtime structures

    private ulong DefineType(
        ulong modulePointer,
        ModuleMetadata metadata,
        string fullName,
        ulong parent,
        uint baseSize,
        int componentSize,
        ClrElementType elementType)
    {
        ulong methodTable = DefineMethodTable(modulePointer, parent, baseSize, componentSize, elementType, perInstInfo: 0);

        TypeDefinitionHandle handle = metadata.Types.ResolveType(fullName)
            ?? throw new InvalidOperationException($"the fixture's metadata defines no '{fullName}'.");

        int rid = System.Reflection.Metadata.Ecma335.MetadataTokens.GetRowNumber(handle);
        _builder.WriteU64(_moduleTables[modulePointer].TypeTable + ((ulong)rid * 8), methodTable);

        if (modulePointer == CoreLibModulePointer) _coreLibTypeRids.Add(rid);

        return methodTable;
    }

    /// <summary>An array method table: no TypeDef row, an element handle in <c>PerInstInfo</c>.</summary>
    private ulong DefineArrayType(ulong modulePointer, ulong parent, int componentSize, ulong elementMethodTable) =>
        DefineMethodTable(modulePointer, parent, 24, componentSize, ClrElementType.SzArray, elementMethodTable);

    /// <summary>
    /// A generic instantiation: its <c>EEClassOrCanonMT</c> carries the canonical method table
    /// with the union's tag bit set, rather than an <c>EEClass</c> pointer.
    /// </summary>
    private ulong DefineInstantiatedType(ulong modulePointer, ulong canonical, ulong parent, uint baseSize)
    {
        ulong methodTable = Alloc(MtSize);
        _builder.WriteU32(methodTable + MtFlags, 0);
        _builder.WriteU32(methodTable + MtBaseSize, baseSize);
        _builder.WriteU64(methodTable + MtParent, parent);
        _builder.WriteU64(methodTable + MtModule, modulePointer);
        _builder.WriteU64(methodTable + MtEEClassOrCanonMt, canonical | 1);
        return methodTable;
    }

    private ulong DefineMethodTable(
        ulong modulePointer, ulong parent, uint baseSize, int componentSize, ClrElementType elementType, ulong perInstInfo)
    {
        ulong methodTable = Alloc(MtSize);
        ulong eeClass = Alloc(EEClassSize);

        uint flags = componentSize > 0 ? 0x8000_0000u | (uint)componentSize : 0u;
        _builder.WriteU32(methodTable + MtFlags, flags);
        _builder.WriteU32(methodTable + MtBaseSize, baseSize);
        _builder.WriteU64(methodTable + MtParent, parent);
        _builder.WriteU64(methodTable + MtModule, modulePointer);
        _builder.WriteU64(methodTable + MtEEClassOrCanonMt, eeClass);
        _builder.WriteU64(methodTable + MtPerInstInfo, perInstInfo);

        _builder.WriteU64(eeClass + EEClassMethodTable, methodTable);
        _builder.WriteU32(eeClass + EEClassCorTypeAttr, 0x0010_0001);
        _builder.WriteU8(eeClass + EEClassElementType, (byte)elementType);

        return methodTable;
    }

    private void DefineFieldDesc(
        ulong modulePointer, ModuleMetadata metadata, string typeName, string fieldName, ulong enclosing, int objectRelativeOffset)
    {
        TypeDefinitionHandle handle = metadata.Types.ResolveType(typeName)
            ?? throw new InvalidOperationException($"the fixture's metadata defines no '{typeName}'.");

        if (!metadata.Types.TryGetField(handle, fieldName, out MetadataField field))
        {
            throw new InvalidOperationException($"'{typeName}' declares no field '{fieldName}'.");
        }

        WriteFieldDesc(modulePointer, field.Token, enclosing, objectRelativeOffset);
    }

    private void WriteFieldDesc(ulong modulePointer, int token, ulong enclosing, int objectRelativeOffset)
    {
        ulong fieldDesc = Alloc(FieldDescStride);
        int stored = objectRelativeOffset - ObjectHeaderSize;

        switch (Style)
        {
            case FieldDescStyle.CoreClrLike:
                _builder.WriteU64(fieldDesc, enclosing);
                _builder.WriteU32(fieldDesc + 8, (uint)(token & 0x00FF_FFFF));

                // Offset in the low 27 bits, a non-zero element type above it so the calibrator
                // has a real bitfield boundary to find rather than a word of zeroes.
                _builder.WriteU32(fieldDesc + 12, (uint)stored | (0x12u << 27));
                break;

            case FieldDescStyle.Alternate:
                _builder.WriteI32(fieldDesc + 8, checked((int)((long)enclosing - (long)(fieldDesc + 8))));
                _builder.WriteU32(fieldDesc + 16, (uint)(token & 0x00FF_FFFF));
                _builder.WriteU32(fieldDesc + 20, ((uint)stored << 5) | 0x1F);
                break;

            default:
                throw new InvalidOperationException($"unknown style {Style}");
        }

        // Alloc is 16-byte aligned, so flags in the low three bits are recoverable — which is
        // the property FieldDescEncoding.EntryMask is derived against.
        int rid = token & 0x00FF_FFFF;
        ulong slot = _moduleTables[modulePointer].FieldTable + ((ulong)rid * 8);
        _builder.WriteU64(slot, fieldDesc | (ulong)(uint)_options.FieldMapEntryFlags);

        if (SampleFieldMapSlot == 0) SampleFieldMapSlot = slot;
    }

    /// <summary>
    /// One <c>FieldDefToDescMap</c> slot the fixture wrote, so a test can read the raw entry
    /// back and confirm it really carries <see cref="SyntheticTargetOptions.FieldMapEntryFlags"/>
    /// rather than trusting the option was honoured.
    /// </summary>
    public ulong SampleFieldMapSlot { get; private set; }

    private ulong Alloc(int size)
    {
        ulong address = _next;
        _next = (_next + (ulong)size + 15) & ~15UL;
        _builder.Reserve(address, size + 64);
        return address;
    }
}
