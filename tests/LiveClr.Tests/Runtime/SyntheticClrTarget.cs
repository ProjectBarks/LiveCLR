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
/// <para>
/// <b>Footnote, for whoever changes these next: the width theory has ONE load-bearing row, not
/// two.</b> <see cref="Alternate"/> packs the offset flush against the top of the word — bits
/// [5, 32) — so there IS no bit above the offset field for a too-wide window to swallow, and
/// its width is pinned by the word boundary whatever the calibration does. Only
/// <see cref="CoreClrLike"/>, whose 27-bit field has <c>m_type</c> sitting above it, can detect
/// a width bug at all. Two styles prove the position is DERIVED rather than recognised; they do
/// not double the evidence for the width. Nothing here needs changing — this is a note about
/// what the row is worth, so that deleting the CoreClrLike row later is understood as removing
/// the width test entirely.
/// </para>
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

    /// <summary>
    /// What <c>EEClass.InternalCorElementType</c> holds for <c>System.String</c>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The default is what a live .NET 9 runtime actually writes, which is not
    /// <c>ELEMENT_TYPE_STRING</c>.</b> Measured over a running CoreCLR 9 process (§17):
    /// <c>System.String</c>'s <c>EEClass</c> reports <c>ELEMENT_TYPE_CLASS</c> (0x12), and across
    /// all 12,283 loaded method tables <c>ELEMENT_TYPE_STRING</c> never appears once. This
    /// fixture previously wrote <c>ELEMENT_TYPE_STRING</c> here — the value the production code
    /// was looking for — so the fixture and the code encoded the same false premise and agreed
    /// with each other for free, which is §13.11 species 1 in its fixture-versus-reality form:
    /// the tests could fail, they simply described a runtime that does not exist.
    /// </para>
    /// <para>
    /// It stays configurable because "what CoreCLR stores in the norm type" is a per-runtime fact
    /// rather than a law, and a test that needs the other spelling should be able to ask for it
    /// and say so in its name — see the tests that pass <see cref="ClrElementType.String"/>.
    /// </para>
    /// </remarks>
    public ClrElementType StringInternalCorElementType { get; init; } = ClrElementType.Class;

    /// <summary>
    /// Give an ordinary app class an <c>EEClass</c> that claims <c>ELEMENT_TYPE_STRING</c>.
    /// </summary>
    /// <remarks>
    /// The hostile counterpart of <see cref="StringInternalCorElementType"/>: a type that is not
    /// <c>System.String</c>, does not have String's method table and has no component size, but
    /// whose norm type says otherwise. A reader that believes the norm type decodes the object's
    /// first fields as a length and a character run, which fabricates a string out of a live
    /// object rather than refusing.
    /// </remarks>
    public bool ImpersonateStringElementType { get; init; }

    /// <summary>
    /// Give generic instantiations a shared canonical method table that no TypeDef row maps to —
    /// CoreCLR's <c>List&lt;__Canon&gt;</c> — instead of pointing them at the typical
    /// instantiation the TypeDef map holds.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>This is the live shape, and the default is not.</b> Measured on the same .NET 9 process
    /// (§17): 75 of 555 objects reached in a live walk have a method table that resolves to no
    /// TypeDef row at all, and 9 slots whose ECMA-335 signature declares
    /// <c>List&lt;T&gt;</c> produced an object the type system could only call
    /// <c>&lt;mt:0x…&gt;</c>. So <see cref="ClrTypeInfo.IsList"/>, which is a name-prefix match,
    /// is false for every live <c>List&lt;T&gt;</c> instance, and <c>AsList()</c> returns null on
    /// a real target.
    /// </para>
    /// <para>
    /// The default keeps the older, unreal shape — canonical <em>is</em> the mapped typical
    /// instantiation — because that is what the existing <c>ClrList</c> tests need in order to
    /// exercise counting, clamping and torn lists at all. Those tests are honest about what they
    /// cover: list DECODING given a named list type. What they cannot cover, and what
    /// <c>GenericInstantiationsAreNotNamedOnALiveShapedTarget</c> pins instead, is list
    /// IDENTIFICATION on the shape a runtime actually produces.
    /// </para>
    /// </remarks>
    public bool SharedCanonicalInstantiation { get; init; }

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

    /// <summary>
    /// Synthesise the .NET 9 statics chain: <c>MTFlags2</c>, <c>m_pAuxiliaryData</c>,
    /// <c>DynamicStaticsInfo</c> and static <c>FieldDesc</c>s (§14).
    /// </summary>
    /// <remarks>
    /// Off by default, and deliberately: a fixture with no statics chain is what a caller who has
    /// to supply <see cref="ExplicitStaticRootSource"/> sees, so the tests that predate this keep
    /// exercising that path unchanged rather than being quietly rerouted through the runtime one.
    /// </remarks>
    public bool WithStatics { get; init; }

    /// <summary>
    /// Where <c>m_pAuxiliaryData</c> sits in the method table. CoreCLR 9 uses 32; a test builds a
    /// target that uses something else, because a calibration that only ever sees 32 proves
    /// nothing about whether the slot is DERIVED.
    /// </summary>
    public int AuxiliarySlot { get; init; } = 32;

    /// <summary>
    /// Which <c>MTFlags2</c> bit means "has a <c>DynamicStaticsInfo</c>". CoreCLR 9 uses bit 1
    /// (<c>0x0002</c>), which §14.0 stresses is NOT descriptor-published.
    /// </summary>
    public int StaticsFlagBit { get; init; } = 1;

    /// <summary>Which <c>FieldDesc</c> bit marks a thread-local static. CoreCLR 9 uses bit 25.</summary>
    public int ThreadStaticBitIndex { get; init; } = 25;

    /// <summary>
    /// Swap the two <c>DynamicStaticsInfo</c> pointers, so <c>m_pGCStatics</c> is the second
    /// member rather than the first. A reader that assumes the declared order gets a base that
    /// produces addresses rather than errors.
    /// </summary>
    public bool GcStaticsSecond { get; init; }

    /// <summary>
    /// Make <c>EEClassOrCanonMT</c> at slot 40 satisfy the back-pointer anchor too, on every
    /// statics-bearing type and on some without.
    /// </summary>
    /// <remarks>
    /// §14.0's correction 1 in fixture form. 26 real types alias the anchor this way and a
    /// per-type sweep picks the wrong slot for four of them; the fixture aliases far more, so a
    /// derivation that resolved ambiguity by preference rather than by unanimity would have to
    /// choose — and would be caught choosing.
    /// </remarks>
    public bool AliasEEClassSlot { get; init; } = true;

    /// <summary>
    /// Point <c>DynamicStaticsInfo.m_pMethodTable</c> at something other than its own method
    /// table, so the anchor cannot close.
    /// </summary>
    public bool BreakStaticsAnchor { get; init; }

    /// <summary>
    /// Break the anchor on exactly ONE statics-bearing type, leaving the derivation to converge
    /// normally.
    /// </summary>
    /// <remarks>
    /// Models a torn or stale <c>m_pAuxiliaryData</c>: the gate still says the type has statics,
    /// and the two pointers below the auxiliary data still look like bases. Only the back-pointer
    /// disagrees — which is the entire reason §14.2 calls it an anchor.
    /// </remarks>
    public bool BreakOneStaticsAnchor { get; init; }

    /// <summary>
    /// Give one static <c>FieldDesc</c> a back-pointer to a different method table, as a stale or
    /// out-of-range <c>FieldDefToDescMap</c> entry would (§5.4).
    /// </summary>
    public bool MisattributeOneStaticFieldDesc { get; init; }

    /// <summary>
    /// Write <c>m_pAuxiliaryData</c> into a SECOND method-table slot as well, so two slots satisfy
    /// the anchor on exactly the same types.
    /// </summary>
    /// <remarks>
    /// Unlike <see cref="AliasEEClassSlot"/>, which the corpus can tell apart because the alias
    /// does not track the gate, this ambiguity is genuine: nothing in the target distinguishes the
    /// two slots. The only correct answer is to refuse, which is the same stance
    /// <c>FieldDescCalibration</c> takes when two bitfield positions reproduce every anchor.
    /// </remarks>
    public int DuplicateAuxiliarySlot { get; init; } = -1;
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
    private const int MtFlags2 = 8;
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

            if (_options.WithStatics) DefineStaticsCorpus(coreLibMetadata);
            if (_options.BreakOneStaticsAnchor) BreakAnchorOnHolder(appMetadata);

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

            // "globals.X" removes a published global, the same spelling ClrLayouts.RequiredEntries
            // uses. A runtime is free to publish fewer globals than ours does (§5.5), and
            // string identity now depends on one of them.
            JsonObject? holder = string.Equals(parts[0], "globals", StringComparison.Ordinal)
                ? root["globals"]?.AsObject()
                : root["types"]?[parts[0]]?.AsObject();

            if (holder is null || parts.Length != 2 || !holder.Remove(parts[1]))
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

    /// <summary>
    /// <c>List&lt;__Canon&gt;</c>: shared by every reference-type instantiation, reachable only
    /// through <c>EEClassOrCanonMT</c>, and in no TypeDef map. Zero unless
    /// <see cref="SyntheticTargetOptions.SharedCanonicalInstantiation"/> asked for the live shape.
    /// </summary>
    private ulong _sharedCanonicalMethodTable;

    private void DefineCoreLibTypes(ModuleMetadata metadata)
    {
        _objectMethodTable = DefineType(CoreLibModulePointer, metadata, "System.Object", 0, 24, 0, ClrElementType.Class);

        // §5.2 fixes System.String's stride at 2 (m_FirstChar is UTF-16). Writing anything else
        // is what a runtime whose MTFlags encoding this reader does not understand looks like.
        int stringStride = _options.BreakComponentSizeEncoding ? 3 : 2;

        // The norm type is what the RUNTIME writes, not what a reader hopes to find:
        // ELEMENT_TYPE_CLASS, measured (§17). See StringInternalCorElementType.
        _stringMethodTable = DefineType(
            CoreLibModulePointer,
            metadata,
            "System.String",
            _objectMethodTable,
            22,
            stringStride,
            _options.StringInternalCorElementType);

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

        // On a live runtime the FieldDescs of a shared generic hang off List<__Canon>, not off
        // the typical instantiation, so the live-shaped fixture puts them there too.
        if (_options.SharedCanonicalInstantiation)
        {
            _sharedCanonicalMethodTable = DefineMethodTable(
                CoreLibModulePointer, _objectMethodTable, 32, 0, ClrElementType.Class, perInstInfo: 0);
        }

        ulong listFieldOwner = _sharedCanonicalMethodTable == 0 ? _listCanonicalMethodTable : _sharedCanonicalMethodTable;
        DefineFieldDesc(CoreLibModulePointer, metadata, "System.Collections.Generic.List`1", "_items", listFieldOwner, 8, 29);
        DefineFieldDesc(CoreLibModulePointer, metadata, "System.Collections.Generic.List`1", "_size", listFieldOwner, 16, 8);

        // System.String's own fields, at the offsets §5.2 publishes for them. _firstChar is a
        // Char (3, odd) — more real data for the width measurement.
        DefineFieldDesc(CoreLibModulePointer, metadata, "System.String", "_stringLength", _stringMethodTable, StringLength, 8);
        DefineFieldDesc(CoreLibModulePointer, metadata, "System.String", "_firstChar", _stringMethodTable, StringFirstChar, 3);
    }

    private void DefineExceptionFieldDescs(ModuleMetadata metadata, ulong exceptionMethodTable)
    {
        TypeDefinitionHandle handle = metadata.Types.ResolveType("System.Exception")
            ?? throw new InvalidOperationException("CoreLib defines no System.Exception.");

        PublishedExceptionFields = 0;
        int filler = 0;

        foreach (MetadataField field in metadata.Types.GetFields(handle))
        {
            if (field.IsStatic || field.IsLiteral) continue;

            if (ExceptionOffsets.TryGetValue(field.Name, out (int Offset, int ElementType) published))
            {
                if (PublishedExceptionFields >= _options.ExceptionFieldLimit) continue;

                // One field stored where the descriptor says it is not: no single bitfield
                // position can then reproduce every published offset, which must end in refusal.
                bool corrupt = _options.CorruptOneExceptionOffset && PublishedExceptionFields == 1;

                WriteFieldDesc(
                    CoreLibModulePointer,
                    field.Token,
                    exceptionMethodTable,
                    corrupt ? published.Offset + 4 : published.Offset,
                    published.ElementType);

                PublishedExceptionFields++;
                continue;
            }

            // System.Exception's REMAINING instance fields. They are not anchors — the descriptor
            // says nothing about them — but they are exactly what the width measurement needs:
            // real descriptors with ODD element types, which the eight published anchors never
            // have. Offsets are synthetic but distinct and inside BaseSize, which is all the
            // BaseSize test requires of them.
            if (filler >= FillerOffsets.Length) continue;

            WriteFieldDesc(
                CoreLibModulePointer,
                field.Token,
                exceptionMethodTable,
                FillerOffsets[filler] + ObjectHeaderSize,
                OddElementTypes[filler % OddElementTypes.Length]);

            filler++;
        }
    }

    /// <summary>How many calibration samples the fixture actually managed to lay down.</summary>
    public int PublishedExceptionFields { get; private set; }

    /// <summary>
    /// The offsets this fixture WROTE, for tests that need to damage a specific field.
    /// </summary>
    /// <remarks>
    /// The same argument as the private constants above, applied one level out. A test that
    /// unmaps <c>methodTable + process.Layouts.MethodTableParentOffset</c> is asking production
    /// where it reads and then damaging exactly that — so it passes whatever the offset is,
    /// including a wrong one, and proves only that production is self-consistent. These say
    /// where the BYTES ARE; if the two ever disagree the test fails, which is the point.
    /// </remarks>
    public static class WrittenAt
    {
        public const int MethodTableBaseSize = MtBaseSize;
        public const int MethodTableParent = MtParent;
        public const int EEClassInternalCorElementType = EEClassElementType;
    }

    /// <summary>
    /// The <c>Exception</c> offsets the shipped descriptor publishes (§5.2), with the element
    /// type CoreCLR stores beside each.
    /// </summary>
    /// <remarks>
    /// <b>Every one of these element types is EVEN, and that is the whole point.</b> Live
    /// validation traced a wrong calibrated width to exactly this: with <c>CLASS</c> = 18 and
    /// <c>I4</c> = 8, the bit directly above the offset field is zero in all eight anchors, so
    /// they cannot distinguish the true width from one bit wider. The fixture reproduces that
    /// blind spot faithfully rather than papering over it — a calibrator that only works because
    /// the fixture happened to include an odd anchor would be proving nothing.
    /// </remarks>
    private static readonly Dictionary<string, (int Offset, int ElementType)> ExceptionOffsets =
        new(StringComparer.Ordinal)
        {
            ["_message"] = (16, 18),
            ["_innerException"] = (32, 18),
            ["_stackTrace"] = (48, 18),
            ["_watsonBuckets"] = (56, 18),
            ["_stackTraceString"] = (64, 18),
            ["_remoteStackTraceString"] = (72, 18),
            ["_xcode"] = (104, 8),
            ["_HResult"] = (108, 8),
        };

    /// <summary>Slots inside <c>System.Exception</c>'s BaseSize that the published fields do not use.</summary>
    private static readonly int[] FillerOffsets = [0, 4, 12, 20, 28, 36, 44, 52, 60, 68, 76, 84];

    /// <summary>
    /// <c>Char</c>, <c>U1</c>, <c>U2</c>, <c>U4</c>, <c>U8</c>, <c>R8</c>, <c>VALUETYPE</c>,
    /// <c>SZARRAY</c> — the odd element types whose low bit a too-wide offset window swallows.
    /// </summary>
    private static readonly int[] OddElementTypes = [3, 5, 7, 9, 11, 13, 17, 29];

    // ---------------------------------------------------------------- app types and heap

    private void DefineAppTypes(ModuleMetadata app)
    {
        ulong baseMt = DefineType(AppModulePointer, app, typeof(FixtureBase).FullName!, _objectMethodTable, 24, 0, ClrElementType.Class);
        ulong derivedMt = DefineType(
            AppModulePointer,
            app,
            typeof(FixtureDerived).FullName!,
            baseMt,
            48,
            0,
            _options.ImpersonateStringElementType ? ClrElementType.String : ClrElementType.Class);
        ulong holderMt = DefineType(AppModulePointer, app, typeof(FixtureHolder).FullName!, _objectMethodTable, 24, 0, ClrElementType.Class);

        DerivedMethodTable = derivedMt;
        _holderMethodTable = holderMt;

        // Element types are per field, exactly as the runtime stores them. Note Numbers (SZARRAY
        // 29) and Position (VALUETYPE 17) are ODD: a FieldDesc window one bit too wide decodes
        // both as offset + 0x8000000, so these two fields are a live regression guard for the
        // width the calibration derives.
        DefineFieldDesc(AppModulePointer, app, typeof(FixtureBase).FullName!, nameof(FixtureBase.Hp), baseMt, 8, 8);
        DefineFieldDesc(AppModulePointer, app, typeof(FixtureDerived).FullName!, nameof(FixtureDerived.Name), derivedMt, 16, 14);
        DefineFieldDesc(AppModulePointer, app, typeof(FixtureDerived).FullName!, nameof(FixtureDerived.Link), derivedMt, 24, 18);
        DefineFieldDesc(AppModulePointer, app, typeof(FixtureDerived).FullName!, nameof(FixtureDerived.Position), derivedMt, 32, 17);
        DefineFieldDesc(AppModulePointer, app, typeof(FixtureHolder).FullName!, nameof(FixtureHolder.Items), holderMt, 8, 18);
        DefineFieldDesc(AppModulePointer, app, typeof(FixtureHolder).FullName!, nameof(FixtureHolder.Numbers), holderMt, 16, 29);

        ulong derivedArrayMt = DefineArrayType(CoreLibModulePointer, _objectMethodTable, 8, derivedMt);
        ulong intArrayMt = DefineArrayType(CoreLibModulePointer, _objectMethodTable, 4, 0);

        // List<FixtureDerived>: a distinct method table whose EEClassOrCanonMT points at the
        // canonical List<T>, which is how a generic instantiation reaches its field layout.
        // Which method table is "canonical" is the whole question — see
        // SyntheticTargetOptions.SharedCanonicalInstantiation for what a live runtime does.
        ulong listCanonical = _sharedCanonicalMethodTable == 0 ? _listCanonicalMethodTable : _sharedCanonicalMethodTable;
        ulong listMt = DefineInstantiatedType(CoreLibModulePointer, listCanonical, _objectMethodTable, 32);

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
        ulong obj = Alloc(48);
        _builder.WriteU64(obj, methodTable);
        _builder.WriteI32(obj + 8, hp);
        _builder.WriteU64(obj + 16, name);
        _builder.WriteU64(obj + 24, link);

        // Inline struct, stored in place rather than behind a reference.
        _builder.WriteI32(obj + 32, hp * 2);
        _builder.WriteI32(obj + 36, hp * 3);
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

    // ---------------------------------------------------------------- statics (§14)

    /// <summary>Bit pattern stamped into every <c>MTFlags2</c>, so the gate bit is not the only one set.</summary>
    /// <remarks>
    /// A fixture where the statics types are the only ones with ANY flag bit would let the
    /// derivation succeed on a bit it never really discriminated. These are set on statics-bearing
    /// and statics-free types alike, so no bit but the real one can predict the anchor.
    /// </remarks>
    private const uint Flags2Noise = 0x0001_8005;

    /// <summary>A plausible-looking pointer to nothing. Fills the blob the reader must NOT choose.</summary>
    private const ulong DecoyPointer = 0x0000_0000_DEAD_BEE0;

    /// <summary>Statics-bearing CoreLib types the fixture synthesised, by full name.</summary>
    public IReadOnlyDictionary<string, StaticsFixtureType> StaticsTypes => _staticsTypes;

    private readonly Dictionary<string, StaticsFixtureType> _staticsTypes = new(StringComparer.Ordinal);

    /// <summary>What the fixture wrote for one statics-bearing type, so tests can check addresses.</summary>
    /// <param name="MethodTable">Its method table.</param>
    /// <param name="GcStatics">Base of the blob holding its reference statics.</param>
    /// <param name="NonGcStatics">Base of the blob holding its primitive statics.</param>
    /// <param name="Offsets">Blob offset written into each field's <c>FieldDesc</c>, by field name.</param>
    internal sealed record StaticsFixtureType(
        ulong MethodTable,
        ulong GcStatics,
        ulong NonGcStatics,
        IReadOnlyDictionary<string, int> Offsets);

    /// <summary>Name of the CoreLib type whose class initialiser the fixture says never ran.</summary>
    public string? UninitializedStaticsType { get; private set; }

    /// <summary>Name of the open generic definition the fixture gave storage-less statics.</summary>
    public string? GenericStaticsType { get; private set; }

    /// <summary>A <c>[ThreadStatic]</c> field, as "Type.Field", that must be refused.</summary>
    public string? ThreadStaticField { get; private set; }

    /// <summary>The object a thread static's slot would resolve to if the guard were removed.</summary>
    public ulong ThreadStaticDecoyObject { get; private set; }

    /// <summary>Object every reference static in the fixture's statics corpus points at.</summary>
    public ulong StaticsTargetObject { get; private set; }

    /// <summary>
    /// Lays down the .NET 9 statics chain over real CoreLib types, plus an anchor corpus large
    /// enough for the derivation's unanimity floors.
    /// </summary>
    private void DefineStaticsCorpus(ModuleMetadata coreLib)
    {
        StaticsTargetObject = DefineString("StaticsCorpusTarget");
        ThreadStaticDecoyObject = DefineString("ThreadStaticDecoy");

        var used = new HashSet<int>(_coreLibTypeRids);

        foreach (CoreLibStatics.PlannedType planned in CoreLibStatics.ThreadStaticCarriers)
        {
            if (!used.Add(planned.Rid)) continue;
            DefineStaticsCarrier(coreLib, planned, initialized: true, storageLess: false);
            ThreadStaticField ??= FirstThreadStaticName(planned);
        }

        bool markedUninitialized = false;
        foreach (CoreLibStatics.PlannedType planned in CoreLibStatics.ReferenceCarriers)
        {
            if (!used.Add(planned.Rid)) continue;

            // One type whose statics exist but whose class initialiser never ran: §14.0 insists
            // that is a different state from "the field is null".
            bool initialized = markedUninitialized || Array.TrueForAll(planned.Fields, f => !f.IsReference);
            if (!initialized) { markedUninitialized = true; UninitializedStaticsType = planned.Name; }

            DefineStaticsCarrier(coreLib, planned, initialized, storageLess: false, allowMisattribution: initialized);
        }

        if (CoreLibStatics.GenericCarrier is CoreLibStatics.PlannedType generic && used.Add(generic.Rid))
        {
            // §14.0, correction 3: an open generic definition's raw bases read exactly 1, so the
            // masked base is zero and the instantiation's method table is what a caller needs.
            DefineStaticsCarrier(coreLib, generic, initialized: false, storageLess: true);
            GenericStaticsType = generic.Name;
        }

        if (CoreLibStatics.RvaCarrier is CoreLibStatics.PlannedType rva && used.Add(rva.Rid))
        {
            DefineStaticsCarrier(coreLib, rva, initialized: true, storageLess: false);
            RvaStaticsType = rva.Name;
            RvaStaticField = rva.RvaFields[0];
        }

        DefineAnchorCorpus(coreLib, used);
    }

    /// <summary>Each statics-bearing method table's <c>m_pAuxiliaryData</c>, so it can be damaged.</summary>
    private readonly Dictionary<ulong, ulong> _auxiliaryOf = [];

    /// <summary>Method table of <see cref="FixtureHolder"/>, the app-module statics carrier.</summary>
    private ulong _holderMethodTable;

    /// <summary>
    /// Give <see cref="FixtureHolder"/> a statics chain whose back-pointer names the wrong method
    /// table.
    /// </summary>
    /// <remarks>
    /// <b>In the app module, deliberately.</b> The derivation walks CoreLib and demands UNANIMITY,
    /// so a CoreLib type that fails the anchor refuses statics for the whole process — which is
    /// the intended behaviour (a type that disagrees means the model is wrong, not that one read
    /// was unlucky) but leaves no way to exercise the per-field anchor check while calibrated.
    /// Breaking a type the derivation never sees separates the two.
    /// </remarks>
    private void BreakAnchorOnHolder(ModuleMetadata app)
    {
        TypeDefinitionHandle handle = app.Types.ResolveType(typeof(FixtureHolder).FullName!)
            ?? throw new InvalidOperationException("the fixture assembly defines no FixtureHolder.");

        if (!app.Types.TryGetField(handle, nameof(FixtureHolder.Instance), out MetadataField field))
        {
            throw new InvalidOperationException("FixtureHolder declares no Instance.");
        }

        (ulong gcBase, _) = DefineStatics(_holderMethodTable, gcSlots: 1, nonGcSlots: 1, initialized: true, storageLess: false);
        _builder.WriteU64(gcBase, HolderAddress);
        WriteStaticFieldDesc(
            AppModulePointer, field.Token, _holderMethodTable, blobOffset: 0, (int)ClrElementType.Class, threadStatic: false);

        _builder.WriteU64(_auxiliaryOf[_holderMethodTable] - 8, _holderMethodTable + 0x40);

        BrokenAnchorType = typeof(FixtureHolder).FullName;
        BrokenAnchorField = nameof(FixtureHolder.Instance);
    }

    /// <summary>Name of the one type whose back-pointer anchor was deliberately broken.</summary>
    public string? BrokenAnchorType { get; private set; }

    /// <summary>Its static field, which the gate and the bases would both have answered for.</summary>
    public string? BrokenAnchorField { get; private set; }

    /// <summary>Name of the CoreLib type carrying <see cref="RvaStaticField"/>.</summary>
    public string? RvaStaticsType { get; private set; }

    /// <summary>An RVA static, which has no descriptor here and must be refused on metadata alone.</summary>
    public string? RvaStaticField { get; private set; }

    /// <summary>A boxed value-type static, as "Type.Field" — the slot holds a reference (§14.0).</summary>
    public string? BoxedStaticType { get; private set; }

    /// <summary>Field name of <see cref="BoxedStaticType"/>'s boxed static.</summary>
    public string? BoxedStaticField { get; private set; }

    /// <summary>The value inside that box, which is what a caller must get back — not the pointer.</summary>
    public const long ExpectedBoxedStatic = 0x0123_4567_89AB_CDEF;

    /// <summary>Gate-set and gate-clear method tables in bulk, so the derivation has a population.</summary>
    /// <remarks>
    /// The derivation requires unanimity over at least 100 types on each side, which is §14.0's
    /// own bar. The gate-CLEAR half is not padding: without negatives, "the anchor always closes"
    /// and "this bit is always set" agree vacuously.
    /// </remarks>
    private void DefineAnchorCorpus(ModuleMetadata coreLib, HashSet<int> used)
    {
        const int PerSide = 160;
        const int AliasedGateClear = 24;

        int rid = coreLib.Reader.TypeDefinitions.Count;
        int gateSet = 0, gateClear = 0;

        while (rid > 1 && (gateSet < PerSide || gateClear < PerSide))
        {
            int candidate = rid--;
            if (!used.Add(candidate)) continue;

            ulong methodTable = DefineTypeAtRid(CoreLibModulePointer, candidate);

            if (gateSet < PerSide)
            {
                DefineStatics(methodTable, gcSlots: 0, nonGcSlots: 0, initialized: true, storageLess: false);
                gateSet++;
                continue;
            }

            _builder.WriteU32(methodTable + MtFlags2, Flags2Noise);

            // Some gate-CLEAR types alias the anchor at slot 40 as well. That is what makes the
            // aliased slot fail unanimity rather than merely lose on a count.
            if (_options.AliasEEClassSlot && gateClear < AliasedGateClear) AliasEEClass(methodTable);

            gateClear++;
        }
    }

    private static string? FirstThreadStaticName(CoreLibStatics.PlannedType planned)
    {
        foreach (CoreLibStatics.PlannedField field in planned.Fields)
        {
            if (field.IsThreadStatic) return $"{planned.Name}.{field.Name}";
        }

        return null;
    }

    /// <summary>One CoreLib type with a real statics blob and real static <c>FieldDesc</c>s.</summary>
    private void DefineStaticsCarrier(
        ModuleMetadata coreLib,
        CoreLibStatics.PlannedType planned,
        bool initialized,
        bool storageLess,
        bool allowMisattribution = false)
    {
        ulong methodTable = DefineTypeAtRid(CoreLibModulePointer, planned.Rid);

        int gcSlots = 1, nonGcSlots = 1;
        foreach (CoreLibStatics.PlannedField field in planned.Fields)
        {
            if (field.IsReference) gcSlots++;
            else nonGcSlots++;
        }

        (ulong gcBase, ulong nonGcBase) = DefineStatics(
            methodTable, gcSlots, nonGcSlots, initialized, storageLess);

        var offsets = new Dictionary<string, int>(StringComparer.Ordinal);
        int gcOffset = 0, nonGcOffset = 0;

        foreach (CoreLibStatics.PlannedField field in planned.Fields)
        {
            // Exactly one value-type static in the whole fixture is stored BOXED, as every real
            // one is. Its slot holds a reference, so a reader that hands the slot straight back
            // reports the box POINTER as the value — §14.0's DateTime.MinValue in miniature.
            bool boxed = !field.IsReference && !storageLess && initialized && BoxedStaticField is null;
            if (boxed)
            {
                BoxedStaticType = planned.Name;
                BoxedStaticField = field.Name;
            }

            int offset;
            if (field.IsReference || boxed)
            {
                offset = gcOffset;
                gcOffset += 8;

                // A thread static's slot is deliberately loaded with a REAL object. Removing the
                // refusal must therefore hand back a plausible answer rather than an obvious
                // failure — which is the whole shape of §14.0's correction 2.
                if (!storageLess)
                {
                    _builder.WriteU64(
                        gcBase + (ulong)offset,
                        boxed ? DefineBox(ExpectedBoxedStatic)
                        : field.IsThreadStatic ? ThreadStaticDecoyObject
                        : StaticsTargetObject);
                }
            }
            else
            {
                offset = nonGcOffset;
                nonGcOffset += 8;
                if (!storageLess) _builder.WriteU64(nonGcBase + (ulong)offset, unchecked((ulong)ExpectedPrimitiveStatic));
            }

            offsets[field.Name] = offset;

            // One descriptor in the fixture points back at a DIFFERENT method table, so the
            // declaring-type cross-check has something to catch.
            ulong declaring = methodTable;
            if (_options.MisattributeOneStaticFieldDesc &&
                MisattributedStaticField is null &&
                allowMisattribution &&
                field.IsReference &&
                !field.IsThreadStatic)
            {
                MisattributedStaticType = planned.Name;
                MisattributedStaticField = field.Name;
                declaring = _objectMethodTable;
            }

            WriteStaticFieldDesc(
                CoreLibModulePointer,
                field.Token,
                declaring,
                offset,
                boxed ? (int)ClrElementType.ValueType
                    : field.IsReference ? (int)ClrElementType.Class
                    : (int)ClrElementType.Int64,
                field.IsThreadStatic);
        }

        _staticsTypes[planned.Name] = new StaticsFixtureType(methodTable, gcBase, nonGcBase, offsets);
        _ = coreLib;
    }

    /// <summary>Name of the type whose descriptor was deliberately misattributed.</summary>
    public string? MisattributedStaticType { get; private set; }

    /// <summary>Field whose <c>FieldDesc</c> claims a different declaring method table.</summary>
    public string? MisattributedStaticField { get; private set; }

    /// <summary>A boxed <c>long</c>: a method table and eight bytes of payload.</summary>
    private ulong DefineBox(long value)
    {
        ulong box = Alloc(ObjectHeaderSize + 8);
        _builder.WriteU64(box, _objectMethodTable);
        _builder.WriteU64(box + ObjectHeaderSize, unchecked((ulong)value));
        return box;
    }

    /// <summary>Value written into every primitive static slot, so a test can recognise a good read.</summary>
    public const long ExpectedPrimitiveStatic = 0x0BAD_F00D_1234_5678;

    /// <summary>
    /// Attach <c>MTFlags2</c>, <c>m_pAuxiliaryData</c> and a <c>DynamicStaticsInfo</c> to a method
    /// table, laid out exactly as §14.1 describes.
    /// </summary>
    private (ulong GcBase, ulong NonGcBase) DefineStatics(
        ulong methodTable, int gcSlots, int nonGcSlots, bool initialized, bool storageLess)
    {
        _builder.WriteU32(methodTable + MtFlags2, Flags2Noise | (1u << _options.StaticsFlagBit));

        ulong gcBase = gcSlots > 0 ? Alloc(gcSlots * 8) : 0;
        ulong nonGcBase = nonGcSlots > 0 ? Alloc(nonGcSlots * 8) : 0;

        // The blob the reader must NOT pick is filled with plausible-looking pointers to nothing,
        // so choosing it produces garbage rather than the zeroes that would flatter it.
        for (int i = 0; i < gcSlots; i++) _builder.WriteU64(nonGcBase + ((ulong)i * 8), DecoyPointer);
        for (int i = 0; i < nonGcSlots && i * 8 < gcSlots * 8; i++) _builder.WriteU64(gcBase + ((ulong)i * 8), DecoyPointer);

        // DynamicStaticsInfo occupies the three pointers BELOW m_pAuxiliaryData.
        ulong auxiliary = Alloc(64, prefix: 24);

        ulong gcStored = storageLess ? 1 : gcBase | (initialized ? 0UL : 1UL);
        ulong nonGcStored = storageLess ? 1 : nonGcBase | (initialized ? 0UL : 1UL);

        _builder.WriteU64(auxiliary - 24, _options.GcStaticsSecond ? nonGcStored : gcStored);
        _builder.WriteU64(auxiliary - 16, _options.GcStaticsSecond ? gcStored : nonGcStored);
        _builder.WriteU64(auxiliary - 8, _options.BreakStaticsAnchor ? methodTable + 0x40 : methodTable);
        _builder.WriteU64(methodTable + (ulong)_options.AuxiliarySlot, auxiliary);
        _auxiliaryOf[methodTable] = auxiliary;

        if (_options.DuplicateAuxiliarySlot >= 0)
        {
            _builder.WriteU64(methodTable + (ulong)_options.DuplicateAuxiliarySlot, auxiliary);
        }

        if (_options.AliasEEClassSlot) AliasEEClass(methodTable);

        return (gcBase, nonGcBase);
    }

    /// <summary>Make slot 40's target satisfy the back-pointer test, as 26 real types do (§14.0).</summary>
    private void AliasEEClass(ulong methodTable)
    {
        if (!_eeClassOf.TryGetValue(methodTable, out ulong eeClass)) return;
        _builder.WriteU64(eeClass - 8, methodTable);
    }

    /// <summary>Each method table's <c>EEClass</c>, so the slot-40 alias can be written to it.</summary>
    private readonly Dictionary<ulong, ulong> _eeClassOf = [];

    /// <summary>
    /// A method table registered at a metadata rid, without asking metadata for the name.
    /// </summary>
    /// <remarks>
    /// The anchor corpus needs a POPULATION, not identities; going through a name lookup for each
    /// of 350 types would cost a full-name index walk per entry and buy nothing.
    /// </remarks>
    private ulong DefineTypeAtRid(ulong modulePointer, int rid)
    {
        ulong methodTable = DefineMethodTable(
            modulePointer, _objectMethodTable, baseSize: 24, componentSize: 0, ClrElementType.Class, perInstInfo: 0);

        _builder.WriteU64(_moduleTables[modulePointer].TypeTable + ((ulong)rid * 8), methodTable);
        if (modulePointer == CoreLibModulePointer) _coreLibTypeRids.Add(rid);

        return methodTable;
    }

    /// <summary>
    /// One static <c>FieldDesc</c>: a BLOB offset rather than an object-relative one, plus the
    /// runtime's static and thread-static marker bits.
    /// </summary>
    private void WriteStaticFieldDesc(
        ulong modulePointer, int token, ulong enclosing, int blobOffset, int elementType, bool threadStatic)
    {
        ulong fieldDesc = Alloc(FieldDescStride);
        uint type = (uint)elementType & 0x1F;

        // Where the marker bits live is not published either, so a build can move them and the
        // derivation has to follow.
        uint markers = 1u << StaticBitIndex;
        if (threadStatic) markers |= 1u << _options.ThreadStaticBitIndex;

        switch (Style)
        {
            case FieldDescStyle.CoreClrLike:
                _builder.WriteU64(fieldDesc, enclosing);
                _builder.WriteU32(fieldDesc + 8, (uint)(token & 0x00FF_FFFF) | markers);
                _builder.WriteU32(fieldDesc + 12, (uint)blobOffset | (type << 27));
                break;

            case FieldDescStyle.Alternate:
                _builder.WriteI32(fieldDesc + 8, checked((int)((long)enclosing - (long)(fieldDesc + 8))));
                _builder.WriteU32(fieldDesc + 16, (uint)(token & 0x00FF_FFFF) | markers);
                _builder.WriteU32(fieldDesc + 20, ((uint)blobOffset << 5) | type);
                break;

            default:
                throw new InvalidOperationException($"unknown style {Style}");
        }

        int rid = token & 0x00FF_FFFF;
        _builder.WriteU64(
            _moduleTables[modulePointer].FieldTable + ((ulong)rid * 8),
            fieldDesc | (ulong)(uint)_options.FieldMapEntryFlags);
    }

    /// <summary>CoreCLR's own <c>m_isStatic</c> position; nothing here derives it, so it stays fixed.</summary>
    private const int StaticBitIndex = 24;

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
        ulong methodTable = Alloc(MethodTableSize);
        _builder.WriteU32(methodTable + MtFlags, 0);
        _builder.WriteU32(methodTable + MtBaseSize, baseSize);
        _builder.WriteU64(methodTable + MtParent, parent);
        _builder.WriteU64(methodTable + MtModule, modulePointer);
        _builder.WriteU64(methodTable + MtEEClassOrCanonMt, canonical | 1);
        return methodTable;
    }

    /// <summary>Big enough to hold whatever slot this build puts <c>m_pAuxiliaryData</c> in.</summary>
    private int MethodTableSize =>
        Math.Max(MtSize, Math.Max(_options.AuxiliarySlot, _options.DuplicateAuxiliarySlot) + 8);

    private ulong DefineMethodTable(
        ulong modulePointer, ulong parent, uint baseSize, int componentSize, ClrElementType elementType, ulong perInstInfo)
    {
        ulong methodTable = Alloc(MethodTableSize);

        // Eight readable bytes below the EEClass, so a statics build can make slot 40 satisfy the
        // back-pointer anchor as 26 real types accidentally do (§14.0, correction 1).
        ulong eeClass = Alloc(EEClassSize, prefix: 8);

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

        _eeClassOf[methodTable] = eeClass;
        return methodTable;
    }

    private void DefineFieldDesc(
        ulong modulePointer,
        ModuleMetadata metadata,
        string typeName,
        string fieldName,
        ulong enclosing,
        int objectRelativeOffset,
        int elementType)
    {
        TypeDefinitionHandle handle = metadata.Types.ResolveType(typeName)
            ?? throw new InvalidOperationException($"the fixture's metadata defines no '{typeName}'.");

        if (!metadata.Types.TryGetField(handle, fieldName, out MetadataField field))
        {
            throw new InvalidOperationException($"'{typeName}' declares no field '{fieldName}'.");
        }

        WriteFieldDesc(modulePointer, field.Token, enclosing, objectRelativeOffset, elementType);
    }

    /// <summary>
    /// Lay down one <c>FieldDesc</c>, packing the offset next to a per-field element type.
    /// </summary>
    /// <remarks>
    /// The element type is a PARAMETER rather than a constant because the entire width question
    /// turns on its low bit. A fixture that stamped one element type on every descriptor could
    /// no more distinguish a correct width from a wider one than the anchors can — which is
    /// precisely the hole live validation fell through.
    /// </remarks>
    private void WriteFieldDesc(ulong modulePointer, int token, ulong enclosing, int objectRelativeOffset, int elementType)
    {
        ulong fieldDesc = Alloc(FieldDescStride);
        int stored = objectRelativeOffset - ObjectHeaderSize;
        uint type = (uint)elementType & 0x1F;

        switch (Style)
        {
            case FieldDescStyle.CoreClrLike:
                _builder.WriteU64(fieldDesc, enclosing);
                _builder.WriteU32(fieldDesc + 8, (uint)(token & 0x00FF_FFFF));

                // Offset in the low 27 bits, element type in the 5 above — CoreCLR's own packing,
                // so the boundary the calibration has to find is a real one.
                _builder.WriteU32(fieldDesc + 12, (uint)stored | (type << 27));
                break;

            case FieldDescStyle.Alternate:
                _builder.WriteI32(fieldDesc + 8, checked((int)((long)enclosing - (long)(fieldDesc + 8))));
                _builder.WriteU32(fieldDesc + 16, (uint)(token & 0x00FF_FFFF));
                _builder.WriteU32(fieldDesc + 20, ((uint)stored << 5) | type);
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

    /// <summary>
    /// Allocate <paramref name="size"/> bytes with <paramref name="prefix"/> readable bytes in
    /// front of the returned address.
    /// </summary>
    /// <remarks>
    /// Two structures here are addressed from ABOVE — <c>DynamicStaticsInfo</c> sits below
    /// <c>m_pAuxiliaryData</c>, and the <c>EEClass</c> alias needs eight writable bytes below it —
    /// so the space in front has to be reserved rather than borrowed from whatever the previous
    /// allocation left behind.
    /// </remarks>
    private ulong Alloc(int size, int prefix = 0)
    {
        ulong block = _next;
        _next = (_next + (ulong)(prefix + size) + 15) & ~15UL;
        _builder.Reserve(block, prefix + size + 64);
        return block + (ulong)prefix;
    }
}
