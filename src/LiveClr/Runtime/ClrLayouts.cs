namespace LiveClr.Runtime;

using System.Diagnostics.CodeAnalysis;
using LiveClr.Cdac;
using LiveClr.Memory;

/// <summary>
/// The CLR-internal offsets this layer needs, resolved once from the contract
/// descriptor and then held as plain integers.
/// </summary>
/// <remarks>
/// <para>
/// Every value here comes from the runtime's own published descriptor (analysis doc
/// §5.2) — <c>Object.m_pMethTab</c>, <c>MethodTable.Module</c>, <c>String.m_FirstChar</c>
/// and friends. Nothing is hardcoded. The point of materialising them into fields is
/// that the traversal above runs at 4 Hz over thousands of pointers, and a dictionary
/// lookup per hop would show up.
/// </para>
/// <para>
/// <b>Construction is all-or-nothing on purpose.</b> §5.5 established that the shipped
/// .NET 9 descriptor omits things a consumer may want, so a caller must be able to tell
/// "this runtime cannot be walked" from "this object was not found". Resolving the
/// required set up front and reporting exactly which entries were missing turns that
/// into one diagnosable failure at attach rather than a null somewhere deep in a walk.
/// </para>
/// <para>Lifetime: PROCESS tier (§8.8). The descriptor does not change while the target runs.</para>
/// </remarks>
public sealed class ClrLayouts
{
    private ClrLayouts(IRuntimeContractTarget target, int pointerSize, ulong methodTableMask)
    {
        Target = target;
        PointerSize = pointerSize;
        MethodTableMask = methodTableMask;
    }

    /// <summary>The descriptor these offsets were read from.</summary>
    public IRuntimeContractTarget Target { get; }

    /// <summary>Target pointer width in bytes.</summary>
    public int PointerSize { get; }

    /// <summary>
    /// <c>~ObjectToMethodTableUnmask</c>. The runtime stores flag bits in the low bits of
    /// an object's method-table slot; §12.4d records that getting this masking wrong
    /// produces a plausible-looking but nonsense pointer.
    /// </summary>
    public ulong MethodTableMask { get; }

    /// <summary>
    /// Offset of an object's first instance field. <c>Object.m_pMethTab</c> sits at 0 and is
    /// pointer-sized, so the field region starts one pointer in. This is the constant that
    /// converts a runtime <c>FieldDesc</c> offset (which excludes the header) into an
    /// object-relative offset, and it is derived rather than assumed: §5.2 publishes
    /// <c>String.m_StringLength = 8</c> on a 64-bit target, which is exactly this value.
    /// </summary>
    public int FirstFieldOffset => PointerSize;

    /// <summary><c>Object.m_pMethTab</c>. Zero on every runtime seen so far, but published, so read it.</summary>
    public int ObjectMethodTableOffset { get; private init; }

    /// <summary><c>String.m_StringLength</c> (§5.2: 8).</summary>
    public int StringLengthOffset { get; private init; }

    /// <summary><c>String.m_FirstChar</c> (§5.2: 12).</summary>
    public int StringFirstCharOffset { get; private init; }

    /// <summary><c>Array.m_NumComponents</c> (§5.2: 8).</summary>
    public int ArrayNumComponentsOffset { get; private init; }

    /// <summary><c>Array."!"</c> — the element base, i.e. where element 0 starts (§5.2: 16).</summary>
    public int ArrayFirstElementOffset { get; private init; }

    /// <summary><c>MethodTable.MTFlags</c> (§5.2: 0).</summary>
    public int MethodTableFlagsOffset { get; private init; }

    /// <summary><c>MethodTable.BaseSize</c> (§5.2: 4).</summary>
    public int MethodTableBaseSizeOffset { get; private init; }

    /// <summary><c>MethodTable.ParentMethodTable</c> (§5.2: 16) — the inheritance chain.</summary>
    public int MethodTableParentOffset { get; private init; }

    /// <summary><c>MethodTable.Module</c> (§5.2: 24) — the §12.4d route to names.</summary>
    public int MethodTableModuleOffset { get; private init; }

    /// <summary><c>MethodTable.EEClassOrCanonMT</c> (§5.2: 40) — a tagged union; see <see cref="ClrTypeSystem"/>.</summary>
    public int MethodTableEEClassOrCanonMtOffset { get; private init; }

    /// <summary><c>EEClass.MethodTable</c> (§5.2: 16) — the back-pointer that makes the union tag verifiable.</summary>
    public int EEClassMethodTableOffset { get; private init; }

    /// <summary><c>EEClass.InternalCorElementType</c> (§5.2: 64) — one byte of <see cref="ClrElementType"/>.</summary>
    public int EEClassElementTypeOffset { get; private init; }

    /// <summary>
    /// <c>EEClass.CorTypeAttr</c> (§5.2: 56) — ECMA-335 <c>TypeAttributes</c> — or -1 when this
    /// runtime does not publish it.
    /// </summary>
    /// <remarks>
    /// Optional, unlike everything above it. Nothing here needs the flags to walk a type: they
    /// enrich <see cref="ClrTypeInfo.TypeAttributes"/> and nothing else, so a runtime that omits
    /// them must still attach. §5.5 is about not assuming coverage, and a required-entry list
    /// that outruns what the layer actually reads turns that assumption into a hard failure.
    /// </remarks>
    public int EEClassTypeAttributesOffset { get; private init; } = -1;

    /// <summary>Whether <see cref="EEClassTypeAttributesOffset"/> was published.</summary>
    public bool HasEEClassTypeAttributes => EEClassTypeAttributesOffset >= 0;

    /// <summary><c>Module.Base</c> (§5.2: 192) — the mapped PE image, entry point to metadata.</summary>
    public int ModuleBaseOffset { get; private init; }

    /// <summary><c>Module.TypeDefToMethodTableMap</c> (§5.2: 336).</summary>
    public int ModuleTypeDefMapOffset { get; private init; }

    /// <summary><c>Module.FieldDefToDescMap</c> (§5.2: 432).</summary>
    public int ModuleFieldDefMapOffset { get; private init; }

    /// <summary><c>ModuleLookupMap.TableData</c> (§5.2: 8).</summary>
    public int LookupMapTableDataOffset { get; private init; }

    /// <summary>
    /// Descriptor entries that must be present for this layer to work at all, in
    /// <c>"Type.Field"</c> form. Exposed so a diagnostic can say precisely what a runtime
    /// failed to publish rather than "unsupported".
    /// </summary>
    /// <remarks>
    /// "Work at all" is meant literally: every entry listed here is read on some path below, and
    /// an entry that is merely nice to have belongs in the optional set instead (currently
    /// <c>EEClass.CorTypeAttr</c>). §5.5 warns against assuming descriptor coverage, and failing
    /// attach over a field nothing reads is that assumption in its most expensive form.
    /// </remarks>
    public static IReadOnlyList<string> RequiredEntries { get; } =
    [
        "Object.m_pMethTab",
        "String.m_StringLength",
        "String.m_FirstChar",
        "Array.m_NumComponents",
        "Array.!",
        "MethodTable.MTFlags",
        "MethodTable.BaseSize",
        "MethodTable.ParentMethodTable",
        "MethodTable.Module",
        "MethodTable.EEClassOrCanonMT",
        "EEClass.MethodTable",
        "EEClass.InternalCorElementType",
        "Module.Base",
        "Module.TypeDefToMethodTableMap",
        "Module.FieldDefToDescMap",
        "ModuleLookupMap.TableData",
        "globals.ObjectToMethodTableUnmask",
    ];

    /// <summary>
    /// Resolve every required entry, or explain what was missing.
    /// </summary>
    /// <param name="target">A bootstrapped contract target.</param>
    /// <param name="layouts">The resolved offsets, when every required entry was published.</param>
    /// <param name="missing">
    /// Comma-separated list of the entries this runtime did not publish. Null on success.
    /// </param>
    public static bool TryCreate(
        IRuntimeContractTarget target,
        [NotNullWhen(true)] out ClrLayouts? layouts,
        out string? missing)
    {
        ArgumentNullException.ThrowIfNull(target);

        layouts = null;
        var gaps = new List<string>();

        int Field(string type, string field)
        {
            if (target.TryGetFieldOffset(type, field, out int offset)) return offset;
            gaps.Add($"{type}.{field}");
            return -1;
        }

        int objectMt = Field("Object", "m_pMethTab");
        int stringLength = Field("String", "m_StringLength");
        int stringFirstChar = Field("String", "m_FirstChar");
        int arrayCount = Field("Array", "m_NumComponents");
        int mtFlags = Field("MethodTable", "MTFlags");
        int mtBaseSize = Field("MethodTable", "BaseSize");
        int mtParent = Field("MethodTable", "ParentMethodTable");
        int mtModule = Field("MethodTable", "Module");
        int mtEEClass = Field("MethodTable", "EEClassOrCanonMT");
        int eeMt = Field("EEClass", "MethodTable");
        int eeElementType = Field("EEClass", "InternalCorElementType");
        int moduleBase = Field("Module", "Base");
        int moduleTypeDefMap = Field("Module", "TypeDefToMethodTableMap");
        int moduleFieldDefMap = Field("Module", "FieldDefToDescMap");
        int lookupTable = Field("ModuleLookupMap", "TableData");

        // The array element base is published as the type's "!" size entry, not as a
        // named field: an array's header size IS where element 0 starts (§5.2).
        if (!target.TryGetTypeSize("Array", out int arrayElementBase))
        {
            gaps.Add("Array.!");
            arrayElementBase = -1;
        }

        // Optional: absence costs ClrTypeInfo.TypeAttributes and nothing else.
        if (!target.TryGetFieldOffset("EEClass", "CorTypeAttr", out int eeAttributes)) eeAttributes = -1;

        if (!target.TryGetGlobalValue("ObjectToMethodTableUnmask", out ulong unmask))
        {
            gaps.Add("globals.ObjectToMethodTableUnmask");
        }

        if (gaps.Count > 0)
        {
            missing = string.Join(", ", gaps);
            return false;
        }

        missing = null;
        layouts = new ClrLayouts(target, target.Memory.Is64Bit ? 8 : 4, ~unmask)
        {
            ObjectMethodTableOffset = objectMt,
            StringLengthOffset = stringLength,
            StringFirstCharOffset = stringFirstChar,
            ArrayNumComponentsOffset = arrayCount,
            ArrayFirstElementOffset = arrayElementBase,
            MethodTableFlagsOffset = mtFlags,
            MethodTableBaseSizeOffset = mtBaseSize,
            MethodTableParentOffset = mtParent,
            MethodTableModuleOffset = mtModule,
            MethodTableEEClassOrCanonMtOffset = mtEEClass,
            EEClassMethodTableOffset = eeMt,
            EEClassElementTypeOffset = eeElementType,
            EEClassTypeAttributesOffset = eeAttributes,
            ModuleBaseOffset = moduleBase,
            ModuleTypeDefMapOffset = moduleTypeDefMap,
            ModuleFieldDefMapOffset = moduleFieldDefMap,
            LookupMapTableDataOffset = lookupTable,
        };

        return true;
    }

    /// <summary>
    /// Read an object's method table, with the flag bits removed (§12.4d).
    /// </summary>
    public bool TryReadMethodTableOf(IMemoryReader memory, ulong objectAddress, out ulong methodTable)
    {
        methodTable = 0;
        if (objectAddress == 0) return false;
        if (!memory.TryReadPointer(objectAddress + (ulong)ObjectMethodTableOffset, out ulong raw)) return false;

        methodTable = raw & MethodTableMask;
        return methodTable != 0;
    }

    /// <summary>
    /// Address of a <c>ModuleLookupMap</c>'s entry for <paramref name="rid"/>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Metadata rids are 1-based and the runtime indexes the table by rid directly, so slot 0
    /// is never used (§5.4).
    /// </para>
    /// <para>
    /// <b>This does NOT chain segments, and it is not bounded to the first one.</b> §5.4
    /// describes these maps as segmented — read a segment's <c>Count</c>, follow <c>Next</c>
    /// when the rid is out of range — but the .NET 9 descriptor publishes only
    /// <c>TableData</c>. With neither <c>Count</c> nor <c>Next</c> there is no way to find a
    /// segment's end or its successor, so a rid past the first segment addresses whatever the
    /// runtime allocated AFTER that segment's array. Nothing here can detect that.
    /// </para>
    /// <para>
    /// Two things keep it safe rather than merely lucky. <paramref name="rowCount"/> is
    /// enforced, not documented: a rid outside the metadata table cannot be turned into an
    /// address at all. And every caller must validate what it reads back — the method table
    /// round trip in <see cref="ClrTypeSystem.IsMethodTable"/>, the declaring-module check in
    /// <see cref="RuntimeFieldLayoutSource"/> — so an entry that came from adjacent runtime
    /// data is rejected rather than believed. The honest summary is: correct for
    /// single-segment maps (every non-dynamic module observed), degrades to "not found" past
    /// that, and never degrades to a wrong answer.
    /// </para>
    /// </remarks>
    /// <param name="memory">Reader for the target.</param>
    /// <param name="lookupMapAddress">Address of the inline <c>ModuleLookupMap</c> within <c>Module</c>.</param>
    /// <param name="rid">1-based metadata row id.</param>
    /// <param name="rowCount">
    /// Number of rows in the corresponding metadata table. The only bound available, since the
    /// map's own <c>Count</c> is unpublished.
    /// </param>
    /// <param name="slotAddress">Address of the entry on success.</param>
    public bool TryGetLookupMapSlot(
        IMemoryReader memory, ulong lookupMapAddress, int rid, int rowCount, out ulong slotAddress)
    {
        slotAddress = 0;
        if (rid <= 0 || rid > rowCount) return false;
        if (!memory.TryReadPointer(lookupMapAddress + (ulong)LookupMapTableDataOffset, out ulong table)) return false;
        if (table == 0) return false;

        slotAddress = table + ((ulong)rid * (ulong)PointerSize);
        return true;
    }
}
