namespace LiveClr.Runtime;

using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using LiveClr.Cdac;
using LiveClr.Memory;
using LiveClr.Metadata;

/// <summary>
/// The two statics bases a type's <c>DynamicStaticsInfo</c> carries, plus the auxiliary-data
/// pointer they were reached through (§14.1).
/// </summary>
/// <param name="AuxiliaryData"><c>MethodTable.m_pAuxiliaryData</c>, after the back-pointer anchor
/// confirmed it.</param>
/// <param name="GcStatics">Base of the GC statics blob, masked, or 0 when the type has none.</param>
/// <param name="NonGcStatics">Base of the non-GC statics blob, masked, or 0 when the type has
/// none.</param>
/// <param name="GcClassInitialized">
/// False when <c>ISCLASSNOTINITED</c> was set on the GC base — the class's static constructor has
/// not run in this process. §14.0: that is a DISTINCT state from "the field is null", and
/// <c>Boolean.TrueString</c> legitimately reads null in a process that never touched
/// <c>Boolean</c>. The storage is real and readable either way; only its contents are still at
/// their default.
/// </param>
/// <param name="NonGcClassInitialized">As above, for the non-GC base.</param>
public readonly record struct StaticsBases(
    ulong AuxiliaryData,
    ulong GcStatics,
    ulong NonGcStatics,
    bool GcClassInitialized,
    bool NonGcClassInitialized);

/// <summary>
/// One bit inside a <c>FieldDesc</c>, located by derivation rather than by struct offset.
/// </summary>
/// <param name="ByteOffset">Byte offset of the 32-bit word holding it, or -1 when not derived.</param>
/// <param name="BitIndex">Bit position within that word.</param>
public readonly record struct FieldDescFlagBit(int ByteOffset, int BitIndex)
{
    /// <summary>A bit whose position could not be established.</summary>
    public static FieldDescFlagBit None => new(-1, 0);

    /// <summary>True when this bit was located and can be read.</summary>
    public bool IsDerived => ByteOffset >= 0;

    /// <summary>Read the bit out of a field descriptor.</summary>
    public bool TryRead(IMemoryReader memory, ulong fieldDesc, out bool set)
    {
        ArgumentNullException.ThrowIfNull(memory);

        set = false;
        if (!IsDerived || fieldDesc == 0) return false;
        if (!memory.TryRead(fieldDesc + (ulong)ByteOffset, out uint word)) return false;

        set = ((word >> BitIndex) & 1) != 0;
        return true;
    }
}

/// <summary>
/// How to get from a <c>MethodTable</c> to its static field storage on this runtime, expressed
/// as derived positions rather than as a hardcoded struct layout.
/// </summary>
/// <param name="Flags2Offset"><c>MethodTable.MTFlags2</c>, published by the descriptor (§5.2).</param>
/// <param name="StaticsFlagBit">
/// The bit in <c>MTFlags2</c> that means "a <c>DynamicStaticsInfo</c> precedes this type's
/// auxiliary data". §14.0: the constant <c>0x0002</c> is NOT descriptor-published, so it is
/// derived here (the bit that exactly predicts the anchor) rather than written down.
/// </param>
/// <param name="AuxiliaryDataSlot">
/// Byte offset of <c>MethodTable.m_pAuxiliaryData</c>. Also unpublished, also derived — and
/// derived ONCE, then frozen; see <see cref="StaticsCalibration"/> for why a per-type sweep picks
/// the wrong slot.
/// </param>
/// <param name="PointerSize">Target pointer width; the <c>DynamicStaticsInfo</c> displacements are
/// multiples of it.</param>
/// <param name="ElementTypeShift">
/// Right shift that lifts <c>FieldDesc.m_type</c> out of the same word the field offset lives in.
/// </param>
/// <param name="ThreadStaticBit">
/// The <c>FieldDesc</c> bit marking a thread-local static, or
/// <see cref="FieldDescFlagBit.None"/> when it could not be derived.
/// </param>
/// <param name="GcStaticsFirst">
/// True when <c>m_pGCStatics</c> is the FIRST of the three <c>DynamicStaticsInfo</c> members, i.e.
/// at <c>aux - 3 * PointerSize</c>. Measured, not assumed — see
/// <see cref="StaticsCalibration"/>.
/// </param>
public readonly record struct StaticsEncoding(
    int Flags2Offset,
    int StaticsFlagBit,
    int AuxiliaryDataSlot,
    int PointerSize,
    int ElementTypeShift,
    FieldDescFlagBit ThreadStaticBit,
    bool GcStaticsFirst)
{
    /// <summary><c>DynamicStaticsInfo.m_pMethodTable</c>, the anchor (§14.2).</summary>
    public int BackPointerDisplacement => -PointerSize;

    /// <summary><c>DynamicStaticsInfo.m_pGCStatics</c>.</summary>
    public int GcStaticsDisplacement => GcStaticsFirst ? -3 * PointerSize : -2 * PointerSize;

    /// <summary><c>DynamicStaticsInfo.m_pNonGCStatics</c>.</summary>
    public int NonGcStaticsDisplacement => GcStaticsFirst ? -2 * PointerSize : -3 * PointerSize;

    /// <summary>
    /// <c>MethodTable::IsDynamicStatics()</c> — whether this type has a
    /// <c>DynamicStaticsInfo</c> at all.
    /// </summary>
    /// <remarks>
    /// The gate is exact and fails SAFE: §14.0 measured zero of 12,283 types-with-statics with it
    /// clear, so there are no false refusals, and a type that fails it produces a correct refusal
    /// rather than a garbage read.
    /// </remarks>
    public bool HasDynamicStatics(IMemoryReader memory, ulong methodTable)
    {
        ArgumentNullException.ThrowIfNull(memory);

        if (methodTable == 0 || (methodTable & 3) != 0) return false;
        if (!memory.TryRead(methodTable + (ulong)Flags2Offset, out uint flags2)) return false;

        return ((flags2 >> StaticsFlagBit) & 1) != 0;
    }

    /// <summary>
    /// Resolve a type's statics bases, or refuse.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>This is the fail-closed surface.</b> Every step is a check that garbage cannot pass: the
    /// method table must be pointer-aligned and non-zero, the gate bit must be set, the auxiliary
    /// pointer must be readable and plausible, and — the load-bearing one —
    /// <c>ptr(aux - PointerSize)</c> must equal the method table we started from (§14.2). A
    /// randomised sweep of 200,000 addresses drawn near real method tables produced 24,819 gate
    /// passes, 37 gate-and-anchor passes, and ZERO that were not themselves real method tables
    /// (§14.0).
    /// </para>
    /// <para>
    /// Bases of zero are returned rather than refused: a type with only GC statics legitimately
    /// has no non-GC base, and an OPEN GENERIC DEFINITION has neither (§14.0, correction 3 —
    /// its raw bases read <c>1</c>, which masks to 0). Refusing to hand out an address for a zero
    /// base is the caller's job, and <see cref="RuntimeStaticFieldSource"/> does it.
    /// </para>
    /// </remarks>
    public bool TryReadBases(IMemoryReader memory, ulong methodTable, out StaticsBases bases)
    {
        ArgumentNullException.ThrowIfNull(memory);

        bases = default;
        if (!HasDynamicStatics(memory, methodTable)) return false;
        if (!memory.TryReadPointer(methodTable + (ulong)AuxiliaryDataSlot, out ulong aux)) return false;

        // Below this nothing can be a loader-heap allocation, and a displacement off it would
        // wrap or address the null page.
        if (aux < MinimumPlausibleAddress) return false;
        if (!memory.TryReadPointer(aux + (ulong)(long)BackPointerDisplacement, out ulong back)) return false;
        if (back != methodTable) return false;

        if (!memory.TryReadPointer(aux + (ulong)(long)GcStaticsDisplacement, out ulong gcRaw)) return false;
        if (!memory.TryReadPointer(aux + (ulong)(long)NonGcStaticsDisplacement, out ulong nonGcRaw)) return false;

        bases = new StaticsBases(
            aux,
            gcRaw & ~(ulong)ClassNotInitedFlag,
            nonGcRaw & ~(ulong)ClassNotInitedFlag,
            (gcRaw & ClassNotInitedFlag) == 0,
            (nonGcRaw & ClassNotInitedFlag) == 0);

        return true;
    }

    /// <summary>Lift <c>FieldDesc.m_type</c> out of the word the field offset shares with it.</summary>
    public ClrElementType DecodeElementType(uint offsetWord) =>
        (ClrElementType)(byte)((offsetWord >> ElementTypeShift) & 0x1F);

    /// <summary>
    /// Whether a static of this element type lives in the GC blob rather than the non-GC one.
    /// </summary>
    /// <remarks>
    /// <c>CLASS</c> and <c>VALUETYPE</c>, and nothing else. §14.0's histogram over 27,732 static
    /// field descriptors is exhaustive on this runtime: every reference-typed static — including
    /// strings and arrays — reports <c>CLASS</c> (21,276 of them), value-type statics report
    /// <c>VALUETYPE</c> and are stored BOXED in the GC blob (651), and everything else is a
    /// primitive, an <c>IntPtr</c> or a function pointer. Note this cannot be decided from the
    /// field's metadata signature: seven statics whose signature says <c>VALUETYPE</c> are enums,
    /// and the runtime stores them as their underlying <c>Int32</c> in the NON-GC blob.
    /// </remarks>
    public static bool IsGcStatic(ClrElementType elementType) =>
        elementType is ClrElementType.Class or ClrElementType.ValueType;

    /// <summary><c>ISCLASSNOTINITED</c> (§14.1: <c>STATICSPOINTERMASK = ~ISCLASSNOTINITED</c>).</summary>
    internal const int ClassNotInitedFlag = 1;

    /// <summary>Nothing below the first 64 KiB is mapped on any target this reads.</summary>
    internal const ulong MinimumPlausibleAddress = 0x10000;
}

/// <summary>
/// Derives <see cref="StaticsEncoding"/> from the running target, instead of hardcoding
/// CoreCLR's <c>MethodTable</c> auxiliary-data layout.
/// </summary>
/// <remarks>
/// <para>
/// <b>What the descriptor gives, and what it does not.</b> §5.2 publishes
/// <c>MethodTable.MTFlags2</c> and nothing else on this path: no <c>m_pAuxiliaryData</c> field, no
/// <c>DynamicStaticsInfo</c> type, no meaning for any <c>MTFlags2</c> bit. §5.5 concluded from
/// that there was "no route and no calibration anchor"; §14 shows both exist. The anchor is
/// <c>DynamicStaticsInfo</c>'s third member, a BACK-POINTER to the method table, so a candidate
/// auxiliary slot is not trusted — it is tested, exactly as
/// <see cref="ClrLayouts.TryResolveEEClass"/> tests the <c>EEClassOrCanonMT</c> union.
/// </para>
/// <para>
/// <b>The slot and the gate bit are derived JOINTLY, and it has to be that way.</b> Neither is
/// derivable alone. Sweeping slots without a gate finds the anchor holding on a large but
/// unexplained SUBSET of types (the ones with statics), which no threshold separates honestly
/// from noise. Deriving the gate bit without a slot has nothing to correlate against. Together
/// they pin each other: the answer is the one (slot, bit) pair for which "the anchor closes" and
/// "the bit is set" agree on EVERY sampled type. Measured on CoreCLR 9.0 (§14.0): slot 32 with
/// bit 1 holds 3033 of 3033 gate-set types and 0 of 9250 gate-clear ones; no other pair comes
/// close.
/// </para>
/// <para>
/// <b>Derived ONCE and frozen. Never swept per lookup.</b> This is the correction §14.0 exists
/// to record. <c>EEClassOrCanonMT</c> at slot 40 satisfies the back-pointer test BY COINCIDENCE
/// for 26 types, so a per-type inclusive sweep silently picks slot 40 for four of them
/// (<c>EpochModel</c>, <c>MonsterModel</c>, <c>OrbModel</c>, <c>PowerModel</c>) and reads their
/// statics out of an <c>EEClass</c>. Unanimity over a corpus is what kills that: slot 40 holds
/// the anchor for 4 of 3032 gate-set types, so it cannot agree with any flag bit and is never
/// a candidate. A per-lookup sweep has no corpus and therefore no way to know.
/// </para>
/// <para>
/// <b>Which of the two bases is the GC one is MEASURED, not read off the struct.</b>
/// <c>DynamicStaticsInfo</c> declares <c>{ m_pGCStatics; m_pNonGCStatics; m_pMethodTable; }</c>,
/// but member order is exactly the sort of thing that is right until it is not, and getting it
/// backwards produces addresses rather than errors. So both orderings are scored against real
/// <c>CLASS</c> statics: the correct one yields object references that validate as method tables,
/// and the other yields garbage. §14.0 measured that control directly — the identical fields read
/// through the wrong base gave 0 valid objects out of 529 — which is what makes "0 garbage out of
/// 17,494" a result rather than a tautology. The calibration therefore proves its own control at
/// attach, and refuses if the two orderings are not cleanly separated.
/// </para>
/// <para>
/// <b>Thread statics are the trap.</b> §14.0, correction 2: a <c>[ThreadStatic]</c> field passes
/// the gate AND the anchor, but its offset indexes per-thread storage, so the auxiliary bases
/// produce a CONFIDENT WRONG ADDRESS. Metadata names them exactly — the attribute is right there
/// in the target's own blob — so that is the authority, and the runtime's own marker bit is
/// derived against it as a second, independent guard. Both are consulted;
/// <see cref="RuntimeStaticFieldSource"/> refuses if either fires.
/// </para>
/// <para>Lifetime: PROCESS tier (§8.8). Derive once at attach.</para>
/// </remarks>
public sealed class StaticsCalibration
{
    /// <summary>Bytes of a <c>MethodTable</c> header sampled per type. Past any plausible fixed part.</summary>
    private const int MethodTableProbeBytes = 96;

    /// <summary>Bytes of a <c>FieldDesc</c> the flag-bit search looks at, matching the offset search.</summary>
    private const int FieldDescProbeBytes = 64;

    /// <summary>Types walked out of CoreLib's TypeDef map. Bounds a cold-path cost.</summary>
    private const int MaxCorpusTypes = 1200;

    /// <summary>Static field descriptors gathered for the base and thread-static measurements.</summary>
    private const int MaxStaticFields = 2048;

    /// <summary>
    /// Gate-set types the winning pair must agree on. §14.0's own bar — "derive by unanimity over
    /// ≥100 gate-set types once at connect" — and high enough that slot 40's 26 coincidences
    /// cannot masquerade as a rule.
    /// </summary>
    private const int MinimumGateSetTypes = 100;

    /// <summary>
    /// Gate-CLEAR types required too. Without negatives, "the anchor always closes" and "this bit
    /// is always set" would agree vacuously and prove nothing about either.
    /// </summary>
    private const int MinimumGateClearTypes = 100;

    /// <summary>
    /// <c>CLASS</c> statics the winning base ordering must resolve to real objects. Below this the
    /// control is not discriminating and the ordering stays underived.
    /// </summary>
    private const int MinimumGcProbes = 8;

    /// <summary>Non-thread-static field descriptors needed before the marker bit is searched for.</summary>
    private const int MinimumThreadStaticNegatives = 16;

    private StaticsCalibration(StaticsEncoding? encoding, string detail, Measurements measurements = default)
    {
        Encoding = encoding;
        Detail = detail;
        CorpusTypes = measurements.CorpusTypes;
        GateSetTypes = measurements.GateSetTypes;
        SlotBitCandidates = measurements.SlotBitCandidates;
        GcProbeFields = measurements.GcProbeFields;
        WrongBaseValidObjects = measurements.WrongBaseValidObjects;
        ThreadStaticSamples = measurements.ThreadStaticSamples;
    }

    /// <summary>The derived encoding, or null when derivation did not converge.</summary>
    public StaticsEncoding? Encoding { get; }

    /// <summary>True when static field addresses can be resolved from the runtime at all.</summary>
    public bool IsCalibrated => Encoding is not null;

    /// <summary>Human-readable outcome, suitable for a startup diagnostic.</summary>
    public string Detail { get; }

    /// <summary>Method tables the derivation was measured against.</summary>
    public int CorpusTypes { get; }

    /// <summary>Of those, how many carry a <c>DynamicStaticsInfo</c>.</summary>
    public int GateSetTypes { get; }

    /// <summary>
    /// (slot, flag bit) pairs that agreed on every sampled type. One is the expected answer; more
    /// than one is reported rather than resolved by preference.
    /// </summary>
    public int SlotBitCandidates { get; }

    /// <summary><c>CLASS</c> statics the base ordering was measured against.</summary>
    public int GcProbeFields { get; }

    /// <summary>
    /// How many of those resolved to a valid object through the REJECTED base. Zero on a converged
    /// calibration by construction; carried so a caller can see the control rather than trust it.
    /// </summary>
    public int WrongBaseValidObjects { get; }

    /// <summary><c>[ThreadStatic]</c> fields the marker bit was derived against.</summary>
    public int ThreadStaticSamples { get; }

    /// <summary>A calibration that was never attempted, or was deliberately disabled.</summary>
    public static StaticsCalibration NotAttempted { get; } =
        new(null, "statics calibration was not attempted.");

    /// <summary>
    /// Attempt the derivation. Never throws; a runtime whose statics cannot be reached is an
    /// ordinary outcome (§5.5), and callers then fall back to <see cref="IClrStaticRootSource"/>.
    /// </summary>
    /// <param name="memory">Reader for the target.</param>
    /// <param name="target">The bootstrapped contract target, for <c>MethodTable.MTFlags2</c>.</param>
    /// <param name="layouts">Resolved CLR offsets.</param>
    /// <param name="metadata">Process-tier metadata cache; CoreLib's blob is loaded through it.</param>
    /// <param name="fieldDescs">
    /// The <c>FieldDesc</c> derivation. Statics share the offset bitfield with instance fields, so
    /// this cannot run without it.
    /// </param>
    public static StaticsCalibration Attempt(
        IMemoryReader memory,
        IRuntimeContractTarget target,
        ClrLayouts layouts,
        ModuleMetadataCache metadata,
        FieldDescCalibration fieldDescs)
    {
        ArgumentNullException.ThrowIfNull(memory);
        ArgumentNullException.ThrowIfNull(target);
        ArgumentNullException.ThrowIfNull(layouts);
        ArgumentNullException.ThrowIfNull(metadata);
        ArgumentNullException.ThrowIfNull(fieldDescs);

        if (fieldDescs.Encoding is not FieldDescEncoding fieldDesc)
        {
            return new StaticsCalibration(
                null,
                "the FieldDesc encoding did not converge, and a static's offset is stored in the same " +
                "bitfield as an instance field's, so statics cannot be resolved either.");
        }

        int elementTypeShift = fieldDesc.OffsetBitShift + fieldDesc.OffsetBitWidth;
        if (elementTypeShift + 5 > 32)
        {
            return new StaticsCalibration(
                null,
                $"the field offset occupies bits [{fieldDesc.OffsetBitShift}, {elementTypeShift}) of its word, " +
                "leaving no room above it for m_type. Without m_type there is no way to tell a GC static from a " +
                "non-GC one, and picking a base by the field's metadata signature is measurably wrong for enums " +
                "(§14.0), so this refuses rather than guessing.");
        }

        if (!target.TryGetFieldOffset("MethodTable", "MTFlags2", out int flags2Offset) ||
            flags2Offset < 0 ||
            flags2Offset + 4 > MethodTableProbeBytes)
        {
            return new StaticsCalibration(
                null, "the descriptor does not publish MethodTable.MTFlags2, which is the only gate on this route.");
        }

        if (!target.TryGetGlobalPointer("ExceptionMethodTable", out ulong globalAddress) ||
            !memory.TryReadPointer(globalAddress, out ulong exceptionMt) ||
            exceptionMt == 0 ||
            !memory.TryReadPointer(exceptionMt + (ulong)layouts.MethodTableModuleOffset, out ulong modulePointer) ||
            !memory.TryReadPointer(modulePointer + (ulong)layouts.ModuleBaseOffset, out ulong moduleBase))
        {
            return new StaticsCalibration(null, "could not reach CoreLib's Module from the published globals.");
        }

        ModuleMetadata? corelib = metadata.GetOrLoad(moduleBase);
        if (corelib is null)
        {
            return new StaticsCalibration(null, $"no ECMA-335 metadata at CoreLib base 0x{moduleBase:X}.");
        }

        List<TypeSample> corpus = CollectTypes(memory, layouts, modulePointer, corelib, flags2Offset);
        return Solve(memory, layouts, modulePointer, corelib, fieldDesc, corpus, flags2Offset, elementTypeShift);
    }

    private readonly record struct Measurements(
        int CorpusTypes,
        int GateSetTypes,
        int SlotBitCandidates,
        int GcProbeFields,
        int WrongBaseValidObjects,
        int ThreadStaticSamples);

    /// <summary>One sampled method table: its flag word and its whole header, read once.</summary>
    private readonly record struct TypeSample(int Rid, ulong MethodTable, uint Flags2, ulong[] Slots);

    /// <summary>One sampled static field descriptor, with the two candidate bases of its type.</summary>
    private sealed record StaticFieldSample(
        byte[] Bytes,
        uint OffsetWord,
        bool DeclaredThreadStatic,
        ulong FirstBaseRaw,
        ulong SecondBaseRaw);

    private static StaticsCalibration Solve(
        IMemoryReader memory,
        ClrLayouts layouts,
        ulong modulePointer,
        ModuleMetadata corelib,
        FieldDescEncoding fieldDesc,
        List<TypeSample> corpus,
        int flags2Offset,
        int elementTypeShift)
    {
        var measurements = new Measurements { CorpusTypes = corpus.Count };

        List<(int Slot, int Bit, int Positives)> candidates = FindSlotAndFlagBit(memory, layouts, corpus);
        measurements = measurements with { SlotBitCandidates = candidates.Count };

        if (candidates.Count == 0)
        {
            return new StaticsCalibration(
                null,
                $"no (auxiliary slot, MTFlags2 bit) pair agrees across all {corpus.Count} sampled CoreLib method " +
                $"tables, with at least {MinimumGateSetTypes} on each side. Either this runtime reaches its " +
                "statics some other way, or too few of CoreLib's types are loaded to measure it.",
                measurements);
        }

        if (candidates.Count > 1)
        {
            string listed = string.Join(", ", candidates.Select(c => $"(+{c.Slot}, bit {c.Bit})"));
            return new StaticsCalibration(
                null,
                $"ambiguous: {candidates.Count} (auxiliary slot, MTFlags2 bit) pairs agree across all " +
                $"{corpus.Count} sampled method tables — {listed}. Picking one is exactly the plausible-but-wrong " +
                "choice this derivation exists to avoid.",
                measurements);
        }

        (int slot, int bit, int positives) = candidates[0];
        measurements = measurements with { GateSetTypes = positives };

        List<TypeSample> gateSet = corpus.FindAll(s => ((s.Flags2 >> bit) & 1) != 0);
        List<StaticFieldSample> statics = CollectStaticFields(
            memory, layouts, modulePointer, corelib, fieldDesc, gateSet, slot, layouts.PointerSize);

        (int firstValid, int firstGarbage) = ScoreBaseOrdering(
            memory, layouts, fieldDesc, statics, elementTypeShift, gcIsFirst: true);
        (int secondValid, int secondGarbage) = ScoreBaseOrdering(
            memory, layouts, fieldDesc, statics, elementTypeShift, gcIsFirst: false);

        bool gcIsFirst = firstGarbage == 0 && firstValid >= MinimumGcProbes && secondValid == 0;
        bool gcIsSecond = secondGarbage == 0 && secondValid >= MinimumGcProbes && firstValid == 0;

        if (gcIsFirst == gcIsSecond)
        {
            return new StaticsCalibration(
                null,
                $"the GC statics base could not be told from the non-GC one. Reading CLASS statics through " +
                $"aux-{3 * layouts.PointerSize} gave {firstValid} valid objects and {firstGarbage} garbage; through " +
                $"aux-{2 * layouts.PointerSize}, {secondValid} valid and {secondGarbage} garbage. A clean answer is " +
                $"one side with at least {MinimumGcProbes} valid and no garbage while the other has none valid " +
                "(§14.0 measured 0 of 529 through the wrong base).",
                measurements with { GcProbeFields = firstValid + secondValid });
        }

        measurements = measurements with
        {
            GcProbeFields = gcIsFirst ? firstValid : secondValid,
            WrongBaseValidObjects = gcIsFirst ? secondValid : firstValid,
        };

        (FieldDescFlagBit threadStaticBit, int threadStaticSamples, int threadStaticCandidates) =
            FindThreadStaticBit(statics);
        measurements = measurements with { ThreadStaticSamples = threadStaticSamples };

        var encoding = new StaticsEncoding(
            flags2Offset, bit, slot, layouts.PointerSize, elementTypeShift, threadStaticBit, gcIsFirst);

        string threadStatics = threadStaticBit.IsDerived
            ? $"thread-static marker at +{threadStaticBit.ByteOffset} bit {threadStaticBit.BitIndex}, derived " +
              $"against {threadStaticSamples} [ThreadStatic] fields"
            : $"no thread-static marker bit derived ({threadStaticSamples} [ThreadStatic] fields sampled, " +
              $"{threadStaticCandidates} candidate bits); thread statics are then refused on the metadata " +
              "attribute alone";

        return new StaticsCalibration(
            encoding,
            $"MethodTable.m_pAuxiliaryData at +{slot}, gated on MTFlags2 bit {bit}: the pair agrees on all " +
            $"{corpus.Count} sampled CoreLib method tables ({positives} with statics, {corpus.Count - positives} " +
            $"without), and is the only pair that does. GC statics at aux{encoding.GcStaticsDisplacement}, " +
            $"non-GC at aux{encoding.NonGcStaticsDisplacement}, measured against " +
            $"{measurements.GcProbeFields} CLASS statics with 0 garbage while the rejected ordering resolved " +
            $"{measurements.WrongBaseValidObjects} objects. {threadStatics}.",
            measurements);
    }

    /// <summary>
    /// Every (auxiliary slot, <c>MTFlags2</c> bit) pair on which "the anchor closes" and "the bit
    /// is set" agree for EVERY sampled type.
    /// </summary>
    /// <remarks>
    /// A pair with no positives agrees vacuously — a bit nothing sets, and a slot the anchor never
    /// closes on, describe each other perfectly and describe the runtime not at all. Both sides
    /// therefore carry a floor.
    /// </remarks>
    private static List<(int Slot, int Bit, int Positives)> FindSlotAndFlagBit(
        IMemoryReader memory, ClrLayouts layouts, List<TypeSample> corpus)
    {
        var results = new List<(int, int, int)>();
        if (corpus.Count < MinimumGateSetTypes + MinimumGateClearTypes) return results;

        int slots = MethodTableProbeBytes / layouts.PointerSize;

        // One read per distinct auxiliary candidate, not one per (type, slot): the same pointers
        // recur across slots, and this runs at attach on a live process.
        var backPointers = new Dictionary<ulong, ulong>();

        for (int slotIndex = 0; slotIndex < slots; slotIndex++)
        {
            var anchored = new bool[corpus.Count];
            int anchorCount = 0;

            for (int i = 0; i < corpus.Count; i++)
            {
                ulong aux = corpus[i].Slots[slotIndex];
                if (aux < StaticsEncoding.MinimumPlausibleAddress || (aux & 7) != 0) continue;

                if (!backPointers.TryGetValue(aux, out ulong back))
                {
                    back = memory.TryReadPointer(aux - (ulong)layouts.PointerSize, out ulong read) ? read : 0;
                    backPointers[aux] = back;
                }

                if (back != corpus[i].MethodTable) continue;

                anchored[i] = true;
                anchorCount++;
            }

            if (anchorCount < MinimumGateSetTypes || corpus.Count - anchorCount < MinimumGateClearTypes) continue;

            for (int bit = 0; bit < 32; bit++)
            {
                bool agrees = true;
                for (int i = 0; i < corpus.Count && agrees; i++)
                {
                    agrees = (((corpus[i].Flags2 >> bit) & 1) != 0) == anchored[i];
                }

                if (agrees) results.Add((slotIndex * layouts.PointerSize, bit, anchorCount));
            }
        }

        return results;
    }

    /// <summary>
    /// Score one hypothesis about which <c>DynamicStaticsInfo</c> member is the GC base, by
    /// reading <c>CLASS</c> statics through it and asking whether what comes back is an object.
    /// </summary>
    /// <remarks>
    /// Thread statics are excluded: their offsets index per-thread storage, so including them
    /// would charge garbage against whichever ordering is correct. Uninitialised classes and zero
    /// bases are skipped rather than counted — neither says anything about the ordering.
    /// </remarks>
    private static (int Valid, int Garbage) ScoreBaseOrdering(
        IMemoryReader memory,
        ClrLayouts layouts,
        FieldDescEncoding fieldDesc,
        List<StaticFieldSample> statics,
        int elementTypeShift,
        bool gcIsFirst)
    {
        int valid = 0, garbage = 0;

        foreach (StaticFieldSample sample in statics)
        {
            if (sample.DeclaredThreadStatic) continue;

            var elementType = (ClrElementType)(byte)((sample.OffsetWord >> elementTypeShift) & 0x1F);
            if (elementType != ClrElementType.Class) continue;

            ulong raw = gcIsFirst ? sample.FirstBaseRaw : sample.SecondBaseRaw;
            if ((raw & StaticsEncoding.ClassNotInitedFlag) != 0) continue;

            ulong basePointer = raw & ~(ulong)StaticsEncoding.ClassNotInitedFlag;
            if (basePointer == 0) continue;

            uint offset = FieldDescEncoding.Decode(sample.OffsetWord, fieldDesc.OffsetBitShift, fieldDesc.OffsetBitWidth);
            if (!memory.TryReadPointer(basePointer + offset, out ulong value))
            {
                garbage++;
                continue;
            }

            if (value == 0) continue;

            if (layouts.TryReadMethodTableOf(memory, value, out ulong methodTable) &&
                layouts.IsMethodTableShaped(memory, methodTable))
            {
                valid++;
            }
            else
            {
                garbage++;
            }
        }

        return (valid, garbage);
    }

    /// <summary>
    /// The <c>FieldDesc</c> bit that is set for exactly the fields metadata marks
    /// <c>[ThreadStatic]</c>.
    /// </summary>
    private static (FieldDescFlagBit Bit, int Positives, int Candidates) FindThreadStaticBit(
        List<StaticFieldSample> statics)
    {
        int positives = statics.Count(s => s.DeclaredThreadStatic);
        if (positives == 0 || statics.Count - positives < MinimumThreadStaticNegatives)
        {
            return (FieldDescFlagBit.None, positives, 0);
        }

        var matches = new List<FieldDescFlagBit>();

        for (int byteOffset = 0; byteOffset + 4 <= FieldDescProbeBytes; byteOffset += 4)
        {
            for (int bit = 0; bit < 32; bit++)
            {
                bool agrees = true;
                foreach (StaticFieldSample sample in statics)
                {
                    uint word = BitConverter.ToUInt32(sample.Bytes, byteOffset);
                    if ((((word >> bit) & 1) != 0) == sample.DeclaredThreadStatic) continue;

                    agrees = false;
                    break;
                }

                if (agrees) matches.Add(new FieldDescFlagBit(byteOffset, bit));
            }
        }

        return matches.Count == 1
            ? (matches[0], positives, 1)
            : (FieldDescFlagBit.None, positives, matches.Count);
    }

    /// <summary>
    /// Walks CoreLib's own loaded types, keeping each method table's whole header.
    /// </summary>
    /// <remarks>
    /// The same self-validating walk <see cref="FieldDescCalibration"/> uses: every type comes out
    /// of <c>Module.TypeDefToMethodTableMap</c> and is kept only if its <c>MethodTable.Module</c>
    /// points back at the module it was walked out of, so an entry read past a segment boundary
    /// (§5.4) cannot enter the corpus. The header is read ONCE per type — the slot sweep then
    /// costs no further reads except one per distinct auxiliary candidate.
    /// </remarks>
    private static List<TypeSample> CollectTypes(
        IMemoryReader memory,
        ClrLayouts layouts,
        ulong modulePointer,
        ModuleMetadata corelib,
        int flags2Offset)
    {
        var corpus = new List<TypeSample>();

        ulong typeMap = modulePointer + (ulong)layouts.ModuleTypeDefMapOffset;
        if (!memory.TryReadPointer(typeMap + (ulong)layouts.LookupMapTableDataOffset, out ulong table) || table == 0)
        {
            return corpus;
        }

        int stride = layouts.PointerSize;
        int slots = MethodTableProbeBytes / stride;
        int typeCount = corelib.Reader.TypeDefinitions.Count;
        var raw = new byte[Math.Max(4096 / stride, 1) * stride];
        var header = new byte[MethodTableProbeBytes];

        for (int first = 1; first <= typeCount && corpus.Count < MaxCorpusTypes;)
        {
            ulong address = table + ((ulong)first * (ulong)stride);

            // Clipped to a page, so an unmapped one costs only the rids it holds.
            int count = ClrLayouts.EntriesWithinPage(address, stride, typeCount - first + 1);
            if (!memory.TryRead(address, raw.AsSpan(0, count * stride)))
            {
                first += count;
                continue;
            }

            for (int i = 0; i < count && corpus.Count < MaxCorpusTypes; i++)
            {
                // Low bits carry lookup-map flags (§5.4).
                ulong methodTable = (stride == 8 ? BitConverter.ToUInt64(raw, i * 8) : BitConverter.ToUInt32(raw, i * 4)) & ~7UL;
                if (methodTable == 0) continue;
                if (!memory.TryReadPointer(methodTable + (ulong)layouts.MethodTableModuleOffset, out ulong owner)) continue;
                if (owner != modulePointer) continue;
                if (!memory.TryRead(methodTable, header)) continue;

                var values = new ulong[slots];
                for (int slot = 0; slot < slots; slot++)
                {
                    values[slot] = stride == 8
                        ? BitConverter.ToUInt64(header, slot * 8)
                        : BitConverter.ToUInt32(header, slot * 4);
                }

                corpus.Add(new TypeSample(
                    first + i, methodTable, BitConverter.ToUInt32(header, flags2Offset), values));
            }

            first += count;
        }

        return corpus;
    }

    /// <summary>
    /// Static field descriptors of the gate-set types, paired with the two candidate bases of the
    /// type that declares them.
    /// </summary>
    /// <remarks>
    /// The declaring back-pointer is required to match EXACTLY, not merely by module. Instance
    /// fields have to settle for module granularity because a generic instantiation's fields are
    /// described by the canonical type's descriptors — but §14.0 measured every one of 27,732
    /// static descriptors pointing back at the precise method table it was reached from, so the
    /// stricter check costs nothing and rules out more.
    /// </remarks>
    private static List<StaticFieldSample> CollectStaticFields(
        IMemoryReader memory,
        ClrLayouts layouts,
        ulong modulePointer,
        ModuleMetadata corelib,
        FieldDescEncoding fieldDesc,
        List<TypeSample> gateSet,
        int auxiliarySlot,
        int pointerSize)
    {
        var samples = new List<StaticFieldSample>();

        ulong fieldMap = modulePointer + (ulong)layouts.ModuleFieldDefMapOffset;
        int fieldRows = corelib.Reader.FieldDefinitions.Count;

        foreach (TypeSample type in gateSet)
        {
            if (samples.Count >= MaxStaticFields) break;

            ulong aux = type.Slots[auxiliarySlot / pointerSize];
            if (aux < StaticsEncoding.MinimumPlausibleAddress) continue;
            if (!memory.TryReadPointer(aux - (ulong)(3 * pointerSize), out ulong firstBase)) continue;
            if (!memory.TryReadPointer(aux - (ulong)(2 * pointerSize), out ulong secondBase)) continue;

            TypeDefinitionHandle handle = MetadataTokens.TypeDefinitionHandle(type.Rid);
            IReadOnlySet<int> threadStatics = corelib.Types.GetThreadStaticFieldTokens(handle);

            foreach (MetadataField field in corelib.Types.GetFields(handle))
            {
                if (samples.Count >= MaxStaticFields) break;
                if (!field.IsStatic || field.IsLiteral) continue;

                // An RVA static lives in the module image, not in either statics blob (§14.0):
                // it would be scored against a base it never used.
                if ((field.Attributes & FieldAttributes.HasFieldRVA) != 0) continue;

                int rid = field.Token & 0x00FF_FFFF;
                if (!layouts.TryGetLookupMapSlot(memory, fieldMap, rid, fieldRows, out ulong slot)) continue;
                if (!memory.TryReadPointer(slot, out ulong entry)) continue;

                ulong fieldDescAddress = entry & fieldDesc.EntryMask;
                if (fieldDescAddress == 0) continue;

                if (fieldDesc.EnclosingSlot >= 0)
                {
                    if (!fieldDesc.TryReadEnclosingMethodTable(memory, fieldDescAddress, out ulong enclosing)) continue;
                    if (enclosing != type.MethodTable) continue;
                }

                var bytes = new byte[FieldDescProbeBytes];
                if (!memory.TryRead(fieldDescAddress, bytes)) continue;

                samples.Add(new StaticFieldSample(
                    bytes,
                    BitConverter.ToUInt32(bytes, fieldDesc.OffsetByteOffset),
                    threadStatics.Contains(field.Token),
                    firstBase,
                    secondBase));
            }
        }

        return samples;
    }
}
