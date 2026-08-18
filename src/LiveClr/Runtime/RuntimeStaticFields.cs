namespace LiveClr.Runtime;

using System.Reflection;
using System.Reflection.Metadata;
using LiveClr.Memory;
using LiveClr.Metadata;

/// <summary>
/// Why a static field did or did not resolve to an address.
/// </summary>
/// <remarks>
/// Every value other than <see cref="Resolved"/> is a REFUSAL, and they are kept apart on
/// purpose: §14.0's whole lesson is that the dangerous outcomes here are the ones that look like
/// answers, so a caller diagnosing a missing static needs to know whether the runtime says the
/// type has no statics at all, whether the field is thread-local, or whether the class simply has
/// no storage yet.
/// </remarks>
public enum ClrStaticStatus
{
    /// <summary>An address was produced.</summary>
    Resolved,

    /// <summary>
    /// <see cref="StaticsCalibration"/> did not converge on this runtime, so nothing here can be
    /// answered from the target. Supply the address through <see cref="IClrStaticRootSource"/>.
    /// </summary>
    NotCalibrated,

    /// <summary>The type does not declare a field by that name, or has no metadata at all.</summary>
    NotDeclared,

    /// <summary>The field exists but is an instance field.</summary>
    NotStatic,

    /// <summary>A <c>const</c>. It has no storage anywhere, so no address is the correct answer.</summary>
    Literal,

    /// <summary>
    /// An RVA static (<c>FieldAttributes.HasFieldRVA</c>). Its bytes live in the module image, not
    /// in either statics blob, so the auxiliary bases do not address it. §14.0 counted 243 of them
    /// — enough that silently falling through would matter.
    /// </summary>
    RvaStatic,

    /// <summary>
    /// A <c>[ThreadStatic]</c> field. §14.0, correction 2: it passes the gate AND the anchor, and
    /// its offset indexes per-thread storage, so applying the auxiliary bases yields a confident
    /// WRONG address. This is the refusal that exists because the alternative is not a miss.
    /// </summary>
    ThreadStatic,

    /// <summary>
    /// <c>MTFlags2</c>'s statics bit is clear: the runtime says this type has no
    /// <c>DynamicStaticsInfo</c>. §14.0 measured the gate exact — zero of 12,283 types with
    /// statics had it clear — so this is a correct refusal rather than a gap.
    /// </summary>
    NoStaticsStorage,

    /// <summary>
    /// The gate was set but <c>ptr(aux - PointerSize)</c> did not point back at the method table.
    /// The auxiliary pointer is not what it claims; nothing below it can be believed.
    /// </summary>
    AnchorFailed,

    /// <summary>The <c>FieldDefToDescMap</c> has no descriptor for this field, or it was unreadable.</summary>
    NoFieldDescriptor,

    /// <summary>The descriptor found points back at a different method table, so it is not this field's.</summary>
    WrongDeclaringType,

    /// <summary>
    /// The dispatched base is zero and the type is an open generic definition. §14.0, correction
    /// 3: <c>ArrayPool`1.s_shared</c> and <c>EmptyArray`1.Value</c> have no storage of their own,
    /// because statics belong to each INSTANTIATION. Resolving one needs that instantiation's
    /// method table, which a lookup by TypeDef name cannot supply.
    /// </summary>
    OpenGenericDefinition,

    /// <summary>
    /// The raw base read exactly <c>ISCLASSNOTINITED</c>: the type is loaded, but its statics blob
    /// has never been allocated because its static constructor has never run.
    /// </summary>
    /// <remarks>
    /// <b>This corrects §14.0.</b> Correction 3 attributes all 3,385 storage-less GC statics to
    /// open generic definitions, generalising from two generic examples. Measured against the same
    /// process through this implementation, only 83 of 3,747 are generic at all; the rest are
    /// ordinary types — <c>BitConverter.IsLittleEndian</c>, <c>DBNull.Value</c>,
    /// <c>JapaneseCalendar.s_defaultInstance</c> — whose class initialiser simply never ran. That
    /// is a different fact with a different remedy: nothing about the type prevents resolution,
    /// and the address appears the moment the target touches the class. It is kept apart from
    /// <see cref="ClrStaticStatus.NoStorage"/> for the same reason §14.0 insists "null" and "class
    /// not initialised" are not the same state.
    /// </remarks>
    ClassNotInitialized,

    /// <summary>
    /// The dispatched base is zero on a type whose class IS initialised: it has no blob of that
    /// kind at all. Not observed on any runtime measured, and reported rather than folded into a
    /// neighbouring case so that it stays visible if it ever is.
    /// </summary>
    NoStorage,

    /// <summary>The computed address is not mapped in the target, so it is a bad decode.</summary>
    Unreadable,
}

/// <summary>
/// Where one static field's storage is, or why it could not be located.
/// </summary>
/// <param name="Status">The outcome. Only <see cref="ClrStaticStatus.Resolved"/> carries an address.</param>
/// <param name="Address">Address of the SLOT — never of anything it points at.</param>
/// <param name="ElementType">The runtime's own <c>FieldDesc.m_type</c> for the field.</param>
/// <param name="IsGcStatic">True when the field lives in the GC blob rather than the non-GC one.</param>
/// <param name="IsClassInitialized">
/// False when <c>ISCLASSNOTINITED</c> was set on the base used. The address is still correct and
/// still readable; the class's static constructor has just never run, so what is there is the
/// default. §14.0: <c>Boolean.TrueString</c> reads null for exactly this reason in a process that
/// never touched <c>Boolean</c>, and collapsing that into plain "null" loses the distinction
/// between "nothing was ever stored" and "null was stored".
/// </param>
public readonly record struct ClrStaticField(
    ClrStaticStatus Status,
    ulong Address,
    ClrElementType ElementType,
    bool IsGcStatic,
    bool IsClassInitialized)
{
    /// <summary>A refusal, carrying its reason and no address.</summary>
    public static ClrStaticField Refused(ClrStaticStatus status) =>
        new(status, 0, ClrElementType.Unknown, false, false);

    /// <summary>True when <see cref="Address"/> may be used.</summary>
    public bool IsResolved => Status == ClrStaticStatus.Resolved;

    /// <summary>
    /// True when the slot holds a REFERENCE to a boxed instance rather than the value itself.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A value-type static is stored boxed in the GC blob — §14.0 measured 525 of them, every one
    /// resolving to a live boxed object and none null. <see cref="Address"/> is still the slot, so
    /// reading it as the field's declared type would yield the BOX POINTER: <c>DateTime.MinValue</c>
    /// would report ticks of 1798517794032, which is a heap address wearing a plausible-looking
    /// number. That is precisely the failure mode this layer exists to prevent, so the
    /// dereference is a documented step and not an accident of who reads first.
    /// </para>
    /// <para>
    /// The dereference deliberately does NOT happen here. This record is process-tier — the slot
    /// address is loader-heap stable — while the box is an ordinary managed object that the GC
    /// moves (§7b.1). <see cref="ClrType.Static"/> does it, inside a snapshot, where the address
    /// it produces is scoped to a single memory image.
    /// </para>
    /// </remarks>
    public bool IsBoxed => IsGcStatic && ElementType == ClrElementType.ValueType;
}

/// <summary>
/// Resolves static field addresses out of the target's own structures: <c>MethodTable</c> →
/// <c>m_pAuxiliaryData</c> → <c>DynamicStaticsInfo</c> → base + <c>FieldDesc</c> offset (§14).
/// </summary>
/// <remarks>
/// <para>
/// <b>This is the route §5.5 said did not exist.</b> It was wrong on both counts: there is a
/// route, and there is an anchor — <c>DynamicStaticsInfo</c>'s back-pointer to the method table
/// — so nothing on the path is a trusted constant. <see cref="StaticsCalibration"/> derives the
/// auxiliary slot, the <c>MTFlags2</c> gate bit and the GC/non-GC base order from the running
/// target; this class does the per-field half and the refusals.
/// </para>
/// <para>
/// <b>Four things produce a wrong ANSWER rather than a miss if they are skipped</b>, and each has
/// its own refusal above: a thread static (<see cref="ClrStaticStatus.ThreadStatic"/>), an RVA
/// static (<see cref="ClrStaticStatus.RvaStatic"/>), an open generic definition
/// (<see cref="ClrStaticStatus.OpenGenericDefinition"/>), and a per-lookup sweep for the auxiliary
/// slot — which is why the slot is frozen in the calibration and never searched here.
/// </para>
/// <para>
/// <b>The address is stable; the value is not.</b> §7b.1 measured the same singleton at two
/// managed addresses minutes apart. A static's SLOT is loader-heap stable, so resolving it is
/// cheap to repeat and safe to repeat — which is why <see cref="ClrType.Static"/> re-resolves
/// every snapshot rather than remembering an object.
/// </para>
/// </remarks>
public sealed class RuntimeStaticFieldSource
{
    private readonly ClrLayouts _layouts;
    private readonly FieldDescCalibration _fieldDescs;

    /// <summary>Wrap the two derivations this depends on.</summary>
    public RuntimeStaticFieldSource(ClrLayouts layouts, StaticsCalibration statics, FieldDescCalibration fieldDescs)
    {
        ArgumentNullException.ThrowIfNull(layouts);
        ArgumentNullException.ThrowIfNull(statics);
        ArgumentNullException.ThrowIfNull(fieldDescs);

        _layouts = layouts;
        _fieldDescs = fieldDescs;
        Calibration = statics;
    }

    /// <summary>The statics derivation this source depends on.</summary>
    public StaticsCalibration Calibration { get; }

    /// <summary>True when static addresses can be read from the runtime at all.</summary>
    public bool IsUsable => Calibration.IsCalibrated && _fieldDescs.IsCalibrated;

    /// <summary>
    /// Locate <paramref name="fieldName"/> declared as a static on <paramref name="type"/>.
    /// </summary>
    /// <remarks>
    /// Declared, not inherited: a static belongs to the type that declares it, and the runtime
    /// stores it in that type's blob. Walking ancestors is the caller's job — see
    /// <see cref="ClrType.Static"/>, which does it for the same reason
    /// <see cref="ClrTypeSystem.TryGetFieldLocation"/> does.
    /// </remarks>
    public ClrStaticField Resolve(IMemoryReader memory, ClrTypeInfo type, string fieldName)
    {
        ArgumentNullException.ThrowIfNull(memory);
        ArgumentNullException.ThrowIfNull(type);
        ArgumentNullException.ThrowIfNull(fieldName);

        if (Calibration.Encoding is not StaticsEncoding encoding ||
            _fieldDescs.Encoding is not FieldDescEncoding fieldDesc)
        {
            return ClrStaticField.Refused(ClrStaticStatus.NotCalibrated);
        }

        if (type.Module is null || type.TypeDefinition.IsNil) return ClrStaticField.Refused(ClrStaticStatus.NotDeclared);
        if (!type.TryGetDeclaredField(fieldName, out MetadataField field))
        {
            return ClrStaticField.Refused(ClrStaticStatus.NotDeclared);
        }

        if (!field.IsStatic) return ClrStaticField.Refused(ClrStaticStatus.NotStatic);
        if (field.IsLiteral) return ClrStaticField.Refused(ClrStaticStatus.Literal);
        if ((field.Attributes & FieldAttributes.HasFieldRVA) != 0)
        {
            return ClrStaticField.Refused(ClrStaticStatus.RvaStatic);
        }

        // Metadata is the authority on [ThreadStatic]: the attribute is in the target's own blob,
        // and it is checked BEFORE anything is read, so the wrong address is never even computed.
        if (type.Module.Metadata.Types.GetThreadStaticFieldTokens(type.TypeDefinition).Contains(field.Token))
        {
            return ClrStaticField.Refused(ClrStaticStatus.ThreadStatic);
        }

        if (!encoding.HasDynamicStatics(memory, type.MethodTable))
        {
            return ClrStaticField.Refused(ClrStaticStatus.NoStaticsStorage);
        }

        if (!encoding.TryReadBases(memory, type.MethodTable, out StaticsBases bases))
        {
            return ClrStaticField.Refused(ClrStaticStatus.AnchorFailed);
        }

        if (!TryReadDescriptor(
                memory, fieldDesc, type, field, out ulong descriptor, out uint word, out ClrStaticStatus failure))
        {
            return ClrStaticField.Refused(failure);
        }

        // The runtime's own second opinion on thread-locality, derived rather than assumed. It
        // agrees with the attribute on every runtime measured; where it cannot be derived at all
        // the attribute stands alone, which is why the attribute is checked first and not instead.
        // A bit that cannot be READ is a refusal, not a pass: the failure this guards is a
        // confident wrong address, so "could not tell" has to fall on the safe side.
        if (encoding.ThreadStaticBit.IsDerived)
        {
            if (!encoding.ThreadStaticBit.TryRead(memory, descriptor, out bool threadLocal))
            {
                return ClrStaticField.Refused(ClrStaticStatus.NoFieldDescriptor);
            }

            if (threadLocal) return ClrStaticField.Refused(ClrStaticStatus.ThreadStatic);
        }

        ClrElementType elementType = encoding.DecodeElementType(word);
        bool isGc = StaticsEncoding.IsGcStatic(elementType);
        ulong basePointer = isGc ? bases.GcStatics : bases.NonGcStatics;
        bool initialized = isGc ? bases.GcClassInitialized : bases.NonGcClassInitialized;

        if (basePointer == 0)
        {
            if (IsGenericDefinition(type)) return ClrStaticField.Refused(ClrStaticStatus.OpenGenericDefinition);

            return ClrStaticField.Refused(
                initialized ? ClrStaticStatus.NoStorage : ClrStaticStatus.ClassNotInitialized);
        }

        uint offset = FieldDescEncoding.Decode(word, fieldDesc.OffsetBitShift, fieldDesc.OffsetBitWidth);
        ulong address = basePointer + offset;

        // A decoded offset is 27 bits wide, so a bad decode addresses something tens of megabytes
        // past a real blob rather than something subtly wrong. One byte proves it is mapped.
        Span<byte> probe = stackalloc byte[1];
        if (!memory.TryRead(address, probe)) return ClrStaticField.Refused(ClrStaticStatus.Unreadable);

        return new ClrStaticField(ClrStaticStatus.Resolved, address, elementType, isGc, initialized);
    }

    /// <summary>
    /// Read the word holding a static's offset and element type out of its <c>FieldDesc</c>.
    /// </summary>
    /// <remarks>
    /// The declaring back-pointer must match EXACTLY. Instance fields settle for module
    /// granularity because a generic instantiation's fields are described by the canonical type's
    /// descriptors, but §14.0 measured all 27,732 static descriptors pointing back at the precise
    /// method table they were reached from, so anything less here would be looser than the
    /// evidence requires.
    /// </remarks>
    private bool TryReadDescriptor(
        IMemoryReader memory,
        FieldDescEncoding fieldDesc,
        ClrTypeInfo type,
        MetadataField field,
        out ulong descriptor,
        out uint offsetWord,
        out ClrStaticStatus failure)
    {
        descriptor = 0;
        offsetWord = 0;
        failure = ClrStaticStatus.NoFieldDescriptor;

        ulong mapAddress = type.Module!.ModulePointer + (ulong)_layouts.ModuleFieldDefMapOffset;
        int rid = field.Token & 0x00FF_FFFF;
        int rowCount = type.Module.Metadata.Reader.FieldDefinitions.Count;

        if (!_layouts.TryGetLookupMapSlot(memory, mapAddress, rid, rowCount, out ulong slot)) return false;
        if (!memory.TryReadPointer(slot, out ulong entry)) return false;

        ulong fieldDescAddress = entry & fieldDesc.EntryMask;
        if (fieldDescAddress == 0) return false;

        if (fieldDesc.EnclosingSlot >= 0)
        {
            if (!fieldDesc.TryReadEnclosingMethodTable(memory, fieldDescAddress, out ulong enclosing) ||
                enclosing != type.MethodTable)
            {
                failure = ClrStaticStatus.WrongDeclaringType;
                return false;
            }
        }

        if (!memory.TryRead(fieldDescAddress + (ulong)fieldDesc.OffsetByteOffset, out uint word)) return false;

        descriptor = fieldDescAddress;
        offsetWord = word;
        return true;
    }

    /// <summary>
    /// Whether this method table describes an open generic definition, i.e. one whose statics
    /// belong to instantiations rather than to it.
    /// </summary>
    /// <remarks>
    /// <b>The nesting chain has to be walked.</b> Checking only the type's own generic parameters
    /// classified 83 of the 3,747 storage-less statics in a live process; the rest are types like
    /// <c>SharedArrayPool`1+&lt;&gt;c</c> and <c>Array+EmptyArray`1</c>, which are as
    /// instantiation-bound as their enclosing type and declare nothing themselves. Cycle-safe and
    /// depth-capped for the same reason <see cref="LiveClr.Metadata.TypeResolver"/> is: the
    /// <c>NestedClass</c> table is never validated, so it is hostile input (§7b.1).
    /// </remarks>
    private static bool IsGenericDefinition(ClrTypeInfo type)
    {
        try
        {
            MetadataReader reader = type.Module!.Metadata.Reader;
            TypeDefinitionHandle current = type.TypeDefinition;
            var seen = new HashSet<TypeDefinitionHandle>();

            for (int depth = 0; depth < TypeResolver.MaxNestingDepth && seen.Add(current); depth++)
            {
                TypeDefinition definition = reader.GetTypeDefinition(current);
                if (definition.GetGenericParameters().Count > 0) return true;
                if (!definition.IsNested) return false;

                TypeDefinitionHandle declaring = definition.GetDeclaringType();
                if (declaring.IsNil) return false;

                current = declaring;
            }

            return false;
        }
        catch (BadImageFormatException)
        {
            return false;
        }
    }
}
