namespace LiveClr.Runtime;

using LiveClr.Memory;
using LiveClr.Metadata;

/// <summary>
/// Resolves instance field offsets out of the target's own <c>FieldDesc</c> structures:
/// metadata token → <c>Module.FieldDefToDescMap</c> → <c>FieldDesc</c> → offset.
/// </summary>
/// <remarks>
/// <para>
/// <b>What the descriptor gives, and what it does not.</b> The .NET 9 contract descriptor
/// (§5.2) publishes <c>Module.FieldDefToDescMap</c> (432) and <c>ModuleLookupMap.TableData</c>
/// (8), so the first hop — token to <c>FieldDesc</c> address — needs nothing hardcoded. It
/// publishes no <c>FieldDesc</c> type at all, so the second hop has no published layout. That
/// is the §5.5 gap at its sharpest, and this class does not paper over it: the second hop uses
/// a <see cref="FieldDescCalibration"/> derived from the runtime's own published
/// <c>System.Exception</c> offsets, and if that derivation does not converge, every lookup
/// here returns false.
/// </para>
/// <para>
/// <b>Two validations before an offset is believed.</b> The <c>FieldDesc</c> must point back
/// at a method table belonging to the same module as the type being resolved (when the
/// calibration found the back-pointer slot at all), and the decoded offset must fit inside
/// <c>MethodTable.BaseSize</c>. §12.4e is the reason: an offset that is merely plausible is
/// worse than no offset, because it produces a card or an enemy with quietly wrong numbers
/// instead of an error.
/// </para>
/// <para>
/// <b>Statics are out of scope here.</b> A static field's <c>FieldDesc</c> offset is relative
/// to a statics base the descriptor does not publish (there is no <c>DomainLocalModule</c> and
/// no <c>MethodTable</c> auxiliary-data entry among its 29 types), so statics are answered by
/// <see cref="IClrStaticRootSource"/> instead.
/// </para>
/// </remarks>
public sealed class RuntimeFieldLayoutSource : IClrFieldLayoutSource
{
    private readonly ClrLayouts _layouts;

    /// <summary>Wrap a calibration result.</summary>
    public RuntimeFieldLayoutSource(ClrLayouts layouts, FieldDescCalibration calibration)
    {
        ArgumentNullException.ThrowIfNull(layouts);
        ArgumentNullException.ThrowIfNull(calibration);
        _layouts = layouts;
        Calibration = calibration;
    }

    /// <summary>The derivation this source depends on.</summary>
    public FieldDescCalibration Calibration { get; }

    /// <summary>True when field offsets can be read from the runtime at all.</summary>
    public bool IsUsable => Calibration.IsCalibrated;

    /// <inheritdoc/>
    public bool TryGetField(IMemoryReader memory, ClrTypeInfo type, string fieldName, out ClrFieldLocation location)
    {
        location = default;

        if (Calibration.Encoding is not FieldDescEncoding encoding) return false;
        if (memory is null || type?.Module is null || fieldName is null) return false;
        if (!type.TryGetDeclaredField(fieldName, out MetadataField field)) return false;
        if (field.IsStatic || field.IsLiteral) return false;

        ulong mapAddress = type.Module.ModulePointer + (ulong)_layouts.ModuleFieldDefMapOffset;
        int rid = field.Token & 0x00FF_FFFF;

        // The Field table's row count is the only bound available — the map's own Count is
        // unpublished (§5.4). See ClrLayouts.TryGetLookupMapSlot.
        int rowCount = type.Module.Metadata.Reader.FieldDefinitions.Count;

        if (!_layouts.TryGetLookupMapSlot(memory, mapAddress, rid, rowCount, out ulong slot)) return false;
        if (!memory.TryReadPointer(slot, out ulong entry)) return false;

        ulong fieldDesc = entry & encoding.EntryMask;
        if (fieldDesc == 0) return false;
        if (!IsForThisType(memory, encoding, fieldDesc, type)) return false;
        if (!encoding.TryDecodeOffset(memory, fieldDesc, out int fieldDescOffset)) return false;

        int objectRelative = fieldDescOffset + _layouts.FirstFieldOffset;

        // BaseSize is the size of an instance with no elements, so every instance field of a
        // non-array type must fit inside it. A decoded offset that does not is not a field.
        //
        // The bound is NOT conditional on having a BaseSize. Live validation showed this guard
        // is what keeps a mis-derived FieldDesc encoding fail-safe: it caught 8 of 8 broken
        // fields while the calibrated width was one bit too wide, because a swallowed m_type bit
        // adds 0x8000000 and no object is that large. A `BaseSize > 0` precondition made that
        // protection evaporate for exactly the types whose header could not be read — the ones
        // least worth trusting. An unreadable or zero BaseSize is now a refusal: every object
        // has at least a method-table pointer, so zero means the read failed or the method table
        // is not one, and neither is a footing for handing out an offset.
        if (type.BaseSize <= (uint)_layouts.FirstFieldOffset) return false;
        if ((uint)objectRelative >= type.BaseSize) return false;

        location = new ClrFieldLocation(fieldName, objectRelative, FieldOffsetSource.Runtime);
        return true;
    }

    /// <summary>
    /// Checks the <c>FieldDesc</c> belongs to the type we asked about.
    /// </summary>
    /// <remarks>
    /// Compared at MODULE granularity rather than by method table, because a generic
    /// instantiation's fields are described by the canonical type's <c>FieldDesc</c>s: the
    /// back-pointer for <c>List&lt;Foo&gt;._items</c> is <c>List&lt;__Canon&gt;</c>, not
    /// <c>List&lt;Foo&gt;</c>. Module identity still rules out reading a garbage pointer,
    /// which is what the check is for.
    /// <para>
    /// No back-pointer slot means no cross-check, and the only remaining guard is the
    /// <c>BaseSize</c> bound below. <see cref="FieldDescCalibration"/> therefore settles for an
    /// encoding without one only when NO candidate entry mask produced one; see its
    /// <c>EntryMasks</c> remark.
    /// </para>
    /// </remarks>
    private bool IsForThisType(IMemoryReader memory, FieldDescEncoding encoding, ulong fieldDesc, ClrTypeInfo type)
    {
        if (encoding.EnclosingSlot < 0) return true;
        if (!encoding.TryReadEnclosingMethodTable(memory, fieldDesc, out ulong enclosing)) return false;
        if (enclosing == type.MethodTable) return true;

        return memory.TryReadPointer(enclosing + (ulong)_layouts.MethodTableModuleOffset, out ulong modulePointer)
            && modulePointer == type.Module!.ModulePointer;
    }
}
