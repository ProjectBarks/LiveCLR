namespace LiveClr.Runtime;

using System.Text;
using LiveClr.Memory;
using LiveClr.Metadata;

/// <summary>
/// A live type, scoped to the snapshot that produced it.
/// </summary>
/// <remarks>
/// A thin snapshot-tier face over process-tier <see cref="ClrTypeInfo"/>. The split matters:
/// the description of a type is cacheable for the life of the process (§8.8), but anything
/// that READS — a static's current value, a base type reached by following a pointer — must be
/// scoped to a snapshot.
/// </remarks>
public sealed class ClrType : IClrType
{
    private readonly ISnapshotContext _context;

    internal ClrType(ISnapshotContext context, ClrTypeInfo info)
    {
        _context = context;
        Info = info;
    }

    /// <summary>The process-tier description behind this handle.</summary>
    public ClrTypeInfo Info { get; }

    /// <inheritdoc/>
    public string Name => Info.Name;

    /// <inheritdoc/>
    public ulong MethodTable => Info.MethodTable;

    /// <inheritdoc/>
    public IClrType? BaseType
    {
        get
        {
            if (_context.IsDisposed) return null;
            ClrTypeInfo? parent = Info.Parent(_context.Memory);
            return parent is null ? null : new ClrType(_context, parent);
        }
    }

    /// <summary>
    /// Instance field names visible on this type, including inherited ones, most-derived first.
    /// </summary>
    /// <remarks>
    /// §12.4 (API fact 1): field names belong to the CLASS, not the object, and enumerating
    /// them per object is "the single biggest cost in a naive traversal". They are cached on
    /// <see cref="ClrTypeInfo"/>, which is process-tier.
    /// </remarks>
    public IReadOnlyCollection<string> FieldNames =>
        _context.IsDisposed ? [] : _context.TypeSystem.GetAllFieldNames(_context.Memory, Info);

    /// <inheritdoc/>
    public bool HasField(string name)
    {
        if (name is null || _context.IsDisposed) return false;

        foreach (ClrTypeInfo type in Info.WithAncestors(_context.Memory))
        {
            if (type.TryGetDeclaredField(name, out MetadataField field) && !field.IsStatic) return true;
        }

        return false;
    }

    /// <summary>
    /// The current value of a static field.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Re-read every time, never remembered. §7b.1: the static's SLOT is loader-heap stable,
    /// but the object it points at moved between two observations of the same singleton
    /// minutes apart.
    /// </para>
    /// <para>
    /// The runtime is asked first (§14, via <see cref="RuntimeStaticFieldSource"/>) and a
    /// caller-supplied <see cref="IClrStaticRootSource"/> second — the same order, and the same
    /// reason, as <see cref="CompositeFieldLayoutSource"/>: a runtime that can answer is believed
    /// over a hand-maintained table, so a stale address is corrected rather than trusted. Returns
    /// null when neither can locate the slot; <see cref="ResolveStatic"/> says which refusal it
    /// was.
    /// </para>
    /// </remarks>
    public IClrValue? Static(string fieldName)
    {
        if (fieldName is null || _context.IsDisposed) return null;

        foreach (ClrTypeInfo type in Info.WithAncestors(_context.Memory))
        {
            if (!type.TryGetDeclaredField(fieldName, out MetadataField field)) continue;
            if (!field.IsStatic || field.IsLiteral) continue;

            ClrStaticField resolved = _context.TypeSystem.StaticFields.Resolve(_context.Memory, type, fieldName);

            if (resolved.IsResolved)
            {
                if (!resolved.IsBoxed) return new ClrValue(_context, resolved.Address, type.GetFieldShape(fieldName));

                // A value-type static lives BOXED in the GC blob (§14.0). Reading the slot as the
                // declared type would hand back the box pointer as if it were the value, so the
                // reference is followed and the payload — one object header in — is what the
                // caller gets. Validated first: a slot that does not address a real object
                // produces nothing rather than a struct read out of whatever was there.
                if (!_context.Memory.TryReadPointer(resolved.Address, out ulong box) || box == 0) return null;
                if (!_context.TypeSystem.TryGetTypeOfObject(_context.Memory, box, out _)) return null;

                return new ClrValue(
                    _context,
                    box + (ulong)_context.TypeSystem.Layouts.FirstFieldOffset,
                    type.GetFieldShape(fieldName));
            }

            if (!_context.StaticRoots.TryGetStaticAddress(_context.Memory, type.Name, fieldName, out ulong address)) continue;
            if (address == 0) continue;

            return new ClrValue(_context, address, type.GetFieldShape(fieldName));
        }

        return null;
    }

    /// <summary>
    /// What the runtime route made of a static field, refusal reason included.
    /// </summary>
    /// <remarks>
    /// Diagnostic, and deliberately NOT what <see cref="Static"/> returns: the refusals are the
    /// interesting part (§14.0), and a caller that gets null from <see cref="Static"/> otherwise
    /// cannot tell "this type has no statics" from "this field is thread-local" from "the class
    /// has never been initialised". Reports on the type that DECLARES the field, walking
    /// ancestors as <see cref="Static"/> does.
    /// </remarks>
    public ClrStaticField ResolveStatic(string fieldName)
    {
        if (fieldName is null) return ClrStaticField.Refused(ClrStaticStatus.NotDeclared);
        if (_context.IsDisposed) return ClrStaticField.Refused(ClrStaticStatus.NotCalibrated);

        ClrStaticField last = ClrStaticField.Refused(ClrStaticStatus.NotDeclared);

        foreach (ClrTypeInfo type in Info.WithAncestors(_context.Memory))
        {
            if (!type.TryGetDeclaredField(fieldName, out MetadataField field) || !field.IsStatic) continue;

            last = _context.TypeSystem.StaticFields.Resolve(_context.Memory, type, fieldName);
            if (last.IsResolved) return last;
        }

        return last;
    }

    /// <inheritdoc/>
    public override string ToString() => Info.ToString();
}

/// <summary>
/// A live object, scoped to the snapshot that produced it.
/// </summary>
public sealed class ClrObject : IClrObject
{
    private readonly ISnapshotContext _context;

    internal ClrObject(ISnapshotContext context, ulong address, ClrTypeInfo type)
    {
        _context = context;
        Address = address;
        TypeInfo = type;
    }

    /// <inheritdoc/>
    /// <remarks>
    /// Diagnostic only, and §7b.1 is why the interface says so: the same singleton reported
    /// <c>0x1a974c6c3e0</c> and later <c>0x1a974c6c240</c>. A compacting GC moved it. An
    /// address that outlives its snapshot is not stale in a detectable way — it points at
    /// something else entirely plausible.
    /// </remarks>
    public ulong Address { get; }

    /// <summary>Process-tier description of this object's type.</summary>
    public ClrTypeInfo TypeInfo { get; }

    /// <inheritdoc/>
    public IClrType Type => new ClrType(_context, TypeInfo);

    /// <inheritdoc/>
    public IClrValue? Field(string name)
    {
        if (name is null || _context.IsDisposed) return null;
        if (!_context.TypeSystem.TryGetFieldLocation(
                _context.Memory, TypeInfo, name, out ClrFieldLocation location, out ClrTypeInfo declaring))
        {
            return null;
        }

        return new ClrValue(_context, Address + (ulong)location.Offset, declaring.GetFieldShape(name));
    }

    /// <summary>Where a field lives, for diagnostics and for verifying a profile against the runtime.</summary>
    public bool TryGetFieldLocation(string name, out ClrFieldLocation location)
    {
        location = default;
        if (name is null || _context.IsDisposed) return false;
        return _context.TypeSystem.TryGetFieldLocation(_context.Memory, TypeInfo, name, out location, out _);
    }

    /// <inheritdoc/>
    public override string ToString() => $"{TypeInfo.Name} @ 0x{Address:X}";
}

/// <summary>
/// A slot in the target: an address plus what metadata says is stored there.
/// </summary>
/// <remarks>
/// <para>
/// A value is a POSITION, not a copy. Nothing is read until something is asked of it, so a
/// field access that is never followed costs no round trips — which is what keeps §12.4's
/// "walk the whole run state at 4 Hz" affordable.
/// </para>
/// <para>
/// <b>Every dereference validates.</b> <see cref="AsObject"/> reads a pointer and then checks
/// that it addresses a real method table before producing an object. That check is why a slot
/// whose declared type is a generic parameter, or an array element whose element type could
/// not be identified, is still safe to follow: a wrong pointer fails to validate rather than
/// producing a convincing object (§12.4e).
/// </para>
/// </remarks>
public sealed class ClrValue : IClrValue
{
    private readonly ISnapshotContext _context;

    internal ClrValue(ISnapshotContext context, ulong address, ClrFieldShape shape)
    {
        _context = context;
        Address = address;
        Shape = shape;
    }

    /// <summary>Address of the slot itself, not of anything it points at.</summary>
    public ulong Address { get; }

    /// <summary>What the declared type says about this slot.</summary>
    public ClrFieldShape Shape { get; }

    /// <summary>A slot that does not exist. Returned instead of null where an interface forbids null.</summary>
    internal static ClrValue None(ISnapshotContext context) => new(context, 0, ClrFieldShape.Unknown);

    /// <inheritdoc/>
    public bool IsNull
    {
        get
        {
            if (Address == 0 || _context.IsDisposed) return true;
            if (CanHoldReference && _context.Memory.TryReadPointer(Address, out ulong pointer)) return pointer == 0;
            return false;
        }
    }

    /// <inheritdoc/>
    public IClrObject? AsObject()
    {
        if (Address == 0 || _context.IsDisposed) return null;

        // An inline struct or primitive is not a reference; following it would read whatever
        // its first bytes happen to be. Metadata already told us, so believe it.
        if (!CanHoldReference) return null;
        if (!_context.Memory.TryReadPointer(Address, out ulong target) || target == 0) return null;
        if (!_context.TypeSystem.TryGetTypeOfObject(_context.Memory, target, out ClrTypeInfo? type)) return null;

        return new ClrObject(_context, target, type);
    }

    /// <inheritdoc/>
    public IClrArray? AsArray()
    {
        if (AsObject() is not ClrObject obj) return null;
        if (!obj.TypeInfo.IsArray) return null;

        return new ClrArray(_context, obj.Address, obj.TypeInfo);
    }

    /// <inheritdoc/>
    public IClrList? AsList()
    {
        if (AsObject() is not ClrObject obj) return null;
        if (!obj.TypeInfo.IsList) return null;

        return ClrList.Create(_context, obj);
    }

    /// <inheritdoc/>
    public string? AsString()
    {
        if (AsObject() is not ClrObject obj) return null;
        if (!obj.TypeInfo.IsString) return null;

        return ReadString(_context, obj.Address);
    }

    /// <inheritdoc/>
    /// <remarks>
    /// Returns <c>default</c> on a failed read rather than throwing. §4.8 keeps the throwing
    /// form available on the memory layer for callers that want it; at this level a torn read
    /// is a normal event during a live walk, and §6.4's retry belongs above.
    /// </remarks>
    public T Read<T>() where T : unmanaged
    {
        if (Address == 0 || _context.IsDisposed) return default;
        return _context.Memory.TryRead(Address, out T value) ? value : default;
    }

    /// <summary>Read with an explicit success flag, for callers that must tell zero from unreadable.</summary>
    public bool TryRead<T>(out T value) where T : unmanaged
    {
        value = default;
        if (Address == 0 || _context.IsDisposed) return false;
        return _context.Memory.TryRead(Address, out value);
    }

    /// <summary>The object reference stored in this slot, unvalidated. Diagnostic only.</summary>
    public ulong ReadPointer() =>
        Address != 0 && !_context.IsDisposed && _context.Memory.TryReadPointer(Address, out ulong p) ? p : 0;

    /// <summary>
    /// True when the declared type permits an object reference. Unknown shapes are permitted:
    /// a generic parameter or an unsignatured slot may well be one, and
    /// <see cref="AsObject"/> validates the target anyway.
    /// </summary>
    private bool CanHoldReference =>
        Shape.IsReference || Shape.ElementType is ClrElementType.Unknown or ClrElementType.Var or ClrElementType.MVar;

    /// <summary>
    /// Decode a <c>System.String</c> instance.
    /// </summary>
    /// <remarks>
    /// <c>String.m_StringLength</c> (8) and <c>String.m_FirstChar</c> (12) are published by the
    /// descriptor (§5.2); nothing here is hardcoded. The length is validated before it is used
    /// to size a read, because a torn read of the length field would otherwise turn one bad
    /// pointer into a multi-megabyte allocation.
    /// </remarks>
    internal static string? ReadString(ISnapshotContext context, ulong address)
    {
        ClrLayouts layouts = context.TypeSystem.Layouts;

        if (!context.Memory.TryRead(address + (ulong)layouts.StringLengthOffset, out int length)) return null;
        if (length == 0) return string.Empty;

        if (length < 0 || length > MaxStringLength)
        {
            context.NoteAnomaly($"string at 0x{address:X} reports an implausible length of {length}");
            return null;
        }

        var bytes = new byte[length * 2];
        if (!context.Memory.TryRead(address + (ulong)layouts.StringFirstCharOffset, bytes)) return null;

        return Encoding.Unicode.GetString(bytes);
    }

    /// <summary>Longer than any identifier or card name; a string past this is a torn read, not data.</summary>
    private const int MaxStringLength = 1 << 22;
}

/// <summary>
/// A live array, indexed with the stride the runtime reports.
/// </summary>
/// <remarks>
/// <para>
/// <c>Array.m_NumComponents</c> (8) and the element base (16) are published (§5.2); the stride
/// is not, and is derived-then-verified — see
/// <see cref="ClrTypeSystem.ComponentSizeIsTrusted"/>.
/// </para>
/// <para>
/// <b>An array whose stride could not be verified reports <see cref="Count"/> 0 AND records a
/// structural anomaly.</b> Reporting the header's element count while refusing to index would
/// hand a caller N phantom nulls — §12.4b's probe bug exactly, where a collection silently
/// reads as empty-but-present and nobody notices. Reporting 0 silently would be the same bug
/// with a different arity. So the count is withheld and the snapshot is marked unusable:
/// arrays are genuinely unreadable on a runtime whose stride encoding does not verify, and
/// that must be loud. <see cref="ReportedCount"/> still carries the raw header value for
/// diagnostics.
/// </para>
/// </remarks>
public sealed class ClrArray : IClrArray
{
    private readonly ISnapshotContext _context;
    private readonly ClrFieldShape _elementShape;

    internal ClrArray(ISnapshotContext context, ulong address, ClrTypeInfo type)
    {
        _context = context;
        Address = address;
        _elementShape = ElementShapeOf(context, type);

        ElementSize = context.TypeSystem.ComponentSizeIsTrusted ? type.ComponentSize : 0;
        ReportedCount = ReadCount(context, address);

        if (ElementSize > 0 && ReportedCount > 0 && !LastElementIsMapped(context, address, ReportedCount, ElementSize))
        {
            // A count is a DECODED number, and a wrong decode of the header — or of the field
            // offset that led here — produces an enormous one rather than an obviously invalid
            // one. Nothing above this bounded it: the only rejection was `> int.MaxValue`, so a
            // count of a billion travelled onward intact and any consumer that walked the array
            // spun instead of failing. A bad decode has to fail fast (§12.5, §13.11).
            context.NoteAnomaly(
                $"array at 0x{address:X} claims {ReportedCount} elements of {ElementSize} bytes, but the slot that " +
                "many elements in is not mapped, so this is a bad decode rather than a large array");
            Count = 0;
            return;
        }

        if (ElementSize > 0 || ReportedCount == 0)
        {
            Count = ReportedCount;
            return;
        }

        context.NoteAnomaly(
            $"array at 0x{address:X} reports {ReportedCount} elements but its element stride could not be " +
            "verified against the runtime's published method tables, so no element is readable");
        Count = 0;
    }

    /// <summary>Address of the array object.</summary>
    public ulong Address { get; }

    /// <inheritdoc/>
    public int Count { get; }

    /// <summary>Raw <c>m_NumComponents</c>, whether or not the array turned out to be readable.</summary>
    public int ReportedCount { get; }

    /// <summary>Element stride in bytes, or 0 when it could not be verified.</summary>
    public int ElementSize { get; }

    /// <summary>False when the stride is unknown; every index then yields a null value.</summary>
    public bool IsReadable => ElementSize > 0;

    /// <inheritdoc/>
    /// <remarks>An out-of-range index yields a null value rather than throwing (§5.5).</remarks>
    public IClrValue this[int index]
    {
        get
        {
            if (index < 0 || index >= Count || ElementSize == 0) return ClrValue.None(_context);

            ulong slot = Address
                + (ulong)_context.TypeSystem.Layouts.ArrayFirstElementOffset
                + ((ulong)index * (ulong)ElementSize);

            return new ClrValue(_context, slot, _elementShape);
        }
    }

    /// <summary>
    /// True when the LAST element's slot can actually be read.
    /// </summary>
    /// <remarks>
    /// One read, and only when it can disagree. If the whole array fits inside the page the
    /// count was just read from, that page is already known to be mapped and the probe could
    /// not come out any way but true — which is the shape of check §13.11 is about, so it is
    /// skipped rather than performed for appearances.
    /// </remarks>
    private static bool LastElementIsMapped(ISnapshotContext context, ulong address, int count, int elementSize)
    {
        const ulong PageSize = 4096;

        ulong first = address + (ulong)context.TypeSystem.Layouts.ArrayFirstElementOffset;
        ulong last = first + ((ulong)(count - 1) * (ulong)elementSize);

        // Wrapped the address space, so no allocation could hold it.
        if (last < address) return false;
        if (last / PageSize == address / PageSize) return true;

        Span<byte> probe = stackalloc byte[1];
        return context.Memory.TryRead(last, probe);
    }

    private static int ReadCount(ISnapshotContext context, ulong address)
    {
        ClrLayouts layouts = context.TypeSystem.Layouts;
        if (!context.Memory.TryRead(address + (ulong)layouts.ArrayNumComponentsOffset, out uint count)) return 0;

        // A count no allocation could hold is a torn read of the header, not a large array.
        if (count > int.MaxValue)
        {
            context.NoteAnomaly($"array at 0x{address:X} reports {count} elements");
            return 0;
        }

        return (int)count;
    }

    /// <summary>
    /// What an element slot holds. Taken from the element method table when the runtime
    /// identified one; otherwise unknown, which still allows following a validated pointer.
    /// </summary>
    private static ClrFieldShape ElementShapeOf(ISnapshotContext context, ClrTypeInfo type)
    {
        if (type.ElementMethodTable == 0) return ClrFieldShape.Unknown;
        if (!context.TypeSystem.TryGetType(context.Memory, type.ElementMethodTable, out ClrTypeInfo? element))
        {
            return ClrFieldShape.Unknown;
        }

        return new ClrFieldShape(element.ElementType, element.Name);
    }
}

/// <summary>
/// <c>System.Collections.Generic.List&lt;T&gt;</c>, walked as its two fields.
/// </summary>
/// <remarks>
/// <para>
/// <b>The count is <c>_size</c>, never <c>_items.Length</c>.</b> §12.4, API fact 2: the backing
/// array is capacity, and using its length over-reads into stale entries — entries that are
/// real objects from a previous state of the list, so the result looks like data rather than
/// like an error.
/// </para>
/// <para>
/// <b>A <c>_size</c> larger than the backing array is a structural anomaly, not an exception.</b>
/// Both fields read fine; they simply disagree, which is the §12.4e signature exactly — a
/// traversal that would come up short with every individual read succeeding. §6.4 prescribes
/// the response: "where a count field exists, treat a shorter walk as a re-sample trigger". So
/// it is recorded on the snapshot, <see cref="Count"/> is clamped to what can actually be
/// read, and the caller learns about it from <c>Validate()</c>.
/// </para>
/// </remarks>
public sealed class ClrList : IClrList
{
    private readonly ISnapshotContext _context;
    private readonly ClrArray? _items;

    private ClrList(ISnapshotContext context, ClrArray? items, int count, int reportedCount)
    {
        _context = context;
        _items = items;
        Count = count;
        ReportedCount = reportedCount;
    }

    /// <summary>Live element count, from <c>_size</c>, clamped to what the backing array can supply.</summary>
    public int Count { get; }

    /// <summary>The raw <c>_size</c> before clamping. Differs from <see cref="Count"/> only when torn.</summary>
    public int ReportedCount { get; }

    /// <summary>Backing array length — CAPACITY, deliberately not the count.</summary>
    public int Capacity => _items?.Count ?? 0;

    /// <inheritdoc/>
    public IClrValue this[int index] =>
        _items is null || index < 0 || index >= Count ? ClrValue.None(_context) : _items[index];

    internal static ClrList Create(ISnapshotContext context, ClrObject list)
    {
        ClrArray? items = list.Field("_items")?.AsArray() as ClrArray;

        int reported = 0;
        if (list.Field("_size") is ClrValue size && size.TryRead(out int value)) reported = value;

        if (reported < 0)
        {
            context.NoteAnomaly($"List at 0x{list.Address:X} reports a negative _size of {reported}");
            reported = 0;
        }

        int capacity = items?.Count ?? 0;
        int count = reported;

        if (reported > capacity)
        {
            context.NoteAnomaly(
                $"List at 0x{list.Address:X} reports _size={reported} but its backing array holds {capacity}; " +
                "the walk would be short (analysis doc §12.4e)");
            count = capacity;
        }

        return new ClrList(context, items, count, reported);
    }
}
