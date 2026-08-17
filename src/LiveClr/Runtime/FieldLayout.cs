namespace LiveClr.Runtime;

using LiveClr.Memory;

/// <summary>
/// Where one instance field lives inside its object.
/// </summary>
/// <param name="Name">Field name, as declared in metadata.</param>
/// <param name="Offset">Offset from the START OF THE OBJECT, i.e. including the method-table
/// pointer. The runtime's own <c>FieldDesc</c> stores an offset that excludes it; the
/// conversion is <see cref="ClrLayouts.FirstFieldOffset"/> and happens before a location
/// reaches this record, so callers never have to remember which convention they hold.</param>
/// <param name="Source">Where the offset came from; a caller diagnosing a wrong read needs
/// to know whether the runtime supplied it or a human did.</param>
public readonly record struct ClrFieldLocation(string Name, int Offset, FieldOffsetSource Source);

/// <summary>Provenance of a field offset.</summary>
public enum FieldOffsetSource
{
    /// <summary>Walked out of the target's own <c>FieldDesc</c> structures.</summary>
    Runtime,

    /// <summary>Supplied by the caller — from ClrMD at connect (§5.5), a profile, or a test.</summary>
    Explicit,
}

/// <summary>
/// Resolves a named instance field of a type to an offset.
/// </summary>
/// <remarks>
/// <para>
/// This is a seam, not an abstraction for its own sake. §5.5's "honest gap" is that the
/// shipped .NET 9 contract descriptor does not publish everything a consumer needs, and
/// instance field layout is one of those things (see
/// <see cref="RuntimeFieldLayoutSource"/> for exactly which pieces are missing and how far
/// the runtime route still gets). §5.5's sanctioned answer is to let something else — ClrMD,
/// suspended, once at connect — supply what the descriptor cannot, then hand off. That is
/// what <see cref="ExplicitFieldLayoutSource"/> is for.
/// </para>
/// <para>
/// A source must return <see langword="false"/> rather than guess. §5.5: every lookup
/// degrades, none throws.
/// </para>
/// </remarks>
public interface IClrFieldLayoutSource
{
    /// <summary>
    /// Locate <paramref name="fieldName"/> declared on <paramref name="type"/>.
    /// </summary>
    /// <param name="memory">Reader for the target; a runtime-backed source needs it.</param>
    /// <param name="type">The declaring type. Inherited fields are resolved by the caller
    /// walking <see cref="ClrTypeInfo.Parent"/>, which mirrors how the runtime lays objects
    /// out (base first, then derived).</param>
    /// <param name="fieldName">Declared field name.</param>
    /// <param name="location">The resolved location on success.</param>
    bool TryGetField(IMemoryReader memory, ClrTypeInfo type, string fieldName, out ClrFieldLocation location);
}

/// <summary>
/// Caller-supplied field offsets, keyed by type full name and field name.
/// </summary>
/// <remarks>
/// The §5.5 hand-off point, and the only way to read instance fields of an ordinary type on a
/// .NET 9 target today (see <see cref="RuntimeFieldLayoutSource"/>). Offsets are
/// OBJECT-RELATIVE — the same numbers ClrMD's <c>ClrInstanceField.Offset</c> reports with
/// <c>includeHeader: true</c>, and the same convention §5.2 uses when it publishes
/// <c>String.m_StringLength = 8</c>.
/// </remarks>
public sealed class ExplicitFieldLayoutSource : IClrFieldLayoutSource
{
    private readonly Dictionary<string, Dictionary<string, int>> _byType = new(StringComparer.Ordinal);

    /// <summary>Record one field's object-relative offset.</summary>
    public ExplicitFieldLayoutSource Add(string typeFullName, string fieldName, int objectRelativeOffset)
    {
        ArgumentNullException.ThrowIfNull(typeFullName);
        ArgumentNullException.ThrowIfNull(fieldName);
        ArgumentOutOfRangeException.ThrowIfNegative(objectRelativeOffset);

        if (!_byType.TryGetValue(typeFullName, out Dictionary<string, int>? fields))
        {
            fields = new Dictionary<string, int>(StringComparer.Ordinal);
            _byType[typeFullName] = fields;
        }

        fields[fieldName] = objectRelativeOffset;
        return this;
    }

    /// <summary>Record several fields of one type.</summary>
    public ExplicitFieldLayoutSource AddType(string typeFullName, params (string Field, int Offset)[] fields)
    {
        ArgumentNullException.ThrowIfNull(fields);
        foreach ((string field, int offset) in fields) Add(typeFullName, field, offset);
        return this;
    }

    /// <summary>Type names this source has offsets for.</summary>
    public IReadOnlyCollection<string> TypeNames => _byType.Keys;

    /// <inheritdoc/>
    public bool TryGetField(IMemoryReader memory, ClrTypeInfo type, string fieldName, out ClrFieldLocation location)
    {
        location = default;
        if (type is null || fieldName is null) return false;
        if (!_byType.TryGetValue(type.Name, out Dictionary<string, int>? fields)) return false;
        if (!fields.TryGetValue(fieldName, out int offset)) return false;

        location = new ClrFieldLocation(fieldName, offset, FieldOffsetSource.Explicit);
        return true;
    }
}

/// <summary>
/// Tries several sources in order and takes the first answer.
/// </summary>
/// <remarks>
/// Order is the policy: the runtime route goes first so that a runtime capable of answering
/// is always believed over a hand-supplied table, which turns a stale profile into a
/// silently-corrected value rather than a silently-wrong read. §7b.2 makes the same argument
/// for Godot offsets — "the offset table becomes a cache and a fallback, not the source of
/// truth".
/// </remarks>
public sealed class CompositeFieldLayoutSource : IClrFieldLayoutSource
{
    private readonly IClrFieldLayoutSource[] _sources;

    /// <summary>Wrap sources, highest priority first.</summary>
    public CompositeFieldLayoutSource(params IClrFieldLayoutSource[] sources)
    {
        ArgumentNullException.ThrowIfNull(sources);
        _sources = sources;
    }

    /// <inheritdoc/>
    public bool TryGetField(IMemoryReader memory, ClrTypeInfo type, string fieldName, out ClrFieldLocation location)
    {
        foreach (IClrFieldLayoutSource source in _sources)
        {
            if (source.TryGetField(memory, type, fieldName, out location)) return true;
        }

        location = default;
        return false;
    }
}
