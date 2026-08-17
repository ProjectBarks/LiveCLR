namespace LiveClr.Cdac;

/// <summary>
/// One field of a descriptor type: an offset, and optionally the name of the type
/// stored there.
/// </summary>
/// <remarks>
/// The descriptor publishes fields as either <c>"Module": 24</c> or
/// <c>"GCHandle": [312, "GCHandle"]</c>. The second form's type name is a hint about how
/// to interpret the bytes (analysis doc §5.2); it is never required to read them, so
/// <see cref="TypeName"/> is nullable and callers may ignore it entirely.
/// </remarks>
public readonly record struct DescriptorField(string Name, int Offset, string? TypeName);

/// <summary>A type the runtime publishes the layout of.</summary>
public sealed class DescriptorType
{
    internal DescriptorType(string name, int? size, IReadOnlyDictionary<string, DescriptorField> fields)
    {
        Name = name;
        Size = size;
        Fields = fields;
    }

    public string Name { get; }

    /// <summary>
    /// The descriptor's <c>"!"</c> entry, when present.
    /// </summary>
    /// <remarks>
    /// <c>"!"</c> is the type's total size. Analysis doc §5.2 annotates
    /// <c>"Array": { "!": 16 }</c> as "element base", which reads as a different concept
    /// but yields the same number for the same reason: an array's header size <em>is</em>
    /// where its element data starts. Most types (<c>Object</c>, <c>MethodTable</c>,
    /// <c>Module</c>) omit it, so this stays nullable and callers must not require it.
    /// </remarks>
    public int? Size { get; }

    /// <summary>Field name → offset. Ordinal, case-sensitive, exactly as published.</summary>
    public IReadOnlyDictionary<string, DescriptorField> Fields { get; }
}

/// <summary>
/// A published global: either a literal value or an index into the descriptor's
/// <c>pointer_data</c> array.
/// </summary>
/// <remarks>
/// Analysis doc §5.3. The two forms mean genuinely different things and conflating them
/// is silently wrong:
/// <list type="bullet">
/// <item><c>"ObjectToMethodTableUnmask": ["0x7", "uint8"]</c> is the value <c>7</c>,
/// baked into the descriptor and needing no memory read.</item>
/// <item><c>"AppDomain": [[1], "pointer"]</c> means <c>pointer_data[1]</c> holds the
/// <em>address of</em> the AppDomain pointer. Reading the AppDomain therefore costs one
/// further dereference — §12.1: <c>pointer_data[1] → &amp;AppDomain = 0x7FFE31252780 →
/// AppDomain = 0x1A96EC71B30</c>.</item>
/// </list>
/// </remarks>
public sealed class DescriptorGlobal
{
    internal DescriptorGlobal(string name, string? typeName, bool isIndirect, ulong value, int pointerDataIndex)
    {
        Name = name;
        TypeName = typeName;
        IsIndirect = isIndirect;
        Value = value;
        PointerDataIndex = pointerDataIndex;
    }

    public string Name { get; }

    /// <summary>Published type hint (<c>uint8</c>, <c>uint64</c>, <c>pointer</c>, ...), if any.</summary>
    public string? TypeName { get; }

    /// <summary>True for the <c>[[index], "pointer"]</c> form.</summary>
    public bool IsIndirect { get; }

    /// <summary>Literal value. Meaningless when <see cref="IsIndirect"/> is true.</summary>
    public ulong Value { get; }

    /// <summary>
    /// Index into <c>pointer_data</c>. Meaningless when <see cref="IsIndirect"/> is false.
    /// Index 0 is unused by the runtime (§5.3).
    /// </summary>
    public int PointerDataIndex { get; }
}
