namespace LiveClr.Metadata;

using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;

/// <summary>
/// One field as ECMA-335 declares it. NAMES AND TOKENS ONLY — deliberately no offset.
/// </summary>
/// <remarks>
/// Metadata says a field <em>exists</em>; it does not say where the field <em>lives</em>.
/// Instance layout is decided by the runtime at type-load time (packing, base-class size,
/// alignment, shared generics), so the offset must come from the runtime side —
/// <c>MethodTable</c> → <c>EEClass</c> → <c>FieldDesc</c> via the cDAC descriptor (§5.2).
/// Putting an <c>Offset</c> property here would invite exactly the wrong assumption.
/// </remarks>
/// <param name="Name">Field name as it appears in the <c>#Strings</c> heap.</param>
/// <param name="Token">Metadata token (table 0x04). Pairs a name with the runtime's
/// <c>FieldDefToDescMap</c> lookup (§5.2, <c>Module.FieldDefToDescMap</c> at offset 432).</param>
/// <param name="Attributes">Raw <c>FieldAttributes</c> from the <c>Field</c> table.</param>
public readonly record struct MetadataField(string Name, int Token, FieldAttributes Attributes)
{
    /// <summary>Statics live on the module/loader heap, not in the object.</summary>
    public bool IsStatic => (Attributes & FieldAttributes.Static) != 0;

    /// <summary>
    /// A <c>const</c>. It has no storage at all, so it will never appear in an object's
    /// layout no matter how the offset is resolved.
    /// </summary>
    public bool IsLiteral => (Attributes & FieldAttributes.Literal) != 0;
}

/// <summary>
/// A type's declared base, as far as metadata alone can describe it.
/// </summary>
/// <param name="FullName">Full name of the base type, or <see langword="null"/> when the base is
/// a generic instantiation (a <c>TypeSpec</c>) whose name cannot be produced without decoding a
/// signature.</param>
/// <param name="Definition">The base's handle when it is defined in THIS module; nil when it is
/// a <c>TypeRef</c> into another module (e.g. <c>System.Object</c> in CoreLib).</param>
/// <param name="IsGenericInstantiation">True when the base is a <c>TypeSpec</c>.</param>
public readonly record struct MetadataBaseType(
    string? FullName,
    TypeDefinitionHandle Definition,
    bool IsGenericInstantiation)
{
    /// <summary>True when <see cref="Definition"/> can be used directly with this resolver.</summary>
    public bool IsInThisModule => !Definition.IsNil;
}

/// <summary>
/// Name-side resolution over one module's metadata: full name → type, type → field names and
/// tokens, nested types, base types.
/// </summary>
/// <remarks>
/// <para>
/// This is the half of type resolution that §12.4d proved needs neither scry nor ClrMD — "just
/// the descriptor plus the documented ECMA-335 layout". The other half, field <em>offsets</em>
/// and live values, comes from the runtime structures; the two meet in <c>Runtime/</c>.
/// </para>
/// <para>
/// <b>Nested types use <c>+</c>.</b> ECMA-335 stores a nested type with an empty namespace and
/// a <c>NestedClass</c> row pointing at its declaring type, so a full name has to be
/// reconstructed. This resolver follows the .NET reflection convention
/// (<c>Outer+Inner</c>) and also accepts the IL convention (<c>Outer/Inner</c>) on input.
/// </para>
/// <para>
/// <b>Everything is cached.</b> §12.4 (API fact 1) records that per-object field-name lookup is
/// the dominant cost in a naive traversal; the name index and per-type field lists are built
/// once and live as long as the owning <see cref="ModuleMetadata"/> (Process tier, §8.8).
/// Because that tier is shared across snapshots and potentially across threads, the caches are
/// guarded — they are write-once-per-key, so contention is confined to first touch.
/// </para>
/// <para>
/// <b>What "write-once" is worth, precisely.</b> Two callers racing on a cold key may both
/// build a value; the one that reaches the lock first publishes, and the other discards its own
/// work and returns the published instance. So every caller of
/// <see cref="GetFields"/>/<see cref="GetFieldNames"/>/<see cref="GetFullName"/> for a given key
/// receives the SAME OBJECT, not merely an equal one, and
/// <c>MetadataConcurrencyTests.ResolverCachesAreConsistentUnderConcurrentReaders</c> tries to
/// break that with eight threads released from a barrier. That is deliberate: the values here
/// are pure functions of the blob, so equality could never have distinguished a guarded cache
/// from an unguarded one, and a test asserting equality would have passed with every lock
/// removed. Reference identity is the one consequence of the locking that a caller can observe.
/// Four of the six lock sites are falsifiable that way and were each confirmed by removal. The
/// other two — the cache-hit check at the top of <see cref="GetFields"/> and of
/// <see cref="GetFieldNames"/> — guard only against reading a dictionary mid-mutation, which has
/// no API-visible consequence; that hazard is real but untested, and the test file says so.
/// </para>
/// <para>
/// <b>THE TABLES ARE HOSTILE INPUT.</b> <see cref="MetadataBlobValidator"/> is structural only:
/// it proves the streams lie inside the blob and stops there. It never inspects a single table
/// row, so every row index, every heap handle, and the entire <c>NestedClass</c> graph reaching
/// this class is attacker-controlled — and the realistic way to get here is not an attacker at
/// all but a stale <c>Module.Base</c> (§7b.1) landing on a plausible-but-wrong image. Two
/// consequences are designed for explicitly:
/// </para>
/// <para>
/// 1. <b>No recursion over table-supplied links.</b> A <c>NestedClass</c> row claiming a type
/// encloses itself, or a 60,000-deep chain, would turn a name lookup into a
/// <c>StackOverflowException</c> — which cannot be caught and kills the process. Name
/// construction is iterative, cycle-detecting, and depth-capped.
/// </para>
/// <para>
/// 2. <b><c>BadImageFormatException</c> is caught at every public entry point.</b> SRM validates
/// heap handles LAZILY, at access time, so a corrupt row survives
/// <c>MetadataReaderProvider.GetMetadataReader()</c> and throws later from
/// <c>GetString</c>. Letting that escape would break the §8.8 error model — a suspect snapshot
/// must be inspectable so the overlay can reuse the last good one — and would kill the polling
/// loop on first lookup rather than on connect.
/// </para>
/// </remarks>
public sealed class TypeResolver
{
    /// <summary>
    /// Hard cap on nesting depth. Real code nests a handful deep; C#'s own compiler limits are
    /// far below this. The cap exists to bound work on a malformed chain, not to constrain
    /// legitimate types.
    /// </summary>
    public const int MaxNestingDepth = 64;

    /// <summary>
    /// Stand-in name for a type whose <c>#Strings</c> handle is out of range. A degraded,
    /// inspectable name beats an exception escaping a method documented not to throw.
    /// </summary>
    public const string UnreadableName = "<unreadable>";

    private readonly MetadataReader _reader;
    private readonly Dictionary<TypeDefinitionHandle, MetadataField[]> _fieldCache = [];
    private readonly Dictionary<TypeDefinitionHandle, string[]> _fieldNameCache = [];
    private readonly Dictionary<TypeDefinitionHandle, string> _nameCache = [];
    private readonly Lock _gate = new();
    private Dictionary<string, TypeDefinitionHandle>? _index;

    /// <summary>Wrap a reader. The reader must outlive this resolver.</summary>
    public TypeResolver(MetadataReader reader)
    {
        ArgumentNullException.ThrowIfNull(reader);
        _reader = reader;
    }

    /// <summary>The underlying reader, for callers that need tables this class does not expose.</summary>
    public MetadataReader Reader => _reader;

    /// <summary>Number of type definitions in the module.</summary>
    public int TypeCount => _reader.TypeDefinitions.Count;

    /// <summary>
    /// Resolve <c>"Namespace.Type"</c> (or <c>"Namespace.Outer+Inner"</c>) to its definition.
    /// Returns <see langword="false"/> when the module does not define the type — a normal
    /// answer, not an error, since a name may legitimately live in a different module.
    /// </summary>
    public bool TryResolveType(string fullName, out TypeDefinitionHandle handle)
    {
        ArgumentNullException.ThrowIfNull(fullName);

        try
        {
            lock (_gate) return Index.TryGetValue(Normalize(fullName), out handle);
        }
        catch (BadImageFormatException)
        {
            // Index construction reads #Strings; a corrupt heap must read as "not found",
            // not as a thrown exception out of a Try* method.
            handle = default;
            return false;
        }
    }

    /// <summary>Convenience over <see cref="TryResolveType"/>; <see langword="null"/> if absent.</summary>
    public TypeDefinitionHandle? ResolveType(string fullName) =>
        TryResolveType(fullName, out TypeDefinitionHandle handle) ? handle : null;

    /// <summary>True if the module defines the type.</summary>
    public bool ContainsType(string fullName) => TryResolveType(fullName, out _);

    /// <summary>
    /// Every type's full name, in metadata order. Enumerating this is what makes a module
    /// self-describing; it is also the fallback when a caller only knows part of a name.
    /// </summary>
    public IEnumerable<string> EnumerateTypeNames()
    {
        foreach (TypeDefinitionHandle handle in _reader.TypeDefinitions)
        {
            yield return GetFullName(handle);
        }
    }

    /// <summary>
    /// Full name of a type definition, with nesting reconstructed. Returns
    /// <see cref="UnreadableName"/> rather than throwing if the row's heap handles are corrupt.
    /// </summary>
    public string GetFullName(TypeDefinitionHandle handle)
    {
        try
        {
            lock (_gate) return GetFullNameCore(handle);
        }
        catch (BadImageFormatException)
        {
            return UnreadableName;
        }
    }

    /// <summary>
    /// The type's DECLARED fields, in metadata order. Inherited fields are not included —
    /// walk <see cref="TryGetBaseType"/> for those, which mirrors how the runtime lays objects
    /// out (base first, then derived).
    /// </summary>
    /// <remarks>
    /// Returns an empty list — never throws — if the type's field rows reference heap handles
    /// outside <c>#Strings</c>. See the class remarks on lazy SRM validation.
    /// </remarks>
    public IReadOnlyList<MetadataField> GetFields(TypeDefinitionHandle handle)
    {
        lock (_gate)
        {
            if (_fieldCache.TryGetValue(handle, out MetadataField[]? hit)) return hit;
        }

        MetadataField[] fields;
        try
        {
            TypeDefinition type = _reader.GetTypeDefinition(handle);
            FieldDefinitionHandleCollection handles = type.GetFields();
            fields = new MetadataField[handles.Count];

            int i = 0;
            foreach (FieldDefinitionHandle fieldHandle in handles)
            {
                FieldDefinition field = _reader.GetFieldDefinition(fieldHandle);
                fields[i++] = new MetadataField(
                    _reader.GetString(field.Name),
                    MetadataTokens.GetToken(fieldHandle),
                    field.Attributes);
            }
        }
        catch (BadImageFormatException)
        {
            // Not cached: a failure here is a property of a corrupt image, and caching it
            // would make a genuinely empty type indistinguishable from an unreadable one.
            return [];
        }

        lock (_gate)
        {
            // Publish under the lock, but let an EARLIER publisher win. Two callers can both
            // miss the check above and both build; assigning unconditionally left the loser
            // holding an array no other caller will ever see, so "write-once per key" was not
            // true in exactly the concurrent case the lock exists for — and, worse, was not
            // observable, since both callers' answers were still equal. Returning the stored
            // instance makes reference identity a property a test can try to violate (§13.11).
            if (_fieldCache.TryGetValue(handle, out MetadataField[]? published)) return published;
            _fieldCache[handle] = fields;
        }

        return fields;
    }

    /// <summary>Declared field names only — the common case (§12.4d read these from <c>#Strings</c>).</summary>
    /// <remarks>Cached alongside the field list; repeated calls do not reallocate.</remarks>
    public IReadOnlyList<string> GetFieldNames(TypeDefinitionHandle handle)
    {
        lock (_gate)
        {
            if (_fieldNameCache.TryGetValue(handle, out string[]? hit)) return hit;
        }

        IReadOnlyList<MetadataField> fields = GetFields(handle);
        var names = new string[fields.Count];
        for (int i = 0; i < fields.Count; i++) names[i] = fields[i].Name;

        lock (_gate)
        {
            // As GetFields: first publisher wins, and everyone gets that instance.
            if (_fieldNameCache.TryGetValue(handle, out string[]? published)) return published;
            _fieldNameCache[handle] = names;
        }

        return names;
    }

    /// <summary>Find a declared field by name.</summary>
    public bool TryGetField(TypeDefinitionHandle handle, string name, out MetadataField field)
    {
        ArgumentNullException.ThrowIfNull(name);

        foreach (MetadataField candidate in GetFields(handle))
        {
            if (string.Equals(candidate.Name, name, StringComparison.Ordinal))
            {
                field = candidate;
                return true;
            }
        }

        field = default;
        return false;
    }

    /// <summary>
    /// Directly nested types of <paramref name="handle"/> (not transitive). Empty, never a
    /// throw, on a corrupt <c>NestedClass</c> table.
    /// </summary>
    public IReadOnlyList<TypeDefinitionHandle> GetNestedTypes(TypeDefinitionHandle handle)
    {
        try
        {
            return _reader.GetTypeDefinition(handle).GetNestedTypes();
        }
        catch (BadImageFormatException)
        {
            return [];
        }
    }

    /// <summary>
    /// The declared base type. Returns <see langword="false"/> for <c>System.Object</c>, for
    /// interfaces, and for any type whose <c>Extends</c> row is nil.
    /// </summary>
    /// <remarks>
    /// Metadata gives the base type's NAME. The runtime gives the base type's identity —
    /// <c>MethodTable.ParentMethodTable</c> at offset 16 (§5.2), which §12.2 verified live
    /// (<c>String.Parent</c> resolved to exactly <c>ObjectMethodTable</c>). Prefer the runtime
    /// chain when you have a live object; use this when you only have metadata.
    /// </remarks>
    public bool TryGetBaseType(TypeDefinitionHandle handle, out MetadataBaseType baseType)
    {
        try
        {
            return TryGetBaseTypeCore(handle, out baseType);
        }
        catch (BadImageFormatException)
        {
            baseType = default;
            return false;
        }
    }

    private bool TryGetBaseTypeCore(TypeDefinitionHandle handle, out MetadataBaseType baseType)
    {
        EntityHandle extends = _reader.GetTypeDefinition(handle).BaseType;
        if (extends.IsNil)
        {
            baseType = default;
            return false;
        }

        switch (extends.Kind)
        {
            case HandleKind.TypeDefinition:
            {
                var definition = (TypeDefinitionHandle)extends;
                baseType = new MetadataBaseType(GetFullName(definition), definition, false);
                return true;
            }

            case HandleKind.TypeReference:
            {
                TypeReference reference = _reader.GetTypeReference((TypeReferenceHandle)extends);
                string ns = _reader.GetString(reference.Namespace);
                string name = _reader.GetString(reference.Name);
                baseType = new MetadataBaseType(
                    ns.Length == 0 ? name : ns + "." + name,
                    default,
                    false);
                return true;
            }

            case HandleKind.TypeSpecification:
                // e.g. `class Foo : List<Bar>`. Producing a name needs a signature decoder;
                // the runtime side answers this far more cheaply via ParentMethodTable.
                baseType = new MetadataBaseType(null, default, true);
                return true;

            default:
                baseType = default;
                return false;
        }
    }

    /// <summary>Lazy full-name index. Callers must already hold <c>_gate</c>.</summary>
    private Dictionary<string, TypeDefinitionHandle> Index
    {
        get
        {
            if (_index is not null) return _index;

            var index = new Dictionary<string, TypeDefinitionHandle>(
                _reader.TypeDefinitions.Count,
                StringComparer.Ordinal);

            foreach (TypeDefinitionHandle handle in _reader.TypeDefinitions)
            {
                try
                {
                    // TryAdd, not Add: a malformed or obfuscated module can carry duplicate
                    // names, and a throwing index would take down the whole connection over
                    // one bad row. Same reasoning for the catch: skip the unreadable row and
                    // keep every other type in the module resolvable.
                    index.TryAdd(GetFullNameCore(handle), handle);
                }
                catch (BadImageFormatException)
                {
                    continue;
                }
            }

            _index = index;
            return _index;
        }
    }

    /// <summary>
    /// Build a full name by walking OUTWARD to the declaring chain's root, iteratively.
    /// Callers must already hold <c>_gate</c>.
    /// </summary>
    /// <remarks>
    /// This was recursive and that was a latent stack-overflow primitive: the
    /// <c>NestedClass</c> table is never inspected by
    /// <see cref="MetadataBlobValidator"/>, so a self-referential or absurdly deep chain
    /// reaches here intact, and the old code could not even break a cycle via the cache
    /// because entries were written only on the way back out.
    /// <para>
    /// On a cycle or an over-deep chain the walk stops and degrades to the simple name of
    /// wherever it stopped. That yields a deterministic, bounded, obviously-odd name — which
    /// is the correct outcome for a corrupt table, since the alternative (an uncatchable
    /// crash) removes the caller's ability to fall back to the last good snapshot at all.
    /// </para>
    /// </remarks>
    private string GetFullNameCore(TypeDefinitionHandle handle)
    {
        if (_nameCache.TryGetValue(handle, out string? cached)) return cached;

        // Innermost-first chain of handles still needing a name.
        var chain = new List<TypeDefinitionHandle>();
        var visited = new HashSet<TypeDefinitionHandle>();
        TypeDefinitionHandle current = handle;
        string prefix;

        while (true)
        {
            if (_nameCache.TryGetValue(current, out string? hit))
            {
                prefix = hit;
                break;
            }

            if (!visited.Add(current) || chain.Count >= MaxNestingDepth)
            {
                // Cycle, or deeper than any real type nests. Stop here.
                prefix = _reader.GetString(_reader.GetTypeDefinition(current).Name);
                break;
            }

            TypeDefinition definition = _reader.GetTypeDefinition(current);
            TypeDefinitionHandle declaring = definition.IsNested ? definition.GetDeclaringType() : default;

            // IsNested comes from the visibility flags, GetDeclaringType from the NestedClass
            // table — a corrupt image can set the first without supplying the second.
            if (declaring.IsNil)
            {
                string ns = _reader.GetString(definition.Namespace);
                string name = _reader.GetString(definition.Name);
                prefix = ns.Length == 0 ? name : ns + "." + name;
                _nameCache[current] = prefix;
                break;
            }

            chain.Add(current);
            current = declaring;
        }

        // Rebuild inward, caching each level so a sibling lookup is O(1).
        for (int i = chain.Count - 1; i >= 0; i--)
        {
            prefix = prefix + "+" + _reader.GetString(_reader.GetTypeDefinition(chain[i]).Name);
            _nameCache[chain[i]] = prefix;
        }

        return prefix;
    }

    /// <summary>Accept the IL nesting separator as well as the reflection one.</summary>
    private static string Normalize(string fullName) =>
        fullName.Contains('/', StringComparison.Ordinal) ? fullName.Replace('/', '+') : fullName;
}
