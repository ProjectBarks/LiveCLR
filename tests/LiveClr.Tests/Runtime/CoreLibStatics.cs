namespace LiveClr.Tests.Runtime;

using System.Reflection;

/// <summary>
/// Which of the RUNNING CoreLib's types and static fields the fixture will synthesise runtime
/// structures for.
/// </summary>
/// <remarks>
/// <para>
/// The fixture maps <c>System.Private.CoreLib</c> from disk, so its metadata is real and its
/// tokens are the real ones. That means the set of types with static fields, and which of those
/// fields carry <c>[ThreadStatic]</c>, can be discovered by REFLECTING over the same assembly
/// rather than hardcoding a list that a future CoreLib would silently invalidate.
/// </para>
/// <para>
/// <b>Why it matters that these are real.</b> <see cref="LiveClr.Runtime.StaticsCalibration"/>
/// derives the runtime's thread-static marker bit against the <c>[ThreadStatic]</c> attribute in
/// the target's own metadata. A fixture that invented the attribute could not test that
/// derivation — it would only test that the fixture and the reader agree with each other.
/// </para>
/// <para>Computed once per test process; the reflection pass is not cheap enough to repeat.</para>
/// </remarks>
internal static class CoreLibStatics
{
    /// <summary>One static field the fixture will lay a <c>FieldDesc</c> down for.</summary>
    internal readonly record struct PlannedField(int Token, string Name, bool IsReference, bool IsThreadStatic);

    /// <summary>One CoreLib type the fixture will give a method table and a statics blob.</summary>
    /// <param name="Rid">Its TypeDef row, which is real because the metadata is real.</param>
    /// <param name="Name">Its full name, for a test to look it up by.</param>
    /// <param name="Fields">Statics the fixture will give storage.</param>
    /// <param name="RvaFields">
    /// Statics with <c>FieldAttributes.HasFieldRVA</c>. The fixture writes NO descriptor for these
    /// — their bytes live in the image — so a reader that does not refuse them on the metadata
    /// alone has nothing to fall back on.
    /// </param>
    internal readonly record struct PlannedType(int Rid, string Name, PlannedField[] Fields, string[] RvaFields);

    /// <summary>Types carrying <c>[ThreadStatic]</c> fields, which pin the marker-bit derivation.</summary>
    internal static IReadOnlyList<PlannedType> ThreadStaticCarriers { get; }

    /// <summary>
    /// Types carrying ordinary reference statics, which pin the GC/non-GC base ordering: the
    /// correct base resolves them to objects and the other does not.
    /// </summary>
    internal static IReadOnlyList<PlannedType> ReferenceCarriers { get; }

    /// <summary>An open generic definition with at least one static, for the refusal path.</summary>
    internal static PlannedType? GenericCarrier { get; }

    /// <summary>A type carrying at least one RVA static, for the refusal path.</summary>
    internal static PlannedType? RvaCarrier { get; }

    static CoreLibStatics()
    {
        var threadStatic = new List<PlannedType>();
        var reference = new List<PlannedType>();
        PlannedType? generic = null;
        PlannedType? rva = null;

        foreach (Type type in LoadableTypes(typeof(object).Assembly))
        {
            if (type.IsNested || type.ContainsGenericParameters && !type.IsGenericTypeDefinition) continue;

            (PlannedField[] fields, string[] rvaFields) = StaticFieldsOf(type);
            if (fields.Length == 0 && rvaFields.Length == 0) continue;

            var planned = new PlannedType(
                type.MetadataToken & 0x00FF_FFFF, type.FullName ?? type.Name, fields, rvaFields);

            if (rvaFields.Length > 0) rva ??= planned;
            if (fields.Length == 0) continue;

            if (type.IsGenericTypeDefinition)
            {
                generic ??= planned;
                continue;
            }

            if (Array.Exists(fields, f => f.IsThreadStatic))
            {
                if (threadStatic.Count < 4) threadStatic.Add(planned);
                continue;
            }

            if (reference.Count < 24 && Array.Exists(fields, f => f.IsReference)) reference.Add(planned);
        }

        ThreadStaticCarriers = threadStatic;
        ReferenceCarriers = reference;
        GenericCarrier = generic;
        RvaCarrier = rva;
    }

    private static (PlannedField[] Fields, string[] RvaFields) StaticFieldsOf(Type type)
    {
        FieldInfo[] fields;
        try
        {
            fields = type.GetFields(
                BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.DeclaredOnly);
        }
        catch (Exception)
        {
            return ([], []);
        }

        var planned = new List<PlannedField>();
        var rva = new List<string>();

        foreach (FieldInfo field in fields)
        {
            if (field.IsLiteral) continue;

            // An RVA static's bytes live in the image, so the fixture must not pretend it has a
            // slot in a statics blob — that is a case the reader refuses on the metadata alone.
            if ((field.Attributes & FieldAttributes.HasFieldRVA) != 0)
            {
                rva.Add(field.Name);
                continue;
            }

            bool isThreadStatic;
            try
            {
                isThreadStatic = field.IsDefined(typeof(ThreadStaticAttribute), inherit: false);
            }
            catch (Exception)
            {
                continue;
            }

            planned.Add(new PlannedField(
                field.MetadataToken,
                field.Name,
                !field.FieldType.IsValueType && !field.FieldType.IsPointer,
                isThreadStatic));
        }

        return ([.. planned], [.. rva]);
    }

    private static IEnumerable<Type> LoadableTypes(Assembly assembly)
    {
        try
        {
            return assembly.GetTypes();
        }
        catch (ReflectionTypeLoadException e)
        {
            return e.Types.Where(t => t is not null)!;
        }
    }
}
