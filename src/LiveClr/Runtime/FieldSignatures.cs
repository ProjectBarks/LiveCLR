namespace LiveClr.Runtime;

using System.Collections.Immutable;
using System.Reflection.Metadata;

/// <summary>
/// ECMA-335 <c>CorElementType</c>. The runtime publishes one of these per type as
/// <c>EEClass.InternalCorElementType</c> (§5.2), which is how a live method table says
/// "I am an SZARRAY" without a name lookup.
/// </summary>
public enum ClrElementType : byte
{
    /// <summary>No element type could be determined.</summary>
    Unknown = 0x00,
    Void = 0x01,
    Boolean = 0x02,
    Char = 0x03,
    SByte = 0x04,
    Byte = 0x05,
    Int16 = 0x06,
    UInt16 = 0x07,
    Int32 = 0x08,
    UInt32 = 0x09,
    Int64 = 0x0A,
    UInt64 = 0x0B,
    Single = 0x0C,
    Double = 0x0D,
    String = 0x0E,
    Pointer = 0x0F,
    ByRef = 0x10,
    ValueType = 0x11,
    Class = 0x12,
    Var = 0x13,
    Array = 0x14,
    GenericInstantiation = 0x15,
    IntPtr = 0x18,
    UIntPtr = 0x19,
    FunctionPointer = 0x1B,
    Object = 0x1C,
    SzArray = 0x1D,
    MVar = 0x1E,
}

/// <summary>Extensions over <see cref="ClrElementType"/>.</summary>
public static class ClrElementTypeExtensions
{
    /// <summary>
    /// True when a slot of this type holds an object reference rather than inline data.
    /// This is the distinction that decides whether following a value produces an object
    /// or reads a struct in place.
    /// </summary>
    public static bool IsReference(this ClrElementType type) => type
        is ClrElementType.String
        or ClrElementType.Class
        or ClrElementType.Array
        or ClrElementType.SzArray
        or ClrElementType.Object;

    /// <summary>
    /// Size in bytes of a primitive, or 0 when the type is not a fixed-size primitive.
    /// </summary>
    public static int PrimitiveSize(this ClrElementType type, int pointerSize) => type switch
    {
        ClrElementType.Boolean or ClrElementType.SByte or ClrElementType.Byte => 1,
        ClrElementType.Char or ClrElementType.Int16 or ClrElementType.UInt16 => 2,
        ClrElementType.Int32 or ClrElementType.UInt32 or ClrElementType.Single => 4,
        ClrElementType.Int64 or ClrElementType.UInt64 or ClrElementType.Double => 8,
        ClrElementType.IntPtr or ClrElementType.UIntPtr or ClrElementType.Pointer
            or ClrElementType.FunctionPointer => pointerSize,
        _ => 0,
    };
}

/// <summary>
/// What a field's ECMA-335 signature says about the slot: enough to decide whether the
/// bytes are a pointer to follow or a value to read.
/// </summary>
/// <remarks>
/// Metadata says a field EXISTS and what its declared type is; it never says where the
/// field lives (see <c>Metadata/TypeResolver</c>). This record carries the first half; the
/// offset comes from the runtime side.
/// </remarks>
/// <param name="ElementType">Decoded <c>CorElementType</c> of the field's declared type.</param>
/// <param name="TypeName">Full name of the field's type when the signature named one.</param>
public readonly record struct ClrFieldShape(ClrElementType ElementType, string? TypeName)
{
    /// <summary>Nothing is known about the slot; treat it as opaque bytes.</summary>
    public static ClrFieldShape Unknown => new(ClrElementType.Unknown, null);

    /// <summary>True when the slot holds an object reference.</summary>
    public bool IsReference => ElementType.IsReference();
}

/// <summary>
/// Minimal <see cref="ISignatureTypeProvider{TType, TGenericContext}"/> that reduces a field
/// signature to a <see cref="ClrFieldShape"/>.
/// </summary>
/// <remarks>
/// <para>
/// Deliberately lossy. The only questions this layer asks of a signature are "is this slot a
/// reference?" and "if it is a primitive, how wide?"; a full type model would be a second
/// reflection framework, which §8.8 explicitly rules out ("surface kept small on purpose").
/// </para>
/// <para>
/// Generic parameters decode to <see cref="ClrElementType.Var"/>/<see cref="ClrElementType.MVar"/>
/// rather than being guessed at. A field typed <c>T</c> may be a reference or a struct
/// depending on the instantiation, and the honest answer at signature level is "unknown" —
/// callers fall back to validating the pointed-at object instead.
/// </para>
/// </remarks>
internal sealed class FieldShapeProvider : ISignatureTypeProvider<ClrFieldShape, object?>
{
    public static FieldShapeProvider Instance { get; } = new();

    public ClrFieldShape GetPrimitiveType(PrimitiveTypeCode typeCode) => typeCode switch
    {
        PrimitiveTypeCode.Boolean => new(ClrElementType.Boolean, "System.Boolean"),
        PrimitiveTypeCode.Char => new(ClrElementType.Char, "System.Char"),
        PrimitiveTypeCode.SByte => new(ClrElementType.SByte, "System.SByte"),
        PrimitiveTypeCode.Byte => new(ClrElementType.Byte, "System.Byte"),
        PrimitiveTypeCode.Int16 => new(ClrElementType.Int16, "System.Int16"),
        PrimitiveTypeCode.UInt16 => new(ClrElementType.UInt16, "System.UInt16"),
        PrimitiveTypeCode.Int32 => new(ClrElementType.Int32, "System.Int32"),
        PrimitiveTypeCode.UInt32 => new(ClrElementType.UInt32, "System.UInt32"),
        PrimitiveTypeCode.Int64 => new(ClrElementType.Int64, "System.Int64"),
        PrimitiveTypeCode.UInt64 => new(ClrElementType.UInt64, "System.UInt64"),
        PrimitiveTypeCode.Single => new(ClrElementType.Single, "System.Single"),
        PrimitiveTypeCode.Double => new(ClrElementType.Double, "System.Double"),
        PrimitiveTypeCode.IntPtr => new(ClrElementType.IntPtr, "System.IntPtr"),
        PrimitiveTypeCode.UIntPtr => new(ClrElementType.UIntPtr, "System.UIntPtr"),
        PrimitiveTypeCode.String => new(ClrElementType.String, "System.String"),
        PrimitiveTypeCode.Object => new(ClrElementType.Object, "System.Object"),
        _ => ClrFieldShape.Unknown,
    };

    public ClrFieldShape GetTypeFromDefinition(MetadataReader reader, TypeDefinitionHandle handle, byte rawTypeKind) =>
        FromHandle(Name(reader, handle), rawTypeKind);

    public ClrFieldShape GetTypeFromReference(MetadataReader reader, TypeReferenceHandle handle, byte rawTypeKind) =>
        FromHandle(Name(reader, handle), rawTypeKind);

    public ClrFieldShape GetTypeFromSpecification(
        MetadataReader reader, object? genericContext, TypeSpecificationHandle handle, byte rawTypeKind) =>
        reader.GetTypeSpecification(handle).DecodeSignature(this, genericContext);

    // An array of anything is itself a reference, whatever the element type is.
    public ClrFieldShape GetSZArrayType(ClrFieldShape elementType) =>
        new(ClrElementType.SzArray, elementType.TypeName is null ? null : elementType.TypeName + "[]");

    public ClrFieldShape GetArrayType(ClrFieldShape elementType, ArrayShape shape) =>
        new(ClrElementType.Array, elementType.TypeName is null ? null : elementType.TypeName + "[]");

    public ClrFieldShape GetByReferenceType(ClrFieldShape elementType) => new(ClrElementType.ByRef, null);

    public ClrFieldShape GetPointerType(ClrFieldShape elementType) => new(ClrElementType.Pointer, null);

    public ClrFieldShape GetFunctionPointerType(MethodSignature<ClrFieldShape> signature) =>
        new(ClrElementType.FunctionPointer, null);

    // The instantiation does not change whether the slot is a reference; List<int> and
    // List<string> are both references, and Nullable<int> is a value type either way.
    public ClrFieldShape GetGenericInstantiation(ClrFieldShape genericType, ImmutableArray<ClrFieldShape> typeArguments) =>
        genericType;

    public ClrFieldShape GetGenericTypeParameter(object? genericContext, int index) => new(ClrElementType.Var, null);

    public ClrFieldShape GetGenericMethodParameter(object? genericContext, int index) => new(ClrElementType.MVar, null);

    public ClrFieldShape GetModifiedType(ClrFieldShape modifier, ClrFieldShape unmodifiedType, bool isRequired) =>
        unmodifiedType;

    public ClrFieldShape GetPinnedType(ClrFieldShape elementType) => elementType;

    /// <summary>
    /// <paramref name="rawTypeKind"/> is the signature's own <c>ELEMENT_TYPE_CLASS</c> (18) /
    /// <c>ELEMENT_TYPE_VALUETYPE</c> (17) discriminator. It is exactly the reference-vs-inline
    /// answer this provider exists to produce, and it needs no cross-module resolution.
    /// </summary>
    private static ClrFieldShape FromHandle(string? name, byte rawTypeKind) => rawTypeKind switch
    {
        0x11 => new(ClrElementType.ValueType, name),
        0x12 => new(ClrElementType.Class, name),

        // rawTypeKind 0 means the signature did not say. A TypeRef/TypeDef in a field
        // signature is one or the other, and guessing "class" would make every enum field
        // look like a pointer, so report it unknown and let the caller validate.
        _ => new(ClrElementType.Unknown, name),
    };

    private static string Name(MetadataReader reader, TypeDefinitionHandle handle)
    {
        TypeDefinition definition = reader.GetTypeDefinition(handle);
        string ns = reader.GetString(definition.Namespace);
        string name = reader.GetString(definition.Name);
        return ns.Length == 0 ? name : ns + "." + name;
    }

    private static string Name(MetadataReader reader, TypeReferenceHandle handle)
    {
        TypeReference reference = reader.GetTypeReference(handle);
        string ns = reader.GetString(reference.Namespace);
        string name = reader.GetString(reference.Name);
        return ns.Length == 0 ? name : ns + "." + name;
    }
}
