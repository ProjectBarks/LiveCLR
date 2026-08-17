namespace LiveClr.Cdac;

using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Text;
using System.Text.Json;
using LiveClr.Memory;

/// <summary>
/// The cDAC contract descriptor as read from a target: 40 bytes of header, a UTF-8 JSON
/// blob describing types/globals/contracts, and the <c>pointer_data</c> array.
/// </summary>
/// <remarks>
/// <para>
/// Analysis doc §5.1 gives the header layout and §5.2 what a shipping .NET 9 runtime
/// puts in the blob. This is the whole reason the design has no per-version offset
/// table: the runtime publishes its own layout, so §4.5's <c>dacvars.h</c>-ordering
/// fragility simply does not apply.
/// </para>
/// <para>
/// Parsing is total: a malformed or truncated descriptor makes <see cref="TryRead"/>
/// return false, and individual JSON entries that do not fit the known shapes are
/// skipped rather than thrown over. The descriptor is a versioned format the runtime
/// may extend, and refusing to start because one future entry is unrecognised would be
/// the opposite of the forward-compatibility this route buys us.
/// </para>
/// </remarks>
public sealed class RuntimeDescriptor
{
    /// <summary>
    /// <c>"DNCCDAC\0"</c>. §5.1: the magic also determines endianness — a big-endian
    /// target would store it reversed, which we reject by matching these bytes exactly.
    /// </summary>
    /// <remarks>Written out byte by byte: the trailing NUL is part of the magic, and a literal NUL in source is a hazard.</remarks>
    private static ReadOnlySpan<byte> Magic => [0x44, 0x4E, 0x43, 0x43, 0x44, 0x41, 0x43, 0x00];

    /// <summary>Header size on a 64-bit target (§5.1).</summary>
    public const int HeaderSize64 = 40;

    /// <summary>
    /// Header size on a 32-bit target. The <c>pad0</c> field is explicit in the runtime's
    /// struct, so it survives even where alignment would not require it; only the three
    /// pointer-sized fields shrink.
    /// </summary>
    public const int HeaderSize32 = 32;

    // A descriptor blob is ~3 KB (§5.2: 3201 bytes). These bounds exist only so that a
    // read at a wrong address fails instead of allocating from garbage.
    private const int MaxJsonSize = 16 * 1024 * 1024;
    private const int MaxPointerDataCount = 1 << 16;

    private RuntimeDescriptor(
        ulong headerAddress,
        uint flags,
        bool targetIs64Bit,
        int descriptorSize,
        ulong jsonAddress,
        ulong pointerDataAddress,
        IReadOnlyList<ulong> pointerData,
        string json,
        int version,
        string baseline,
        IReadOnlyDictionary<string, DescriptorType> types,
        IReadOnlyDictionary<string, DescriptorGlobal> globals,
        IReadOnlyDictionary<string, int> contracts)
    {
        HeaderAddress = headerAddress;
        Flags = flags;
        TargetIs64Bit = targetIs64Bit;
        DescriptorSize = descriptorSize;
        JsonAddress = jsonAddress;
        PointerDataAddress = pointerDataAddress;
        PointerData = pointerData;
        Json = json;
        Version = version;
        Baseline = baseline;
        Types = types;
        Globals = globals;
        Contracts = contracts;
    }

    /// <summary>Address of the 40-byte header itself. Zero for a JSON-only fixture.</summary>
    public ulong HeaderAddress { get; }

    /// <summary>Raw flags word. Bit 0 is set by every known runtime; bit 1 is pointer size.</summary>
    public uint Flags { get; }

    /// <summary>
    /// §5.1: flags bit 1 is the pointer size, and it is inverted relative to the obvious
    /// reading — <c>0</c> means 64-bit. The observed x64 value is <c>0x1</c>.
    /// </summary>
    public bool TargetIs64Bit { get; }

    /// <summary>Pointer width the <em>descriptor</em> claims, which is what pointer_data uses.</summary>
    public int PointerSize => TargetIs64Bit ? 8 : 4;

    /// <summary>Byte count of the UTF-8 JSON blob (3201 for the §5.2 runtime).</summary>
    public int DescriptorSize { get; }

    /// <summary>Address of the JSON blob in the target.</summary>
    public ulong JsonAddress { get; }

    /// <summary>Address of the <c>pointer_data</c> array in the target.</summary>
    public ulong PointerDataAddress { get; }

    /// <summary>
    /// The <c>pointer_data</c> array, already read. Each entry is the <em>address of</em>
    /// a runtime global, not its value (§5.3). Index 0 is unused.
    /// </summary>
    public IReadOnlyList<ulong> PointerData { get; }

    /// <summary>The raw JSON, kept verbatim for diagnostics and for recording fixtures.</summary>
    public string Json { get; }

    /// <summary>Descriptor format version (<c>0</c> for .NET 9).</summary>
    public int Version { get; }

    /// <summary>
    /// Baseline the descriptor extends. <c>"empty"</c> means nothing is inherited — which
    /// is precisely why §5.5's gap exists: what is not in this blob is not published at all.
    /// </summary>
    public string Baseline { get; }

    public IReadOnlyDictionary<string, DescriptorType> Types { get; }

    public IReadOnlyDictionary<string, DescriptorGlobal> Globals { get; }

    /// <summary>Contract name → version (<c>Loader: 1</c>, <c>Object: 1</c>, ...).</summary>
    public IReadOnlyDictionary<string, int> Contracts { get; }

    /// <summary>
    /// Read and parse a descriptor from the target, given the address
    /// <see cref="DescriptorLocator"/> resolved.
    /// </summary>
    public static bool TryRead(
        IMemoryReader reader,
        ulong descriptorAddress,
        [NotNullWhen(true)] out RuntimeDescriptor? descriptor)
    {
        ArgumentNullException.ThrowIfNull(reader);
        descriptor = null;

        // Magic and flags first: flags decides the header's own size, so reading a fixed
        // 40 bytes would over-read a 32-bit target sitting at the end of a page.
        Span<byte> prefix = stackalloc byte[12];
        if (!reader.TryRead(descriptorAddress, prefix)) return false;
        if (!prefix[..8].SequenceEqual(Magic)) return false;

        uint flags = BinaryPrimitives.ReadUInt32LittleEndian(prefix[8..]);
        bool is64Bit = (flags & 0x2) == 0;

        Span<byte> header = stackalloc byte[HeaderSize64];
        header = header[..(is64Bit ? HeaderSize64 : HeaderSize32)];
        if (!reader.TryRead(descriptorAddress, header)) return false;

        uint descriptorSize = BinaryPrimitives.ReadUInt32LittleEndian(header[12..]);
        ulong jsonAddress;
        uint pointerDataCount;
        ulong pointerDataAddress;

        if (is64Bit)
        {
            jsonAddress = BinaryPrimitives.ReadUInt64LittleEndian(header[16..]);
            pointerDataCount = BinaryPrimitives.ReadUInt32LittleEndian(header[24..]);
            pointerDataAddress = BinaryPrimitives.ReadUInt64LittleEndian(header[32..]);
        }
        else
        {
            jsonAddress = BinaryPrimitives.ReadUInt32LittleEndian(header[16..]);
            pointerDataCount = BinaryPrimitives.ReadUInt32LittleEndian(header[20..]);
            pointerDataAddress = BinaryPrimitives.ReadUInt32LittleEndian(header[28..]);
        }

        if (descriptorSize == 0 || descriptorSize > MaxJsonSize) return false;
        if (pointerDataCount > MaxPointerDataCount) return false;
        if (jsonAddress == 0) return false;

        var jsonBytes = new byte[descriptorSize];
        if (!reader.TryRead(jsonAddress, jsonBytes)) return false;

        ulong[] pointerData = [];
        if (pointerDataCount != 0)
        {
            if (pointerDataAddress == 0) return false;
            if (!TryReadPointerData(reader, pointerDataAddress, (int)pointerDataCount, is64Bit, out pointerData))
            {
                return false;
            }
        }

        string json = Encoding.UTF8.GetString(jsonBytes);
        return TryParse(json, pointerData, is64Bit, flags, descriptorAddress, jsonAddress, pointerDataAddress, out descriptor);
    }

    /// <summary>
    /// Build a descriptor from JSON that is already in hand — a recorded fixture, or a
    /// blob extracted statically from the DLL. §8.8 wants CI to run without a live game,
    /// and this is the seam that allows it.
    /// </summary>
    public static bool TryParse(
        string json,
        IReadOnlyList<ulong>? pointerData,
        [NotNullWhen(true)] out RuntimeDescriptor? descriptor) =>
        TryParse(json, pointerData ?? [], targetIs64Bit: true, flags: 1, headerAddress: 0, jsonAddress: 0, pointerDataAddress: 0, out descriptor);

    private static bool TryParse(
        string json,
        IReadOnlyList<ulong> pointerData,
        bool targetIs64Bit,
        uint flags,
        ulong headerAddress,
        ulong jsonAddress,
        ulong pointerDataAddress,
        [NotNullWhen(true)] out RuntimeDescriptor? descriptor)
    {
        ArgumentNullException.ThrowIfNull(json);
        descriptor = null;

        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(json, new JsonDocumentOptions
            {
                CommentHandling = JsonCommentHandling.Skip,
                AllowTrailingCommas = true,
            });
        }
        catch (JsonException)
        {
            return false;
        }

        using (document)
        {
            JsonElement root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object) return false;

            int version = root.TryGetProperty("version", out JsonElement versionElement) &&
                          versionElement.ValueKind == JsonValueKind.Number &&
                          versionElement.TryGetInt32(out int v)
                ? v
                : 0;

            string baseline = root.TryGetProperty("baseline", out JsonElement baselineElement) &&
                              baselineElement.ValueKind == JsonValueKind.String
                ? baselineElement.GetString() ?? "empty"
                : "empty";

            descriptor = new RuntimeDescriptor(
                headerAddress,
                flags,
                targetIs64Bit,
                Encoding.UTF8.GetByteCount(json),
                jsonAddress,
                pointerDataAddress,
                pointerData,
                json,
                version,
                baseline,
                ParseTypes(root),
                ParseGlobals(root),
                ParseContracts(root));
        }

        return true;
    }

    private static bool TryReadPointerData(
        IMemoryReader reader,
        ulong address,
        int count,
        bool is64Bit,
        out ulong[] pointerData)
    {
        pointerData = [];
        int pointerSize = is64Bit ? 8 : 4;

        // One bulk read, not `count` reads: the array is contiguous and small, and a
        // single read is also a single moment in time.
        var raw = new byte[count * pointerSize];
        if (!reader.TryRead(address, raw)) return false;

        var values = new ulong[count];
        for (int i = 0; i < count; i++)
        {
            values[i] = is64Bit
                ? BinaryPrimitives.ReadUInt64LittleEndian(raw.AsSpan(i * 8))
                : BinaryPrimitives.ReadUInt32LittleEndian(raw.AsSpan(i * 4));
        }

        pointerData = values;
        return true;
    }

    private static Dictionary<string, DescriptorType> ParseTypes(JsonElement root)
    {
        var types = new Dictionary<string, DescriptorType>(StringComparer.Ordinal);
        if (!root.TryGetProperty("types", out JsonElement typesElement) ||
            typesElement.ValueKind != JsonValueKind.Object)
        {
            return types;
        }

        foreach (JsonProperty typeProperty in typesElement.EnumerateObject())
        {
            if (typeProperty.Value.ValueKind != JsonValueKind.Object) continue;

            int? size = null;
            var fields = new Dictionary<string, DescriptorField>(StringComparer.Ordinal);

            foreach (JsonProperty fieldProperty in typeProperty.Value.EnumerateObject())
            {
                // "!" is the type's own size, not a field. See DescriptorType.Size.
                if (fieldProperty.NameEquals("!"))
                {
                    if (TryReadOffset(fieldProperty.Value, out int typeSize)) size = typeSize;
                    continue;
                }

                if (!TryReadFieldOffset(fieldProperty.Value, out int offset, out string? fieldTypeName)) continue;
                fields[fieldProperty.Name] = new DescriptorField(fieldProperty.Name, offset, fieldTypeName);
            }

            types[typeProperty.Name] = new DescriptorType(typeProperty.Name, size, fields);
        }

        return types;
    }

    private static Dictionary<string, DescriptorGlobal> ParseGlobals(JsonElement root)
    {
        var globals = new Dictionary<string, DescriptorGlobal>(StringComparer.Ordinal);
        if (!root.TryGetProperty("globals", out JsonElement globalsElement) ||
            globalsElement.ValueKind != JsonValueKind.Object)
        {
            return globals;
        }

        foreach (JsonProperty property in globalsElement.EnumerateObject())
        {
            if (TryParseGlobal(property.Name, property.Value, out DescriptorGlobal? global))
            {
                globals[property.Name] = global;
            }
        }

        return globals;
    }

    /// <summary>
    /// Decode one published global. Array length carries the meaning, and the two lengths
    /// are unambiguous by design: <em>two</em> elements is "value and type", <em>one</em>
    /// element is "indirect value" — an index into <c>pointer_data</c>.
    /// </summary>
    /// <remarks>
    /// The rule composes, which is what makes it safe to apply in this order: the .NET 9
    /// spelling <c>[[1], "pointer"]</c> is a two-element "value and type" whose value is
    /// the one-element <c>[1]</c>, so unwrapping the type first and then testing for
    /// indirection handles both it and the terse <c>[1]</c> with one code path.
    /// <para>
    /// Getting this wrong in the terse direction is not cosmetic: reading <c>[1]</c> as a
    /// typeless literal publishes the pointer_data <em>index</em> as the global's
    /// <em>value</em>, so a caller asking for e.g. <c>AppDomain</c> receives <c>1</c> and
    /// has no way to tell. Every .NET 9 global carries a type, which is exactly why the
    /// fixture cannot catch it and why the shape is enforced here rather than trusted.
    /// </para>
    /// </remarks>
    private static bool TryParseGlobal(string name, JsonElement element, [NotNullWhen(true)] out DescriptorGlobal? global)
    {
        global = null;
        string? typeName = null;
        JsonElement valueElement = element;

        if (valueElement.ValueKind == JsonValueKind.Array && valueElement.GetArrayLength() == 2)
        {
            JsonElement typeElement = valueElement[1];
            if (typeElement.ValueKind != JsonValueKind.String) return false;

            typeName = typeElement.GetString();
            valueElement = valueElement[0];
        }

        if (valueElement.ValueKind == JsonValueKind.Array)
        {
            if (valueElement.GetArrayLength() != 1) return false;
            if (!TryReadOffset(valueElement[0], out int index)) return false;

            global = new DescriptorGlobal(name, typeName, isIndirect: true, value: 0, pointerDataIndex: index);
            return true;
        }

        if (!TryReadScalar(valueElement, out ulong literal)) return false;

        global = new DescriptorGlobal(name, typeName, isIndirect: false, value: literal, pointerDataIndex: -1);
        return true;
    }

    private static Dictionary<string, int> ParseContracts(JsonElement root)
    {
        var contracts = new Dictionary<string, int>(StringComparer.Ordinal);
        if (!root.TryGetProperty("contracts", out JsonElement contractsElement) ||
            contractsElement.ValueKind != JsonValueKind.Object)
        {
            return contracts;
        }

        foreach (JsonProperty property in contractsElement.EnumerateObject())
        {
            if (property.Value.ValueKind == JsonValueKind.Number && property.Value.TryGetInt32(out int version))
            {
                contracts[property.Name] = version;
            }
        }

        return contracts;
    }

    private static bool TryReadFieldOffset(JsonElement element, out int offset, out string? typeName)
    {
        typeName = null;

        // [offset, "TypeName"] — the type is a hint and may be absent.
        if (element.ValueKind == JsonValueKind.Array)
        {
            int length = element.GetArrayLength();
            if (length is < 1 or > 2) { offset = 0; return false; }
            if (length == 2 && element[1].ValueKind == JsonValueKind.String) typeName = element[1].GetString();
            return TryReadOffset(element[0], out offset);
        }

        return TryReadOffset(element, out offset);
    }

    private static bool TryReadOffset(JsonElement element, out int offset)
    {
        offset = 0;
        if (!TryReadScalar(element, out ulong value)) return false;
        if (value > int.MaxValue) return false;
        offset = (int)value;
        return true;
    }

    /// <summary>
    /// Scalars are published either as JSON numbers or as hex strings (<c>"0x7"</c>) —
    /// the string form exists because values wider than a double cannot round-trip
    /// through JSON numbers.
    /// </summary>
    private static bool TryReadScalar(JsonElement element, out ulong value)
    {
        value = 0;

        switch (element.ValueKind)
        {
            case JsonValueKind.Number:
                if (element.TryGetUInt64(out value)) return true;
                if (element.TryGetInt64(out long signed))
                {
                    value = unchecked((ulong)signed);
                    return true;
                }

                return false;

            case JsonValueKind.String:
                string? text = element.GetString();
                if (string.IsNullOrEmpty(text)) return false;

                // No sign. The string form exists to express values a JSON number cannot
                // hold, and "0xFFFFFFFFFFFFFFFF" already covers the full width — so a
                // leading '-' is malformed, and wrapping it to a near-2^64 literal would
                // manufacture a plausible-looking global out of a typo.
                ReadOnlySpan<char> span = text;
                bool hex = span.StartsWith("0x", StringComparison.OrdinalIgnoreCase);
                if (hex) span = span[2..];

                return ulong.TryParse(
                    span,
                    hex ? NumberStyles.HexNumber : NumberStyles.None,
                    CultureInfo.InvariantCulture,
                    out value);

            default:
                return false;
        }
    }
}
