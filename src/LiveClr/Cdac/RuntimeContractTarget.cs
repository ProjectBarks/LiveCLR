namespace LiveClr.Cdac;

using System.Diagnostics.CodeAnalysis;
using LiveClr.Memory;

/// <summary>
/// The read-side view of a parsed contract descriptor: name-based lookups for types,
/// fields, globals and contract versions against a live target.
/// </summary>
/// <remarks>
/// <para>
/// Shaped after Microsoft's cDAC <c>Target</c> (analysis doc §8.3) so that an official
/// package, should one ever ship, can be slotted in behind
/// <see cref="IRuntimeContractTarget"/>.
/// </para>
/// <para>
/// <b>Every lookup degrades; none throws.</b> This is not defensive style, it is a
/// finding: §5.5 established that the shipped .NET 9 descriptor does <em>not</em>
/// publish <c>AppDomain</c>, <c>Assembly</c> or <c>ArrayListBase</c>, and
/// <c>baseline: "empty"</c> means nothing is inherited to fill the gap. Microsoft's
/// compatibility goal covers readers and contracts, not coverage of every structure a
/// consumer wants (§5). A caller that cannot walk the assembly list must be able to fall
/// back to the object-upward route — which is impossible if a missing key throws.
/// </para>
/// </remarks>
public sealed class RuntimeContractTarget : IRuntimeContractTarget, IContractRegistry
{
    private readonly string[] _typeNames;
    private readonly string[] _globalNames;
    private readonly string[] _contractNames;

    private RuntimeContractTarget(IMemoryReader memory, RuntimeDescriptor descriptor)
    {
        Memory = memory;
        Descriptor = descriptor;

        // Materialised once. The interface hands these out as collections, and
        // recomputing them per call would make an innocuous-looking property expensive
        // inside a polling loop.
        _typeNames = [.. descriptor.Types.Keys];
        _globalNames = [.. descriptor.Globals.Keys];
        _contractNames = [.. descriptor.Contracts.Keys];
    }

    /// <inheritdoc/>
    public IMemoryReader Memory { get; }

    /// <summary>The parsed descriptor behind this target.</summary>
    public RuntimeDescriptor Descriptor { get; }

    /// <inheritdoc/>
    public int DescriptorVersion => Descriptor.Version;

    /// <inheritdoc/>
    public string DescriptorJson => Descriptor.Json;

    /// <inheritdoc/>
    public IReadOnlyCollection<string> TypeNames => _typeNames;

    /// <inheritdoc/>
    public IReadOnlyCollection<string> GlobalNames => _globalNames;

    /// <summary>Contracts the descriptor advertises (<c>Loader</c>, <c>Object</c>, ...).</summary>
    public IReadOnlyCollection<string> ContractNames => _contractNames;

    /// <summary>Pair an already-parsed descriptor with the reader it was read from.</summary>
    public static RuntimeContractTarget Create(IMemoryReader memory, RuntimeDescriptor descriptor)
    {
        ArgumentNullException.ThrowIfNull(memory);
        ArgumentNullException.ThrowIfNull(descriptor);
        return new RuntimeContractTarget(memory, descriptor);
    }

    /// <summary>
    /// Full bootstrap from a CoreCLR module base: §4.3 export walk → §5.1 header →
    /// §5.2 JSON → §5.3 pointer_data.
    /// </summary>
    /// <returns>
    /// False when the module does not export the descriptor (pre-.NET-9 runtimes) or the
    /// descriptor cannot be read. Both are ordinary outcomes when probing a process, not
    /// exceptional ones.
    /// </returns>
    public static bool TryCreate(
        IMemoryReader memory,
        ulong coreClrModuleBase,
        [NotNullWhen(true)] out RuntimeContractTarget? target)
    {
        ArgumentNullException.ThrowIfNull(memory);
        target = null;

        if (!DescriptorLocator.TryLocate(memory, coreClrModuleBase, out ulong descriptorAddress)) return false;
        return TryCreateFromDescriptorAddress(memory, descriptorAddress, out target);
    }

    /// <summary>Same, when the descriptor address is already known.</summary>
    public static bool TryCreateFromDescriptorAddress(
        IMemoryReader memory,
        ulong descriptorAddress,
        [NotNullWhen(true)] out RuntimeContractTarget? target)
    {
        ArgumentNullException.ThrowIfNull(memory);
        target = null;

        if (!RuntimeDescriptor.TryRead(memory, descriptorAddress, out RuntimeDescriptor? descriptor)) return false;

        target = new RuntimeContractTarget(memory, descriptor);
        return true;
    }

    /// <inheritdoc/>
    public bool HasType(string typeName) =>
        typeName is not null && Descriptor.Types.ContainsKey(typeName);

    /// <summary>Look up a published type. Null when the descriptor does not publish it.</summary>
    public DescriptorType? GetTypeLayout(string typeName) =>
        typeName is not null && Descriptor.Types.TryGetValue(typeName, out DescriptorType? type) ? type : null;

    /// <inheritdoc/>
    /// <remarks>
    /// Only types carrying a <c>"!"</c> entry have a published size, and most do not —
    /// <c>Object</c>, <c>MethodTable</c> and <c>Module</c> all omit it. A false here means
    /// "not published", never "size zero".
    /// </remarks>
    public bool TryGetTypeSize(string typeName, out int size)
    {
        size = 0;
        DescriptorType? type = GetTypeLayout(typeName);
        if (type?.Size is not int published) return false;

        size = published;
        return true;
    }

    /// <inheritdoc/>
    public bool HasField(string typeName, string fieldName) =>
        fieldName is not null && GetTypeLayout(typeName)?.Fields.ContainsKey(fieldName) == true;

    /// <inheritdoc/>
    public bool TryGetFieldOffset(string typeName, string fieldName, out int offset)
    {
        offset = 0;
        if (fieldName is null) return false;
        if (GetTypeLayout(typeName) is not DescriptorType type) return false;
        if (!type.Fields.TryGetValue(fieldName, out DescriptorField field)) return false;

        offset = field.Offset;
        return true;
    }

    /// <summary>
    /// The optional type name published alongside a field offset — the
    /// <c>[312, "GCHandle"]</c> form. Absent for plain <c>"Module": 24</c> fields, which
    /// is the common case, so a false result says nothing about whether the field exists.
    /// </summary>
    public bool TryGetFieldType(string typeName, string fieldName, out string? fieldTypeName)
    {
        fieldTypeName = null;
        if (fieldName is null) return false;
        if (GetTypeLayout(typeName) is not DescriptorType type) return false;
        if (!type.Fields.TryGetValue(fieldName, out DescriptorField field)) return false;
        if (field.TypeName is null) return false;

        fieldTypeName = field.TypeName;
        return true;
    }

    /// <summary>
    /// Address of a field within an instance. No read happens here, so this cannot fail
    /// for reasons other than the field not being published.
    /// </summary>
    public bool TryGetFieldAddress(ulong instanceAddress, string typeName, string fieldName, out ulong address)
    {
        address = 0;
        if (!TryGetFieldOffset(typeName, fieldName, out int offset)) return false;

        address = instanceAddress + (ulong)offset;
        return true;
    }

    /// <summary>Read a field of an instance using the published offset.</summary>
    /// <remarks>
    /// Returns false for both "not published" and "read failed". Callers that must tell
    /// those apart should check <see cref="HasField"/> first — for a polling consumer the
    /// distinction rarely matters, since either way the value is unavailable this tick.
    /// </remarks>
    public bool TryReadField<T>(ulong instanceAddress, string typeName, string fieldName, out T value)
        where T : unmanaged
    {
        value = default;
        if (!TryGetFieldAddress(instanceAddress, typeName, fieldName, out ulong address)) return false;
        return Memory.TryRead(address, out value);
    }

    /// <summary>Read a pointer-sized field of an instance using the published offset.</summary>
    public bool TryReadFieldPointer(ulong instanceAddress, string typeName, string fieldName, out ulong value)
    {
        value = 0;
        if (!TryGetFieldAddress(instanceAddress, typeName, fieldName, out ulong address)) return false;
        return Memory.TryReadPointer(address, out value);
    }

    /// <summary>True if the descriptor publishes this global, in either form.</summary>
    public bool HasGlobal(string name) =>
        name is not null && Descriptor.Globals.ContainsKey(name);

    /// <summary>The raw global entry, so callers can tell the two forms apart.</summary>
    public DescriptorGlobal? GetGlobal(string name) =>
        name is not null && Descriptor.Globals.TryGetValue(name, out DescriptorGlobal? global) ? global : null;

    /// <inheritdoc/>
    /// <remarks>
    /// Literal globals only — <c>ObjectToMethodTableUnmask</c>, <c>ObjectHeaderSize</c>,
    /// <c>MethodDescAlignment</c> and friends, whose values are baked into the descriptor
    /// and need no memory access. Indirect globals deliberately return false here:
    /// silently substituting <c>pointer_data[i]</c> would hand back the <em>address of</em>
    /// the global where the caller asked for its value (§5.3), which is the kind of
    /// plausible-but-wrong number that costs a day to find.
    /// </remarks>
    public bool TryGetGlobalValue(string name, out ulong value)
    {
        value = 0;
        if (GetGlobal(name) is not DescriptorGlobal global || global.IsIndirect) return false;

        value = global.Value;
        return true;
    }

    /// <inheritdoc/>
    public bool TryGetGlobalPointer(string name, out ulong addressOfGlobal)
    {
        addressOfGlobal = 0;
        if (GetGlobal(name) is not DescriptorGlobal global || !global.IsIndirect) return false;

        int index = global.PointerDataIndex;
        if (index < 0 || index >= Descriptor.PointerData.Count) return false;

        addressOfGlobal = Descriptor.PointerData[index];
        return addressOfGlobal != 0;
    }

    /// <summary>
    /// The dereference §5.3 ends with: <c>pointer_data[i]</c> is <c>&amp;AppDomain</c>, so
    /// the AppDomain pointer itself needs one more read. Kept separate from
    /// <see cref="TryGetGlobalPointer"/> because this one touches the target and can fail
    /// transiently, while that one cannot fail at all once the descriptor is parsed.
    /// </summary>
    public bool TryReadGlobalPointer(string name, out ulong value)
    {
        value = 0;
        if (!TryGetGlobalPointer(name, out ulong addressOfGlobal)) return false;
        return Memory.TryReadPointer(addressOfGlobal, out value);
    }

    /// <inheritdoc/>
    public bool TryGetContractVersion(string contractName, out int version)
    {
        version = 0;
        if (contractName is null) return false;
        return Descriptor.Contracts.TryGetValue(contractName, out version);
    }
}
