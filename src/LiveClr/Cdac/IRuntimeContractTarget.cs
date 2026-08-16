namespace LiveClr.Cdac;

using LiveClr.Memory;

/// <summary>
/// A parsed cDAC contract descriptor: what the runtime publishes about itself.
/// Shaped deliberately like Microsoft's cDAC <c>Target</c> so that if an official
/// package ever ships, it can be slotted in behind this interface.
/// </summary>
/// <remarks>
/// Every lookup is a Try*/Has* pair. The .NET 9 descriptor does NOT publish
/// everything (analysis doc §5.5: no AppDomain, Assembly, or ArrayListBase),
/// so callers must degrade rather than assume coverage. Never throw for a
/// missing entry.
/// </remarks>
public interface IRuntimeContractTarget
{
    IMemoryReader Memory { get; }

    /// <summary>Descriptor JSON version field.</summary>
    int DescriptorVersion { get; }

    /// <summary>Raw descriptor JSON, retained for diagnostics and fixtures.</summary>
    string DescriptorJson { get; }

    bool TryGetGlobalValue(string name, out ulong value);

    /// <summary>
    /// Globals published as <c>[[index], "pointer"]</c> resolve through the
    /// descriptor's pointer_data array: the entry holds the ADDRESS OF the
    /// global, so reading its value requires one further dereference.
    /// </summary>
    bool TryGetGlobalPointer(string name, out ulong addressOfGlobal);

    bool HasType(string typeName);

    bool TryGetTypeSize(string typeName, out int size);

    bool HasField(string typeName, string fieldName);

    bool TryGetFieldOffset(string typeName, string fieldName, out int offset);

    IReadOnlyCollection<string> TypeNames { get; }
    IReadOnlyCollection<string> GlobalNames { get; }
}

/// <summary>Contract versions the descriptor advertises (Loader, Object, RuntimeTypeSystem, ...).</summary>
public interface IContractRegistry
{
    bool TryGetContractVersion(string contractName, out int version);
}
