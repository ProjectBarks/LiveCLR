namespace LiveClr.Cdac;

using LiveClr.Memory;

/// <summary>
/// Finds the cDAC contract descriptor in a target process: the one export that turns
/// CLR inspection from a version-keyed offset table into a self-describing read.
/// </summary>
/// <remarks>
/// <para>
/// Analysis doc §5: <c>coreclr.dll</c> exports only twelve symbols, and
/// <c>DotNetRuntimeContractDescriptor</c> is the one that publishes the runtime's own
/// layout. Reaching it uses the §4.3 remote export walk verbatim — no local
/// <c>LoadLibrary</c>, no matched DAC dll, no <c>g_dacTable</c> slot arithmetic
/// (§4.5 explains why that arithmetic is only ever valid against one exact build).
/// </para>
/// <para>
/// Module discovery itself is not done here. It is documented Win32 (§4.2) and belongs
/// to the process layer; this type takes a base address so it stays testable against a
/// synthetic image and reusable for a dump reader.
/// </para>
/// </remarks>
public static class DescriptorLocator
{
    /// <summary>The exported symbol, spelled exactly as the runtime exports it.</summary>
    public const string ExportName = "DotNetRuntimeContractDescriptor";

    /// <summary>
    /// Resolve the address of the 40-byte descriptor header in the target, given the
    /// base address the CoreCLR module is mapped at.
    /// </summary>
    /// <returns>
    /// False if the module is not a readable PE or does not export the symbol. A process
    /// running .NET 8 or earlier is exactly that case, so this must stay a probe rather
    /// than an assertion.
    /// </returns>
    public static bool TryLocate(IMemoryReader reader, ulong moduleBase, out ulong descriptorAddress)
    {
        ArgumentNullException.ThrowIfNull(reader);
        descriptorAddress = 0;

        if (!PeImage.TryLoad(reader, moduleBase, out PeImage? image)) return false;
        return TryLocate(image, out descriptorAddress);
    }

    /// <summary>Same, for a module whose headers are already parsed.</summary>
    public static bool TryLocate(PeImage image, out ulong descriptorAddress)
    {
        ArgumentNullException.ThrowIfNull(image);
        descriptorAddress = 0;

        if (!image.TryFindExport(ExportName, out ulong rva)) return false;

        // A forwarder would give us a string address, not a descriptor. The runtime does
        // not forward this symbol, but reading 40 bytes at a wrong address yields
        // plausible garbage rather than an error, which is the failure class this whole
        // library is built to avoid (§6.4).
        if (image.IsForwarderRva(rva)) return false;

        descriptorAddress = image.ImageBase + rva;
        return true;
    }

    /// <summary>
    /// Probe several module bases and take the first that exports the descriptor. Useful
    /// when the caller has a module list but no reliable name match (self-contained
    /// deployments rename nothing, but single-file hosts do relocate the runtime).
    /// </summary>
    public static bool TryLocate(IMemoryReader reader, IEnumerable<ulong> moduleBases, out ulong descriptorAddress)
    {
        ArgumentNullException.ThrowIfNull(reader);
        ArgumentNullException.ThrowIfNull(moduleBases);
        descriptorAddress = 0;

        foreach (ulong moduleBase in moduleBases)
        {
            if (TryLocate(reader, moduleBase, out descriptorAddress)) return true;
        }

        return false;
    }
}
