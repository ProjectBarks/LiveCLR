namespace LiveClr.Tests.Cdac;

using System.Buffers.Binary;
using System.Text;

/// <summary>
/// Assembles the §5.1 descriptor header, its JSON blob and its <c>pointer_data</c> array
/// into a fake address space — the static half of what §12.1 read out of a live game.
/// </summary>
internal static class SyntheticDescriptor
{
    /// <summary>Address of the descriptor header: image base + the §5.1 export RVA.</summary>
    public const ulong DescriptorAddress = SyntheticPe.DefaultImageBase + SyntheticPe.DescriptorExportRva;

    // Both are the live §12.1 values, which are the static RVAs (0x3EC2A0, 0x45F4F0)
    // rebased onto the ASLR'd module base — a cheap check that the fixture is coherent.
    public const ulong JsonAddress = SyntheticPe.DefaultImageBase + 0x3E_C2A0;
    public const ulong PointerDataAddress = SyntheticPe.DefaultImageBase + 0x45_F4F0;

    /// <summary>
    /// The <c>pointer_data</c> array. Indices 1, 2, 3, 8, 10 and 11 are the addresses
    /// §5.3 verified against the shipped DLL; the rest are filler at plausible
    /// neighbouring addresses, since the doc only tabulated the six it used. Index 0 is
    /// unused by the runtime, so it is left zero here too.
    /// </summary>
    public static ulong[] PointerData =>
    [
        0x0000_0000_0000_0000UL, // 0  unused
        0x0000_0001_8046_2780UL, // 1  &AppDomain              (§5.3)
        0x0000_0001_8046_3218UL, // 2  &ThreadStore            (§5.3)
        0x0000_0001_8046_32C0UL, // 3  &FinalizerThread        (§5.3)
        0x0000_0001_8046_3300UL, // 4  &GCThread               (filler)
        0x0000_0001_8046_3310UL, // 5  &ArrayBoundsZero        (filler)
        0x0000_0001_8046_3320UL, // 6  &ExceptionMethodTable   (filler)
        0x0000_0001_8046_3330UL, // 7  &FreeObjectMethodTable  (filler)
        0x0000_0001_8046_3400UL, // 8  &ObjectMethodTable      (§5.3)
        0x0000_0001_8046_3340UL, // 9  &ObjectArrayMethodTable (filler)
        0x0000_0001_8046_3368UL, // 10 &StringMethodTable      (§5.3)
        0x0000_0001_8046_3438UL, // 11 &SyncTableEntries       (§5.3)
        0x0000_0001_8046_3350UL, // 12 &MiniMetaDataBuffAddress (filler)
        0x0000_0001_8046_3358UL, // 13 &MiniMetaDataBuffMaxSize (filler)
    ];

    public static byte[] Header64(
        int jsonSize,
        ulong jsonAddress = JsonAddress,
        int pointerDataCount = 14,
        ulong pointerDataAddress = PointerDataAddress,
        uint flags = 0x1,
        string magic = "DNCCDAC")
    {
        var header = new byte[40];
        Span<byte> span = header;

        Encoding.ASCII.GetBytes(magic).CopyTo(span);  // byte 7 stays NUL
        BinaryPrimitives.WriteUInt32LittleEndian(span[8..], flags);
        BinaryPrimitives.WriteUInt32LittleEndian(span[12..], (uint)jsonSize);
        BinaryPrimitives.WriteUInt64LittleEndian(span[16..], jsonAddress);
        BinaryPrimitives.WriteUInt32LittleEndian(span[24..], (uint)pointerDataCount);
        BinaryPrimitives.WriteUInt64LittleEndian(span[32..], pointerDataAddress);

        return header;
    }

    /// <summary>
    /// The 32-bit form: <c>pad0</c> survives, only the pointer-sized fields shrink, so
    /// the header is 32 bytes and pointer_data lands at +28.
    /// </summary>
    public static byte[] Header32(int jsonSize, uint jsonAddress, int pointerDataCount, uint pointerDataAddress)
    {
        var header = new byte[32];
        Span<byte> span = header;

        Encoding.ASCII.GetBytes("DNCCDAC").CopyTo(span);
        BinaryPrimitives.WriteUInt32LittleEndian(span[8..], 0x3);   // bit0 set, bit1 = 32-bit
        BinaryPrimitives.WriteUInt32LittleEndian(span[12..], (uint)jsonSize);
        BinaryPrimitives.WriteUInt32LittleEndian(span[16..], jsonAddress);
        BinaryPrimitives.WriteUInt32LittleEndian(span[20..], (uint)pointerDataCount);
        BinaryPrimitives.WriteUInt32LittleEndian(span[28..], pointerDataAddress);

        return header;
    }

    public static byte[] Pointers64(IReadOnlyList<ulong> values)
    {
        var raw = new byte[values.Count * 8];
        for (int i = 0; i < values.Count; i++)
        {
            BinaryPrimitives.WriteUInt64LittleEndian(raw.AsSpan(i * 8), values[i]);
        }

        return raw;
    }

    public static byte[] Pointers32(IReadOnlyList<uint> values)
    {
        var raw = new byte[values.Count * 4];
        for (int i = 0; i < values.Count; i++)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(raw.AsSpan(i * 4), values[i]);
        }

        return raw;
    }

    /// <summary>
    /// The whole §12.1 scenario in one call: a coreclr-like module at an ASLR'd base
    /// exporting the descriptor, the header, the real JSON blob, and pointer_data.
    /// </summary>
    /// <param name="json">Blob to publish; the verbatim §5.2 fixture when omitted.</param>
    /// <param name="magic">
    /// Header magic. Overridable so that a magic test can run against a target that is
    /// <em>otherwise entirely valid</em> — blob and pointer_data both mapped and readable —
    /// which is the only arrangement in which the magic check is the thing doing the
    /// refusing. Mapping the 40-byte header alone leaves <c>jsonAddress</c> pointing at
    /// nothing, so the read fails thirty lines later whether the magic is checked or not
    /// (§13.11).
    /// </param>
    public static FakeMemory BuildTarget(string? json = null, string magic = "DNCCDAC")
    {
        byte[] jsonBytes = Encoding.UTF8.GetBytes(json ?? DescriptorFixture.Json);

        return new FakeMemory()
            .Map(SyntheticPe.DefaultImageBase, SyntheticPe.BuildCoreClrLike())
            .Map(DescriptorAddress, Header64(jsonBytes.Length, magic: magic))
            .Map(JsonAddress, jsonBytes)
            .Map(PointerDataAddress, Pointers64(PointerData));
    }
}
