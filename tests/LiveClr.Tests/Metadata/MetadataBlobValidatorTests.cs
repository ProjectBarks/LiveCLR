namespace LiveClr.Tests.Metadata;

using System.Buffers.Binary;
using System.Text;
using LiveClr.Metadata;

/// <summary>
/// Direct tests of the gate that stands between remote bytes and
/// <c>System.Reflection.Metadata</c>, which the BCL documents as NOT hardened against
/// untrusted input. Every case here is a blob a stale or wrong module base could produce.
/// </summary>
public sealed class MetadataBlobValidatorTests
{
    [Fact]
    public void AcceptsARealMetadataRoot()
    {
        // A root emitted by MetadataRootBuilder — genuine library output, no PE walk needed,
        // so this stays a test of the validator rather than of ModuleMetadata.
        byte[] blob = SyntheticMetadata.Build(_ => { });

        Assert.True(MetadataBlobValidator.TryValidate(blob, out MetadataRootInfo? info, out _));
        Assert.NotNull(info);
        Assert.True(info.HasStream("#~"));
        Assert.True(info.HasStream("#Strings"));
        Assert.False(info.HasStream("#NotAStream"));
    }

    [Fact]
    public void RejectsAnEmptyOrTinyBlob()
    {
        Assert.False(MetadataBlobValidator.TryValidate([], out _, out string? error));
        Assert.NotNull(error);

        Assert.False(MetadataBlobValidator.TryValidate(new byte[19], out _, out _));
    }

    [Fact]
    public void RejectsAMissingSignature()
    {
        byte[] blob = BuildBlob();
        blob[0] = (byte)'X';

        Assert.False(MetadataBlobValidator.TryValidate(blob, out _, out string? error));
        Assert.Contains("BSJB", error ?? string.Empty);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-4)]
    [InlineData(6)]      // not a multiple of 4
    [InlineData(1024)]   // beyond the ECMA-335 cap
    public void RejectsAnImplausibleVersionLength(int versionLength)
    {
        byte[] blob = BuildBlob();
        BinaryPrimitives.WriteInt32LittleEndian(blob.AsSpan(12), versionLength);

        Assert.False(MetadataBlobValidator.TryValidate(blob, out _, out _));
    }

    [Theory]
    [InlineData(0)]        // no streams at all
    [InlineData(65)]       // just past MaxStreams
    [InlineData(65535)]    // the largest lie the 16-bit field can tell
    public void RejectsAnImplausibleStreamCount(int declaredStreams)
    {
        byte[] blob = BuildBlob(declaredStreamCount: declaredStreams);

        Assert.False(MetadataBlobValidator.TryValidate(blob, out _, out string? error));
        Assert.NotNull(error);
    }

    [Fact]
    public void AcceptsAStreamCountAtTheCapBoundary()
    {
        // The cap must reject 65 without rejecting a merely unusual 64 — a real image can
        // carry more streams than the canonical five.
        byte[] blob = BuildBlob(declaredStreamCount: 64, streamHeaderRepeats: 64);

        Assert.True(MetadataBlobValidator.TryValidate(blob, out MetadataRootInfo? info, out string? error));
        Assert.Null(error);
        Assert.NotNull(info);
        Assert.Equal(64, info.Streams.Count);
    }

    [Fact]
    public void RejectsAStreamOffsetPlusSizeThatOverflowsTheBlob()
    {
        // The core check. 0xFFFFFFF0 + 0x20 wraps in 32-bit arithmetic and would look like a
        // tiny, in-range stream to a careless validator.
        byte[] blob = BuildBlob(streamOffset: 0xFFFF_FFF0u, streamSize: 0x20u);

        Assert.False(MetadataBlobValidator.TryValidate(blob, out _, out string? error));
        Assert.Contains("outside", error ?? string.Empty);
    }

    [Fact]
    public void RejectsATruncatedStreamHeaderTable()
    {
        byte[] blob = BuildBlob();

        // 38 bytes: the root header and stream count survive, the declared stream header
        // does not. A short remote copy looks exactly like this.
        Assert.False(MetadataBlobValidator.TryValidate(blob.AsSpan(0, 38), out _, out string? error));
        Assert.Contains("stream header", error ?? string.Empty);

        // 80 bytes: headers intact, but the stream they describe no longer fits.
        Assert.False(MetadataBlobValidator.TryValidate(blob.AsSpan(0, 80), out _, out string? spanError));
        Assert.Contains("outside", spanError ?? string.Empty);
    }

    [Fact]
    public void RejectsABlobWithNoTableStream()
    {
        byte[] blob = BuildBlob(streamName: "#Strings");

        Assert.False(MetadataBlobValidator.TryValidate(blob, out _, out string? error));
        Assert.Contains("#~", error ?? string.Empty);
    }

    [Fact]
    public void RejectsAnUnterminatedStreamName()
    {
        byte[] blob = BuildBlob();
        // Overwrite the name and its NUL padding with non-zero bytes.
        for (int i = 40; i < blob.Length; i++) blob[i] = 0xAB;

        Assert.False(MetadataBlobValidator.TryValidate(blob, out _, out _));
    }

    [Fact]
    public void AcceptsAMinimalWellFormedRootAndReportsItsShape()
    {
        byte[] blob = BuildBlob();

        Assert.True(MetadataBlobValidator.TryValidate(blob, out MetadataRootInfo? info, out string? error));
        Assert.Null(error);
        Assert.NotNull(info);
        Assert.Equal("v4.0.30319", info.VersionString);
        Assert.Single(info.Streams);
        Assert.Equal("#~", info.Streams[0].Name);
    }

    /// <summary>
    /// Hand-built metadata root: BSJB, version block, one stream header. Small enough that
    /// every offset under test is obvious.
    /// </summary>
    private static byte[] BuildBlob(
        string streamName = "#~",
        uint streamOffset = 64,
        uint streamSize = 32,
        int? declaredStreamCount = null,
        int streamHeaderRepeats = 1)
    {
        const string Version = "v4.0.30319";
        byte[] versionBytes = new byte[12]; // 10 chars + NUL, rounded up to a multiple of 4
        Encoding.ASCII.GetBytes(Version).CopyTo(versionBytes, 0);

        // 8 bytes of offset/size plus the name rounded up to a 4-byte boundary.
        int headerBytes = 8 + ((streamName.Length + 1 + 3) & ~3);
        var blob = new byte[Math.Max(128, 32 + (streamHeaderRepeats * headerBytes) + 64)];
        Span<byte> span = blob;

        BinaryPrimitives.WriteUInt32LittleEndian(span, 0x424A_5342); // 'BSJB'
        BinaryPrimitives.WriteUInt16LittleEndian(span[4..], 1);
        BinaryPrimitives.WriteUInt16LittleEndian(span[6..], 1);
        BinaryPrimitives.WriteUInt32LittleEndian(span[8..], 0);      // Reserved
        BinaryPrimitives.WriteInt32LittleEndian(span[12..], versionBytes.Length);
        versionBytes.CopyTo(span[16..]);

        int cursor = 16 + versionBytes.Length;                       // 28
        BinaryPrimitives.WriteUInt16LittleEndian(span[cursor..], 0); // Flags
        BinaryPrimitives.WriteUInt16LittleEndian(
            span[(cursor + 2)..], (ushort)(declaredStreamCount ?? streamHeaderRepeats));
        cursor += 4;                                                 // 32

        for (int i = 0; i < streamHeaderRepeats; i++)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(span[cursor..], streamOffset);
            BinaryPrimitives.WriteUInt32LittleEndian(span[(cursor + 4)..], streamSize);
            Encoding.ASCII.GetBytes(streamName).CopyTo(span[(cursor + 8)..]);
            cursor += headerBytes;
        }

        return blob;
    }
}
