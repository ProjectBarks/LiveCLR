namespace LiveClr.Tests.Cdac;

using System.Text;
using LiveClr.Cdac;

/// <summary>
/// The §5.1 header parse and the §5.2 JSON parse, driven through a fake address space so
/// the whole §12.1 path — export walk, header, blob, pointer_data — is exercised as one
/// piece rather than as four mocked halves.
/// </summary>
public class RuntimeDescriptorTests
{
    [Fact]
    public void TryRead_ParsesTheHeaderFieldsFromTheVerifiedByteDump()
    {
        using FakeMemory memory = SyntheticDescriptor.BuildTarget();

        Assert.True(RuntimeDescriptor.TryRead(memory, SyntheticDescriptor.DescriptorAddress, out RuntimeDescriptor? d));

        Assert.Equal(0x1u, d.Flags);
        Assert.True(d.TargetIs64Bit);            // §5.1: flags bit1 clear means 64-bit
        Assert.Equal(8, d.PointerSize);
        Assert.Equal(SyntheticDescriptor.JsonAddress, d.JsonAddress);
        Assert.Equal(SyntheticDescriptor.PointerDataAddress, d.PointerDataAddress);
        Assert.Equal(14, d.PointerData.Count);
        Assert.Equal(Encoding.UTF8.GetByteCount(DescriptorFixture.Json), d.DescriptorSize);
    }

    [Fact]
    public void TryRead_KeepsTheJsonVerbatim()
    {
        // §12.1's strongest single check was that the live blob came back byte-identical
        // to the static extraction, so the raw text has to survive the round trip.
        using FakeMemory memory = SyntheticDescriptor.BuildTarget();

        Assert.True(RuntimeDescriptor.TryRead(memory, SyntheticDescriptor.DescriptorAddress, out RuntimeDescriptor? d));
        Assert.Equal(DescriptorFixture.Json, d.Json);
    }

    [Fact]
    public void TryRead_ParsesTheDescriptorContents()
    {
        using FakeMemory memory = SyntheticDescriptor.BuildTarget();
        Assert.True(RuntimeDescriptor.TryRead(memory, SyntheticDescriptor.DescriptorAddress, out RuntimeDescriptor? d));

        // §5.2: version 0, baseline "empty", 29 types / 22 globals / 7 contracts.
        Assert.Equal(0, d.Version);
        Assert.Equal("empty", d.Baseline);
        Assert.Equal(29, d.Types.Count);
        Assert.Equal(22, d.Globals.Count);
        Assert.Equal(7, d.Contracts.Count);
    }

    [Fact]
    public void TryRead_ReadsPointerDataAsTheAddressesOfGlobals()
    {
        using FakeMemory memory = SyntheticDescriptor.BuildTarget();
        Assert.True(RuntimeDescriptor.TryRead(memory, SyntheticDescriptor.DescriptorAddress, out RuntimeDescriptor? d));

        Assert.Equal(SyntheticDescriptor.PointerData[1], d.PointerData[1]);   // &AppDomain, §5.3
        Assert.Equal(0UL, d.PointerData[0]);                                  // index 0 unused
    }

    /// <summary>
    /// Reading 40 bytes at the wrong address yields plausible garbage rather than an error,
    /// so the magic is the only thing standing between us and a confident misparse.
    /// </summary>
    /// <remarks>
    /// The target is complete and readable in every other respect — the same
    /// <see cref="SyntheticDescriptor.BuildTarget"/> the parsing tests use — so the magic is
    /// the ONLY thing that can refuse it. An earlier version mapped the 40-byte header alone;
    /// <c>jsonAddress</c> then pointed at unmapped memory and <c>TryRead</c> refused thirty
    /// lines later at the blob read, which meant deleting the magic check left this test
    /// green. §13.11's species: the check refused, but not for the reason under test.
    /// </remarks>
    [Theory]
    [InlineData("DNCCDA?")]   // one byte of the eight
    [InlineData("dnccdac")]   // right letters, wrong case
    [InlineData("CADCCND")]   // §5.1: a big-endian target stores it reversed
    public void TryRead_RejectsAWrongMagic(string magic)
    {
        using FakeMemory memory = SyntheticDescriptor.BuildTarget(magic: magic);

        Assert.False(RuntimeDescriptor.TryRead(memory, SyntheticDescriptor.DescriptorAddress, out RuntimeDescriptor? d));
        Assert.Null(d);

        // The control, in the same test: the identical target with the magic intact parses.
        // Without this the refusal above could still be coming from somewhere else.
        using FakeMemory intact = SyntheticDescriptor.BuildTarget();
        Assert.True(RuntimeDescriptor.TryRead(intact, SyntheticDescriptor.DescriptorAddress, out _));
    }

    [Fact]
    public void TryRead_RejectsAnUnmappedJsonBlob()
    {
        byte[] jsonBytes = Encoding.UTF8.GetBytes(DescriptorFixture.Json);
        using var memory = new FakeMemory()
            .Map(SyntheticDescriptor.DescriptorAddress, SyntheticDescriptor.Header64(jsonBytes.Length))
            .Map(SyntheticDescriptor.PointerDataAddress, SyntheticDescriptor.Pointers64(SyntheticDescriptor.PointerData));

        Assert.False(RuntimeDescriptor.TryRead(memory, SyntheticDescriptor.DescriptorAddress, out _));
    }

    [Fact]
    public void TryRead_RejectsATruncatedJsonBlob()
    {
        // descriptor_size longer than what is actually mapped: a partial read must fail
        // rather than hand back a blob that happens to parse.
        byte[] jsonBytes = Encoding.UTF8.GetBytes(DescriptorFixture.Json);
        using var memory = new FakeMemory()
            .Map(SyntheticDescriptor.DescriptorAddress, SyntheticDescriptor.Header64(jsonBytes.Length + 64))
            .Map(SyntheticDescriptor.JsonAddress, jsonBytes)
            .Map(SyntheticDescriptor.PointerDataAddress, SyntheticDescriptor.Pointers64(SyntheticDescriptor.PointerData));

        Assert.False(RuntimeDescriptor.TryRead(memory, SyntheticDescriptor.DescriptorAddress, out _));
    }

    [Fact]
    public void TryRead_RejectsAnAbsurdDescriptorSize()
    {
        using var memory = new FakeMemory()
            .Map(SyntheticDescriptor.DescriptorAddress, SyntheticDescriptor.Header64(int.MaxValue));

        Assert.False(RuntimeDescriptor.TryRead(memory, SyntheticDescriptor.DescriptorAddress, out _));
    }

    [Fact]
    public void TryRead_RejectsMalformedJson()
    {
        Assert.False(TryReadWithJson("{ this is not json", out _));
    }

    [Fact]
    public void TryRead_HandlesADescriptorWithNoPointerData()
    {
        // Legal: pointer_data_count of zero just means no indirect globals. It must not
        // be confused with a failed read.
        byte[] jsonBytes = Encoding.UTF8.GetBytes(DescriptorFixture.Json);
        using var memory = new FakeMemory()
            .Map(SyntheticDescriptor.DescriptorAddress, SyntheticDescriptor.Header64(jsonBytes.Length, pointerDataCount: 0))
            .Map(SyntheticDescriptor.JsonAddress, jsonBytes);

        Assert.True(RuntimeDescriptor.TryRead(memory, SyntheticDescriptor.DescriptorAddress, out RuntimeDescriptor? d));
        Assert.Empty(d.PointerData);
    }

    [Fact]
    public void TryRead_UsesTheThirtyTwoBitHeaderLayoutWhenFlagsSayThirtyTwoBit()
    {
        // The pointer-sized fields shift, so a reader that always uses the 64-bit offsets
        // reads descriptor_size's neighbours as a pointer. flags bit1 is the only signal.
        const uint jsonAddress = 0x0040_0000;
        const uint pointerDataAddress = 0x0041_0000;
        byte[] jsonBytes = Encoding.UTF8.GetBytes(DescriptorFixture.Json);

        using var memory = new FakeMemory(is64Bit: false)
            .Map(0x0030_0000, SyntheticDescriptor.Header32(jsonBytes.Length, jsonAddress, 3, pointerDataAddress))
            .Map(jsonAddress, jsonBytes)
            .Map(pointerDataAddress, SyntheticDescriptor.Pointers32([0, 0x0050_0000, 0x0050_0004]));

        Assert.True(RuntimeDescriptor.TryRead(memory, 0x0030_0000, out RuntimeDescriptor? d));
        Assert.False(d.TargetIs64Bit);
        Assert.Equal(4, d.PointerSize);
        Assert.Equal(3, d.PointerData.Count);
        Assert.Equal(0x0050_0000UL, d.PointerData[1]);
    }

    [Fact]
    public void TryParse_WorksWithoutAnyMemoryAtAll()
    {
        // The fixture seam §8.8 asks for: parse a recorded blob with no target present.
        Assert.True(RuntimeDescriptor.TryParse(DescriptorFixture.Json, null, out RuntimeDescriptor? d));

        Assert.Equal(29, d.Types.Count);
        Assert.Empty(d.PointerData);
    }

    [Fact]
    public void ParsedFields_CarryTheirOptionalTypeName()
    {
        Assert.True(RuntimeDescriptor.TryParse(DescriptorFixture.Json, null, out RuntimeDescriptor? d));

        DescriptorField gcHandle = d.Types["Thread"].Fields["GCHandle"];
        Assert.Equal(312, gcHandle.Offset);
        Assert.Equal("GCHandle", gcHandle.TypeName);

        DescriptorField plain = d.Types["MethodTable"].Fields["Module"];
        Assert.Equal(24, plain.Offset);
        Assert.Null(plain.TypeName);
    }

    [Fact]
    public void ParsedTypes_TreatTheBangKeyAsTheTypeSize()
    {
        Assert.True(RuntimeDescriptor.TryParse(DescriptorFixture.Json, null, out RuntimeDescriptor? d));

        Assert.Equal(16, d.Types["Array"].Size);
        Assert.DoesNotContain("!", d.Types["Array"].Fields.Keys);
        Assert.Null(d.Types["Object"].Size);
    }

    [Fact]
    public void ParsedGlobals_DistinguishLiteralsFromPointerDataIndices()
    {
        Assert.True(RuntimeDescriptor.TryParse(DescriptorFixture.Json, null, out RuntimeDescriptor? d));

        DescriptorGlobal literal = d.Globals["ObjectToMethodTableUnmask"];
        Assert.False(literal.IsIndirect);
        Assert.Equal(0x7UL, literal.Value);
        Assert.Equal("uint8", literal.TypeName);

        DescriptorGlobal indirect = d.Globals["AppDomain"];
        Assert.True(indirect.IsIndirect);
        Assert.Equal(1, indirect.PointerDataIndex);
        Assert.Equal("pointer", indirect.TypeName);
    }

    [Theory]
    [InlineData("[\"0x10\", \"uint32\"]", 16UL)]     // hex string, the published form
    [InlineData("[16, \"uint32\"]", 16UL)]           // bare number
    [InlineData("16", 16UL)]                         // no type hint at all
    [InlineData("\"0x10\"", 16UL)]                   // bare hex string
    [InlineData("[\"0xFFFFFFFFFFFFFFFF\", \"uint64\"]", ulong.MaxValue)]
    public void ParsedGlobals_AcceptEveryPublishedScalarSpelling(string json, ulong expected)
    {
        RuntimeDescriptor d = ParseGlobal(json);

        Assert.False(d.Globals["X"].IsIndirect);
        Assert.Equal(expected, d.Globals["X"].Value);
    }

    [Theory]
    [InlineData("[[1], \"pointer\"]")]   // the .NET 9 spelling: value and type
    [InlineData("[1]")]                  // the terse spelling: indirect value, no type
    [InlineData("[\"0x1\"]")]            // same, with the index written in hex
    public void ParsedGlobals_TreatEveryOneElementArrayAsIndirect(string json)
    {
        // A one-element array is unambiguously an indirect value, and a two-element array
        // is unambiguously value-and-type. Reading the terse form as a typeless literal
        // would publish the pointer_data INDEX as the global's VALUE — a caller asking
        // for AppDomain would receive 1, with nothing to distinguish it from a real
        // address. Every .NET 9 global carries a type, so the fixture cannot catch this.
        RuntimeDescriptor d = ParseGlobal(json);
        DescriptorGlobal global = d.Globals["X"];

        Assert.True(global.IsIndirect);
        Assert.Equal(1, global.PointerDataIndex);
        Assert.Equal(0UL, global.Value);
    }

    [Fact]
    public void ParsedGlobals_TerseAndTypedIndirectFormsAgree()
    {
        DescriptorGlobal terse = ParseGlobal("[7]").Globals["X"];
        DescriptorGlobal typed = ParseGlobal("[[7], \"pointer\"]").Globals["X"];

        Assert.Equal(typed.IsIndirect, terse.IsIndirect);
        Assert.Equal(typed.PointerDataIndex, terse.PointerDataIndex);
        Assert.Equal(typed.Value, terse.Value);
        Assert.Null(terse.TypeName);
        Assert.Equal("pointer", typed.TypeName);
    }

    [Theory]
    [InlineData("\"-5\"")]        // no runtime publishes a negative; wrapping it would
    [InlineData("\"-0x5\"")]      // manufacture a near-2^64 literal out of a typo
    [InlineData("\" 5\"")]        // leading whitespace
    [InlineData("\"\"")]
    [InlineData("\"nonsense\"")]
    [InlineData("[1, 2]")]        // two elements, but the second is not a type
    [InlineData("[1, 2, 3]")]
    [InlineData("[[1, 2]]")]
    [InlineData("[]")]
    [InlineData("true")]
    [InlineData("null")]
    public void ParsedGlobals_SkipMalformedSpellings(string json)
    {
        Assert.False(ParseGlobal(json).Globals.ContainsKey("X"));
    }

    private static RuntimeDescriptor ParseGlobal(string json)
    {
        string blob = """{"version":0,"baseline":"empty","globals":{"X":""" + json + "}}";

        Assert.True(RuntimeDescriptor.TryParse(blob, null, out RuntimeDescriptor? d));
        Assert.NotNull(d);
        return d;
    }

    [Fact]
    public void Parsing_SkipsEntriesItCannotUnderstandInsteadOfFailing()
    {
        // The descriptor is a versioned format the runtime may extend. Refusing to start
        // because one future entry is unrecognised would throw away the forward
        // compatibility that motivates using it at all (§5).
        const string blob = """
            {
              "version": 0,
              "baseline": "empty",
              "types": { "Object": { "m_pMethTab": 0, "Weird": { "nested": 1 } } },
              "globals": { "Fine": ["0x2", "uint8"], "Weird": { "nested": 1 } },
              "contracts": { "Loader": 1, "Weird": "one" }
            }
            """;

        Assert.True(RuntimeDescriptor.TryParse(blob, null, out RuntimeDescriptor? d));

        Assert.Equal(0, d.Types["Object"].Fields["m_pMethTab"].Offset);
        Assert.DoesNotContain("Weird", d.Types["Object"].Fields.Keys);
        Assert.True(d.Globals.ContainsKey("Fine"));
        Assert.False(d.Globals.ContainsKey("Weird"));
        Assert.Equal(1, d.Contracts["Loader"]);
        Assert.False(d.Contracts.ContainsKey("Weird"));
    }

    /// <summary>
    /// The header fields the parser reads rather than assumes: format version, baseline, and
    /// per-contract versions.
    /// </summary>
    /// <remarks>
    /// Every blob in this suite is the shipped §5.2 one — version 0, baseline "empty", every
    /// contract at version 1 — and those are ALSO the fallbacks this parser uses when a field is
    /// missing or malformed. So the three were indistinguishable from constants: hardcoding
    /// <c>version = 0</c>, <c>baseline = "empty"</c> and <c>contracts[name] = 1</c> left the
    /// whole suite green (§13.11). The descriptor is an explicitly versioned format the runtime
    /// is expected to extend, and a later baseline is the ordinary forward case, not a hostile
    /// one.
    /// </remarks>
    [Fact]
    public void Parsing_ReadsTheVersionBaselineAndContractVersionsRatherThanAssumingThem()
    {
        const string blob = """
            {
              "version": 1,
              "baseline": "generic_baseline",
              "contracts": { "Loader": 1, "Object": 2, "Thread": 7 }
            }
            """;

        Assert.True(RuntimeDescriptor.TryParse(blob, null, out RuntimeDescriptor? d));

        Assert.Equal(1, d.Version);
        Assert.Equal("generic_baseline", d.Baseline);
        Assert.Equal(1, d.Contracts["Loader"]);
        Assert.Equal(2, d.Contracts["Object"]);
        Assert.Equal(7, d.Contracts["Thread"]);
    }

    [Fact]
    public void Parsing_FallsBackToVersionZeroAndAnEmptyBaselineOnlyWhenTheyAreAbsent()
    {
        // The other half of the pair above: the defaults are what a descriptor that publishes
        // neither gets, not what every descriptor gets.
        Assert.True(RuntimeDescriptor.TryParse("""{"types":{}}""", null, out RuntimeDescriptor? d));

        Assert.Equal(0, d.Version);
        Assert.Equal("empty", d.Baseline);

        // A wrong-shaped value is also a fallback, not a parse failure — §5's forward
        // compatibility argument applies to the header fields too.
        Assert.True(RuntimeDescriptor.TryParse("""{"version":"1","baseline":7}""", null, out RuntimeDescriptor? odd));
        Assert.Equal(0, odd.Version);
        Assert.Equal("empty", odd.Baseline);
    }

    [Fact]
    public void Parsing_ToleratesADescriptorWithNoTypesOrGlobals()
    {
        Assert.True(RuntimeDescriptor.TryParse("""{"version":0,"baseline":"empty"}""", null, out RuntimeDescriptor? d));

        Assert.Empty(d.Types);
        Assert.Empty(d.Globals);
        Assert.Empty(d.Contracts);
    }

    private static bool TryReadWithJson(string json, out RuntimeDescriptor? descriptor)
    {
        byte[] jsonBytes = Encoding.UTF8.GetBytes(json);
        using var memory = new FakeMemory()
            .Map(SyntheticDescriptor.DescriptorAddress, SyntheticDescriptor.Header64(jsonBytes.Length, pointerDataCount: 0))
            .Map(SyntheticDescriptor.JsonAddress, jsonBytes);

        return RuntimeDescriptor.TryRead(memory, SyntheticDescriptor.DescriptorAddress, out descriptor);
    }
}
