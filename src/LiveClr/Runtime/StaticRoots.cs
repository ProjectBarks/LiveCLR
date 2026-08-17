namespace LiveClr.Runtime;

using LiveClr.Memory;

/// <summary>
/// Supplies the ADDRESS of a static field's storage slot.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why this is a seam and not an implementation.</b> A static field's storage lives in a
/// per-module statics blob reached through structures the .NET 9 contract descriptor does not
/// publish: its 29 types include no <c>DomainLocalModule</c>, no <c>MethodTable</c> auxiliary
/// data, and no <c>FieldDesc</c> (§5.2, and §5.5 for the same shape of gap one level up).
/// There is therefore no descriptor-only route from <c>"MyGame.RunManager"</c> +
/// <c>"Instance"</c> to an address, and no published ground truth to calibrate one against the
/// way <see cref="FieldDescCalibration"/> does for instance fields.
/// </para>
/// <para>
/// §5.5 already names the sanctioned answer for exactly this class of gap: "ClrMD (suspended,
/// once at connect) to resolve the module pointer and any static-field addresses, then hand
/// off". §8.8 confines ClrMD to dev/test and cold bootstrap, never the polling loop — which is
/// precisely how this is shaped, since a static's ADDRESS is loader-heap stable while the
/// object it points at is not.
/// </para>
/// <para>
/// <b>The address is cacheable; the value is not.</b> §7b.1 measured the same singleton at two
/// different managed addresses minutes apart. Resolve the address once at connect, then re-read
/// it every snapshot — which is what <c>ClrType.Static</c> does, and why static roots are
/// re-resolved rather than remembered.
/// </para>
/// </remarks>
public interface IClrStaticRootSource
{
    /// <summary>
    /// Address of the slot holding the static field, or false when unknown.
    /// </summary>
    /// <param name="memory">Reader for the target, for implementations that resolve lazily.</param>
    /// <param name="typeFullName">Declaring type's full metadata name.</param>
    /// <param name="fieldName">Static field name.</param>
    /// <param name="address">Address of the slot — NOT the value in it.</param>
    bool TryGetStaticAddress(IMemoryReader memory, string typeFullName, string fieldName, out ulong address);
}

/// <summary>A source that knows nothing. The default, so statics degrade to null rather than throw.</summary>
public sealed class EmptyStaticRootSource : IClrStaticRootSource
{
    /// <summary>The singleton instance.</summary>
    public static EmptyStaticRootSource Instance { get; } = new();

    /// <inheritdoc/>
    public bool TryGetStaticAddress(IMemoryReader memory, string typeFullName, string fieldName, out ulong address)
    {
        address = 0;
        return false;
    }
}

/// <summary>Caller-supplied static field addresses, resolved once at connect (§5.5).</summary>
public sealed class ExplicitStaticRootSource : IClrStaticRootSource
{
    private readonly Dictionary<(string Type, string Field), ulong> _addresses = [];

    /// <summary>Record the address of one static field's slot.</summary>
    public ExplicitStaticRootSource Add(string typeFullName, string fieldName, ulong slotAddress)
    {
        ArgumentNullException.ThrowIfNull(typeFullName);
        ArgumentNullException.ThrowIfNull(fieldName);
        _addresses[(typeFullName, fieldName)] = slotAddress;
        return this;
    }

    /// <summary>Number of recorded roots.</summary>
    public int Count => _addresses.Count;

    /// <inheritdoc/>
    public bool TryGetStaticAddress(IMemoryReader memory, string typeFullName, string fieldName, out ulong address) =>
        _addresses.TryGetValue((typeFullName, fieldName), out address);
}
