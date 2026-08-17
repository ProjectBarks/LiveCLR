namespace LiveClr.Calibration;

/// <summary>
/// One observation of a struct whose field offset is unknown: "at this address there lives an
/// object of the type being calibrated, and one of its pointer fields holds this target".
/// </summary>
/// <remarks>
/// Analysis doc §12.5 derived the Godot parent offset (0x128) this way, using a known
/// parent/child pair as ground truth. §7b.2 notes the pairs need not come from an external
/// tool at all: any two managed objects in a known relationship expose the native pointers.
/// </remarks>
/// <param name="Address">Base address of the object being scanned.</param>
/// <param name="ExpectedTarget">The pointer value that must appear somewhere in it.</param>
public readonly record struct PointerSample(ulong Address, ulong ExpectedTarget);

/// <summary>One observation of a struct with an independently-known field value.</summary>
/// <remarks>
/// The value must be independently known — that is the whole trick. §12.5's anchor was "this
/// control is full-screen, so its size is the design viewport (1920x1080)". Deriving the
/// offset from a value you read at a guessed offset proves nothing.
/// </remarks>
/// <typeparam name="T">Field type, compared by exact bit pattern.</typeparam>
/// <param name="Address">Base address of the object being scanned.</param>
/// <param name="ExpectedValue">The value that must appear somewhere in it.</param>
public readonly record struct ValueSample<T>(ulong Address, T ExpectedValue) where T : unmanaged;

/// <summary>
/// One observation of a struct containing two adjacent values of the same type — a vector,
/// a rect's origin, a pair of counts.
/// </summary>
/// <remarks>
/// §12.5 found the Godot size offset by scanning for 1920 and 1080 as an <i>adjacent float
/// pair</i>. Scanning for the components separately is much weaker: 1920 alone occurs all over
/// a real object, and the adjacency constraint is what makes a two-component match rare.
/// </remarks>
/// <typeparam name="T">Component type, compared by exact bit pattern.</typeparam>
/// <param name="Address">Base address of the object being scanned.</param>
/// <param name="First">Expected first component.</param>
/// <param name="Second">Expected second component, stored immediately after the first.</param>
public readonly record struct PairSample<T>(ulong Address, T First, T Second) where T : unmanaged;
