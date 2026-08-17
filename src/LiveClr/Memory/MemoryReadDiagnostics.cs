namespace LiveClr.Memory;

/// <summary>
/// Exposes the Win32 error behind the most recent failed read.
/// </summary>
/// <remarks>
/// <see cref="IMemoryReader.TryRead"/> deliberately returns only a bool, but
/// §4.8's error contract needs more than that: <c>scryObject.ts</c>'s
/// <c>isTransientRead</c> distinguishes retryable failures by matching
/// "Only part of a Read..." (ERROR_PARTIAL_COPY, a torn or straddling read)
/// against "Invalid access to memory location" (a bad pointer). Collapsing both
/// to a generic message keeps the retry logic compiling while quietly changing
/// which failures it retries.
/// <para>
/// <b>Measured caveat.</b> <c>ReadProcessMemory</c> reports ERROR_PARTIAL_COPY
/// for a wholly unmapped address as well as for a genuinely straddling one, so
/// the code separates those two cases less cleanly than the classifier's two
/// arms suggest. Both are retryable, so §4.8's behaviour is unaffected — but do
/// not build anything on "299 means the read was torn". The never-retry case is
/// carried by §6.4's address-zero rule, not by the error code.
/// </para>
/// <para>
/// A separate interface rather than a wider <see cref="IMemoryReader"/>: the
/// read primitive stays a single method, and readers that have no native error
/// to report (fakes, recorded fixtures) simply do not implement this.
/// </para>
/// </remarks>
public interface IMemoryReadDiagnostics
{
    /// <summary>
    /// Win32 error from the last failed <see cref="IMemoryReader.TryRead"/>, or
    /// 0 after a successful read. Only meaningful immediately after a failure.
    /// </summary>
    int LastNativeErrorCode { get; }
}

/// <summary>Helpers for reporting read failures with §4.8's error shape intact.</summary>
public static class MemoryReadDiagnostics
{
    /// <summary>
    /// Win32 error from <paramref name="reader"/>'s last failed read, or 0 when
    /// it does not track one.
    /// </summary>
    public static int LastNativeErrorCode(this IMemoryReader reader)
    {
        ArgumentNullException.ThrowIfNull(reader);
        return reader is IMemoryReadDiagnostics d ? d.LastNativeErrorCode : 0;
    }

    /// <summary>
    /// Builds the exception for a failed read, carrying the real Win32 error so
    /// the message renders the substring <c>isTransientRead</c> matches on.
    /// </summary>
    /// <remarks>
    /// Use this at every throw site that follows a failed <c>TryRead</c>. The
    /// convenience overloads on <see cref="MemoryReaderExtensions"/> cannot —
    /// they see only the bool — so they fall back to error 0, which still
    /// renders a classifier-matching message but cannot distinguish a torn read
    /// from a bad pointer.
    /// </remarks>
    public static MemoryAccessException ReadFailure(this IMemoryReader reader, ulong address, int length) =>
        new(address, length, reader.LastNativeErrorCode());
}
