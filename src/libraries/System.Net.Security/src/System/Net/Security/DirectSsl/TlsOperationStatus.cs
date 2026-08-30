// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

namespace System.Net.Security
{
    /// <summary>
    /// Status returned from non-blocking TLS operations on <see cref="SafeTlsHandle"/>.
    /// </summary>
    /// <remarks>
    /// Maps to OpenSSL's <c>SSL_get_error()</c> classification in provider-opaque terms.
    /// Schannel's <c>SEC_I_CONTINUE_NEEDED</c> / <c>SEC_E_INCOMPLETE_MESSAGE</c> map
    /// onto the same enum values if a Windows backing is added later.
    /// </remarks>
    public enum TlsOperationStatus
    {
        /// <summary>
        /// Operation completed successfully. For <see cref="SafeTlsHandle.Read"/>:
        /// <c>bytesRead</c> bytes were produced, or <c>bytesRead == 0</c> means
        /// the peer sent <c>close_notify</c> (clean shutdown).
        /// </summary>
        Complete = 0,

        /// <summary>
        /// The TLS provider needs to read from the underlying socket before it can
        /// make progress. Wait for socket-readable, then call the same method again.
        /// </summary>
        WantRead = 1,

        /// <summary>
        /// The TLS provider needs to write to the underlying socket before it can
        /// make progress. Wait for socket-writable, then call the same method again.
        /// </summary>
        WantWrite = 2,

        /// <summary>
        /// The underlying transport is gone (RST, unexpected EOF before <c>close_notify</c>).
        /// The caller should dispose the <see cref="SafeTlsHandle"/>.
        /// </summary>
        Closed = 3,
    }
}
