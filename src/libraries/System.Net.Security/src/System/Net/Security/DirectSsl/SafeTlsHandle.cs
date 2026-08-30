// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.IO;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

namespace System.Net.Security
{
    /// <summary>
    /// A per-connection TLS session bound to a socket file descriptor.
    /// All operations are non-blocking — the underlying socket must be non-blocking.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Internally wraps OpenSSL's <c>SSL*</c>, bound to the socket via
    /// <c>SSL_set_fd</c> (no memory BIOs). The <see cref="SafeSocketHandle"/> is
    /// ref-counted via <c>DangerousAddRef</c> for the lifetime of this handle.
    /// </para>
    /// <para>
    /// <see cref="Read"/> and <see cref="Write"/> throw
    /// <see cref="InvalidOperationException"/> if the handshake has not completed.
    /// The caller must drive <see cref="Handshake"/> to completion first.
    /// </para>
    /// </remarks>
    [UnsupportedOSPlatform("windows")]
    [UnsupportedOSPlatform("browser")]
    [UnsupportedOSPlatform("wasi")]
    public sealed class SafeTlsHandle : SafeHandle
    {
        private SafeSocketHandle? _socket;
        private bool _socketRefAdded;
        private bool _handshakeCompleted;

        private SafeTlsHandle() : base(IntPtr.Zero, ownsHandle: true) { }

        /// <inheritdoc/>
        public override bool IsInvalid => handle == IntPtr.Zero;

        /// <inheritdoc/>
        protected override bool ReleaseHandle()
        {
            if (handle != IntPtr.Zero)
            {
                NativeInterop.SslSetQuietShutdown(handle, 1);
                NativeInterop.SslShutdown(handle);
                NativeInterop.SslDestroy(handle);
                SetHandle(IntPtr.Zero);
            }

            if (_socketRefAdded && _socket is not null)
            {
                _socket.DangerousRelease();
                _socketRefAdded = false;
            }

            return true;
        }

        /// <summary>
        /// Creates a TLS connection bound to a socket.
        /// </summary>
        /// <param name="context">The TLS configuration context.</param>
        /// <param name="socket">
        /// The socket to bind. Must be non-blocking. The handle is ref-counted
        /// for the lifetime of this <see cref="SafeTlsHandle"/>.
        /// </param>
        /// <param name="isServer">
        /// <see langword="true"/> for server-side (accept state);
        /// <see langword="false"/> for client-side (connect state).
        /// </param>
        /// <exception cref="IOException">
        /// The native <c>SSL_new</c> or <c>SSL_set_fd</c> call failed.
        /// </exception>
        public static SafeTlsHandle Create(
            SafeTlsContextHandle context,
            SafeSocketHandle socket,
            bool isServer)
        {
            ArgumentNullException.ThrowIfNull(context);
            ArgumentNullException.ThrowIfNull(socket);

            if (!(OperatingSystem.IsLinux() || OperatingSystem.IsFreeBSD()))
            {
                throw new PlatformNotSupportedException("SafeTlsHandle requires Linux or FreeBSD.");
            }

            // SSL_new(ctx)
            Microsoft.Win32.SafeHandles.SafeSslHandle internalHandle = Interop.Ssl.SslCreate(context);
            if (internalHandle.IsInvalid)
            {
                throw new IOException("SSL_new failed.");
            }

            IntPtr sslPtr = internalHandle.DangerousGetHandle();
            var tls = new SafeTlsHandle();
            tls.SetHandle(sslPtr);

            // SSL_set_fd — bind TLS to the socket's file descriptor.
            bool addedRef = false;
            try
            {
                socket.DangerousAddRef(ref addedRef);
                int fd = socket.DangerousGetHandle().ToInt32();

                // TODO: Add Interop.Ssl.SslSetFd(sslPtr, fd) — the one new P/Invoke.
                // This is a placeholder showing the intent.
                // Interop.Ssl.SslSetFd(sslPtr, fd);
            }
            catch
            {
                if (addedRef)
                {
                    socket.DangerousRelease();
                }

                tls.Dispose();
                throw;
            }

            tls._socket = socket;
            tls._socketRefAdded = addedRef;

            if (isServer)
            {
                Interop.Ssl.SslSetAcceptState(internalHandle);
            }
            else
            {
                Interop.Ssl.SslSetConnectState(internalHandle);
            }

            // Prevent the internal handle from releasing the SSL* — we own it now.
            internalHandle.SetHandleAsInvalid();

            return tls;
        }

        // ── Pre-handshake configuration ───────────────────────────────────────

        /// <summary>
        /// Sets the target host name for SNI (client-side). On the server side,
        /// use <see cref="TargetHostName"/> to read the client's SNI after handshake.
        /// </summary>
        public void SetTargetHostName(string targetHost)
        {
            ObjectDisposedException.ThrowIf(IsInvalid || IsClosed, this);
            ArgumentNullException.ThrowIfNull(targetHost);
            // Interop.Ssl.SslSetTlsExtHostName exists internally already.
            _ = targetHost;
        }

        /// <summary>
        /// Enables quiet shutdown — <see cref="Shutdown"/> will not wait for the
        /// peer's <c>close_notify</c> before returning <see cref="TlsOperationStatus.Complete"/>.
        /// </summary>
        public void SetQuietShutdown(bool enabled)
        {
            ObjectDisposedException.ThrowIf(IsInvalid || IsClosed, this);
            NativeInterop.SslSetQuietShutdown(handle, enabled ? 1 : 0);
        }

        // ── Non-blocking operations ───────────────────────────────────────────

        /// <summary>
        /// Drives the TLS handshake forward. Call repeatedly, observing the
        /// returned status and waiting for socket readiness between calls.
        /// </summary>
        /// <exception cref="AuthenticationException">
        /// A TLS protocol error, certificate verification failure, or other
        /// unrecoverable handshake error occurred.
        /// </exception>
        public TlsOperationStatus Handshake()
        {
            ObjectDisposedException.ThrowIf(IsInvalid || IsClosed, this);

            Interop.Ssl.SslErrorCode error;
            int n = NativeInterop.SslDoHandshake(handle, out error);

            if (n == 1)
            {
                _handshakeCompleted = true;
                return TlsOperationStatus.Complete;
            }

            return error switch
            {
                Interop.Ssl.SslErrorCode.SSL_ERROR_WANT_READ => TlsOperationStatus.WantRead,
                Interop.Ssl.SslErrorCode.SSL_ERROR_WANT_WRITE => TlsOperationStatus.WantWrite,
                Interop.Ssl.SslErrorCode.SSL_ERROR_ZERO_RETURN => TlsOperationStatus.Closed,
                Interop.Ssl.SslErrorCode.SSL_ERROR_SYSCALL => TlsOperationStatus.Closed,
                _ => throw new AuthenticationException($"TLS handshake failed (SSL_do_handshake error={error})."),
            };
        }

        /// <summary>Reads decrypted data from the TLS connection.</summary>
        /// <exception cref="InvalidOperationException">
        /// The TLS handshake has not completed.
        /// </exception>
        /// <exception cref="IOException">
        /// An unrecoverable I/O error occurred during decryption.
        /// </exception>
        public TlsOperationStatus Read(Span<byte> buffer, out int bytesRead)
        {
            ObjectDisposedException.ThrowIf(IsInvalid || IsClosed, this);

            if (!_handshakeCompleted)
            {
                throw new InvalidOperationException("TLS handshake has not been completed.");
            }

            Interop.Ssl.SslErrorCode error;
            int n = NativeInterop.SslRead(handle, ref MemoryMarshal.GetReference(buffer), buffer.Length, out error);

            if (n > 0)
            {
                bytesRead = n;
                return TlsOperationStatus.Complete;
            }

            bytesRead = 0;

            return error switch
            {
                Interop.Ssl.SslErrorCode.SSL_ERROR_WANT_READ => TlsOperationStatus.WantRead,
                Interop.Ssl.SslErrorCode.SSL_ERROR_WANT_WRITE => TlsOperationStatus.WantWrite,
                Interop.Ssl.SslErrorCode.SSL_ERROR_ZERO_RETURN => TlsOperationStatus.Complete, // clean EOF
                Interop.Ssl.SslErrorCode.SSL_ERROR_SYSCALL => TlsOperationStatus.Closed,
                _ => throw new IOException($"TLS read failed (SSL_read error={error})."),
            };
        }

        /// <summary>Writes data through the TLS connection (encrypts and sends).</summary>
        /// <exception cref="InvalidOperationException">
        /// The TLS handshake has not been completed.
        /// </exception>
        /// <exception cref="IOException">
        /// An unrecoverable I/O error occurred during encryption.
        /// </exception>
        public TlsOperationStatus Write(ReadOnlySpan<byte> buffer, out int bytesWritten)
        {
            ObjectDisposedException.ThrowIf(IsInvalid || IsClosed, this);

            if (!_handshakeCompleted)
            {
                throw new InvalidOperationException("TLS handshake has not been completed.");
            }

            Interop.Ssl.SslErrorCode error;
            int n = NativeInterop.SslWrite(handle, ref MemoryMarshal.GetReadOnlyReference(buffer), buffer.Length, out error);

            if (n > 0)
            {
                bytesWritten = n;
                return TlsOperationStatus.Complete;
            }

            bytesWritten = 0;

            return error switch
            {
                Interop.Ssl.SslErrorCode.SSL_ERROR_WANT_WRITE => TlsOperationStatus.WantWrite,
                Interop.Ssl.SslErrorCode.SSL_ERROR_WANT_READ => TlsOperationStatus.WantRead,
                Interop.Ssl.SslErrorCode.SSL_ERROR_ZERO_RETURN => TlsOperationStatus.Closed,
                Interop.Ssl.SslErrorCode.SSL_ERROR_SYSCALL => TlsOperationStatus.Closed,
                _ => throw new IOException($"TLS write failed (SSL_write error={error})."),
            };
        }

        /// <summary>Initiates TLS shutdown (sends <c>close_notify</c>).</summary>
        /// <exception cref="IOException">
        /// An unrecoverable I/O error occurred during shutdown.
        /// </exception>
        public TlsOperationStatus Shutdown()
        {
            ObjectDisposedException.ThrowIf(IsInvalid || IsClosed, this);

            int n = NativeInterop.SslShutdown(handle);

            if (n >= 1)
            {
                return TlsOperationStatus.Complete;
            }

            if (n == 0)
            {
                return TlsOperationStatus.WantRead; // need peer's close_notify
            }

            Interop.Ssl.SslErrorCode error = NativeInterop.SslGetError(handle, n);

            return error switch
            {
                Interop.Ssl.SslErrorCode.SSL_ERROR_WANT_READ => TlsOperationStatus.WantRead,
                Interop.Ssl.SslErrorCode.SSL_ERROR_WANT_WRITE => TlsOperationStatus.WantWrite,
                _ => TlsOperationStatus.Closed,
            };
        }

        // ── Negotiated info (valid once Handshake returned Complete) ──────────

        /// <summary>Gets the negotiated TLS protocol version.</summary>
        public SslProtocols NegotiatedProtocol => SslProtocols.None; // TODO: SSL_version

        /// <summary>Gets the negotiated cipher suite.</summary>
        public TlsCipherSuite NegotiatedCipherSuite => default; // TODO: SSL_get_current_cipher

        /// <summary>Gets the negotiated ALPN protocol.</summary>
        public SslApplicationProtocol NegotiatedApplicationProtocol => default; // TODO: SSL_get0_alpn_selected

        /// <summary>Gets the SNI hostname the client requested (server side),
        /// or the hostname set via <see cref="SetTargetHostName"/> (client side).</summary>
        public string? TargetHostName => null; // TODO: SSL_get_servername

        /// <summary>Gets whether this session was resumed from a previous session.</summary>
        public bool SessionResumed => false; // TODO: SSL_session_reused

        /// <summary>Gets the remote peer's certificate, if one was presented.</summary>
        public X509Certificate2? GetRemoteCertificate() => null; // TODO: SSL_get_peer_certificate

        // ── Native interop stubs ──────────────────────────────────────────────
        // These wrap existing CryptoNative_* functions but operate on raw IntPtr
        // instead of the internal SafeSslHandle type. In the real implementation,
        // these would be proper [LibraryImport] declarations.
        private static class NativeInterop
        {
            internal static void SslSetQuietShutdown(IntPtr ssl, int mode)
            {
                // CryptoNative_SslSetQuietShutdown — already exists in runtime.
            }

            internal static int SslShutdown(IntPtr ssl)
            {
                // CryptoNative_SslShutdown — already exists in runtime.
                return 0;
            }

            internal static void SslDestroy(IntPtr ssl)
            {
                // CryptoNative_SslDestroy — already exists in runtime.
            }

            internal static Interop.Ssl.SslErrorCode SslGetError(IntPtr ssl, int ret)
            {
                // CryptoNative_SslGetError — already exists in runtime.
                return Interop.Ssl.SslErrorCode.SSL_ERROR_NONE;
            }

            internal static int SslDoHandshake(IntPtr ssl, out Interop.Ssl.SslErrorCode error)
            {
                // CryptoNative_SslDoHandshake — already exists in runtime.
                error = Interop.Ssl.SslErrorCode.SSL_ERROR_NONE;
                return 1;
            }

            internal static int SslRead(IntPtr ssl, ref byte buf, int num, out Interop.Ssl.SslErrorCode error)
            {
                // CryptoNative_SslRead — already exists in runtime.
                error = Interop.Ssl.SslErrorCode.SSL_ERROR_NONE;
                return 0;
            }

            internal static int SslWrite(IntPtr ssl, ref byte buf, int num, out Interop.Ssl.SslErrorCode error)
            {
                // CryptoNative_SslWrite — already exists in runtime.
                error = Interop.Ssl.SslErrorCode.SSL_ERROR_NONE;
                return 0;
            }
        }
    }
}
