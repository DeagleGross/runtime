// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Authentication;

namespace System.Net.Security
{
    /// <summary>
    /// A long-lived TLS configuration context. Thread-safe; create once per listener,
    /// share across many <see cref="SafeTlsHandle"/> instances.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Internally wraps OpenSSL's <c>SSL_CTX*</c>. Configuration is applied from
    /// <see cref="SslServerAuthenticationOptions"/> or <see cref="SslClientAuthenticationOptions"/>
    /// during factory construction.
    /// </para>
    /// <para>
    /// Only <see cref="SetSessionCacheSize"/> and <see cref="SetSessionTimeout"/> remain as
    /// instance methods — these knobs are not yet available on the options types.
    /// </para>
    /// </remarks>
    [UnsupportedOSPlatform("windows")]
    [UnsupportedOSPlatform("browser")]
    [UnsupportedOSPlatform("wasi")]
    public sealed class SafeTlsContextHandle : SafeHandle
    {
        private SafeTlsContextHandle() : base(IntPtr.Zero, ownsHandle: true) { }

        /// <inheritdoc/>
        public override bool IsInvalid => handle == IntPtr.Zero;

        /// <inheritdoc/>
        protected override bool ReleaseHandle()
        {
            Interop.Ssl.SslCtxDestroy(handle);
            SetHandle(IntPtr.Zero);
            return true;
        }

        /// <summary>
        /// Creates a server-side TLS context configured from the given options.
        /// </summary>
        /// <param name="options">
        /// Server authentication options. Properties mapped to native configuration:
        /// <see cref="SslServerAuthenticationOptions.ServerCertificate"/> or
        /// <see cref="SslServerAuthenticationOptions.ServerCertificateContext"/> → certificate/key,
        /// <see cref="SslServerAuthenticationOptions.EnabledSslProtocols"/> → protocol range,
        /// <see cref="SslServerAuthenticationOptions.ApplicationProtocols"/> → ALPN,
        /// <see cref="SslServerAuthenticationOptions.AllowRenegotiation"/> → renegotiation policy,
        /// <see cref="SslServerAuthenticationOptions.AllowTlsResume"/> → session cache,
        /// <see cref="SslServerAuthenticationOptions.CipherSuitesPolicy"/> → cipher suites.
        /// </param>
        /// <exception cref="AuthenticationException">
        /// Certificate or key configuration failed (e.g., private key mismatch).
        /// </exception>
        /// <exception cref="PlatformNotSupportedException">
        /// The current platform does not support direct-fd TLS.
        /// </exception>
        public static SafeTlsContextHandle Create(SslServerAuthenticationOptions options)
        {
            ArgumentNullException.ThrowIfNull(options);
            ThrowIfNotSupported();

            IntPtr method = Interop.Ssl.SslV2_3Method();
            SafeTlsContextHandle ctx = CreateFromMethod(method);

            // Apply configuration from options.
            // In the real implementation, each property maps to an SSL_CTX_* call.
            // The runtime already has internal helpers for all of these in
            // SslAuthenticationOptions.UpdateOptions / SslStreamPal.Unix.cs.

            // TODO: Wire the following from options:
            // options.ServerCertificate / ServerCertificateContext → SSL_CTX_use_certificate + SSL_CTX_use_PrivateKey
            // options.EnabledSslProtocols → SSL_CTX_set_min/max_proto_version
            // options.ApplicationProtocols → SSL_CTX_set_alpn_select_cb
            // options.AllowRenegotiation → SSL_CTX_set_options(SSL_OP_NO_RENEGOTIATION)
            // options.AllowTlsResume → SSL_CTX_set_session_cache_mode
            // options.CipherSuitesPolicy → SSL_CTX_set_ciphersuites / SSL_CTX_set_cipher_list

            return ctx;
        }

        /// <summary>
        /// Creates a client-side TLS context configured from the given options.
        /// </summary>
        /// <exception cref="PlatformNotSupportedException">
        /// The current platform does not support direct-fd TLS.
        /// </exception>
        public static SafeTlsContextHandle Create(SslClientAuthenticationOptions options)
        {
            ArgumentNullException.ThrowIfNull(options);
            ThrowIfNotSupported();

            IntPtr method = Interop.Ssl.SslV2_3Method();
            SafeTlsContextHandle ctx = CreateFromMethod(method);

            // TODO: Wire the following from options:
            // options.EnabledSslProtocols → SSL_CTX_set_min/max_proto_version
            // options.ApplicationProtocols → SSL_CTX_set_alpn_protos
            // options.AllowRenegotiation → SSL_CTX_set_options(SSL_OP_NO_RENEGOTIATION)
            // options.AllowTlsResume → SSL_CTX_set_session_cache_mode
            // options.CipherSuitesPolicy → SSL_CTX_set_ciphersuites / SSL_CTX_set_cipher_list

            return ctx;
        }

        /// <summary>
        /// Sets the TLS session cache size. Controls how many resumable sessions
        /// are kept in memory.
        /// </summary>
        /// <remarks>
        /// This is not available on <see cref="SslServerAuthenticationOptions"/> today.
        /// Maps to OpenSSL's <c>SSL_CTX_sess_set_cache_size</c>.
        /// </remarks>
        public void SetSessionCacheSize(int size)
        {
            ObjectDisposedException.ThrowIf(IsInvalid || IsClosed, this);
            ArgumentOutOfRangeException.ThrowIfNegativeOrZero(size);
            // TODO: Interop.Ssl.SslCtxSetCacheSize(handle, size);
            _ = size;
        }

        /// <summary>
        /// Sets the TLS session timeout. Sessions older than this are not resumed.
        /// </summary>
        /// <remarks>
        /// This is not available on <see cref="SslServerAuthenticationOptions"/> today.
        /// Maps to OpenSSL's <c>SSL_CTX_set_timeout</c>.
        /// </remarks>
        public void SetSessionTimeout(TimeSpan timeout)
        {
            ObjectDisposedException.ThrowIf(IsInvalid || IsClosed, this);
            ArgumentOutOfRangeException.ThrowIfLessThan(timeout, TimeSpan.Zero);
            // TODO: Interop.Ssl.SslCtxSetTimeout(handle, (int)timeout.TotalSeconds);
            _ = timeout;
        }

        private static SafeTlsContextHandle CreateFromMethod(IntPtr method)
        {
            SafeTlsContextHandle ctx = Interop.Ssl.SslCtxCreate(method);
            if (ctx.IsInvalid)
            {
                throw new AuthenticationException("Failed to create TLS context (SSL_CTX_new returned null).");
            }

            return ctx;
        }

        private static void ThrowIfNotSupported()
        {
            if (!(OperatingSystem.IsLinux() || OperatingSystem.IsFreeBSD()))
            {
                throw new PlatformNotSupportedException("SafeTlsContextHandle requires Linux or FreeBSD.");
            }
        }
    }
}
