// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace TlsPersistentBench;

/// <summary>
/// Minimal direct P/Invoke into OpenSSL 3.x. Mirrors the surface used by the
/// aspnetcore-side OpenSslDirect engine so the bench's 4th variant is an
/// apples-to-apples comparison with what was previously measured against TlsSession.
///
/// Linux-only. Library names are hardcoded to <c>libssl.so.3</c> and
/// <c>libcrypto.so.3</c> — same as the aspnetcore prototype. Use only on a host
/// with OpenSSL 3.x installed (the runtime build host normally has it).
/// </summary>
internal static unsafe partial class OpenSslInterop
{
    private const string LibSsl = "libssl.so.3";
    private const string LibCrypto = "libcrypto.so.3";

    // SSL_get_error return codes
    public const int SSL_ERROR_NONE = 0;
    public const int SSL_ERROR_SSL = 1;
    public const int SSL_ERROR_WANT_READ = 2;
    public const int SSL_ERROR_WANT_WRITE = 3;
    public const int SSL_ERROR_SYSCALL = 5;
    public const int SSL_ERROR_ZERO_RETURN = 6;

    // File types
    public const int SSL_FILETYPE_PEM = 1;

    // Session cache modes
    public const int SSL_SESS_CACHE_SERVER = 0x0002;

    // SSL_CTX_ctrl op codes (session cache helpers)
    private const int SSL_CTRL_SET_SESS_CACHE_SIZE = 42;
    private const int SSL_CTRL_SET_SESS_CACHE_MODE = 44;

    // ---- Context ----
    [LibraryImport(LibSsl)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    public static partial IntPtr TLS_server_method();

    [LibraryImport(LibSsl)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    public static partial IntPtr SSL_CTX_new(IntPtr method);

    [LibraryImport(LibSsl)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    public static partial void SSL_CTX_free(IntPtr ctx);

    [LibraryImport(LibSsl, StringMarshalling = StringMarshalling.Utf8)]
    public static partial int SSL_CTX_use_certificate_file(IntPtr ctx, string file, int type);

    [LibraryImport(LibSsl, StringMarshalling = StringMarshalling.Utf8)]
    public static partial int SSL_CTX_use_PrivateKey_file(IntPtr ctx, string file, int type);

    [LibraryImport(LibSsl)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    public static partial int SSL_CTX_check_private_key(IntPtr ctx);

    [LibraryImport(LibSsl)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static partial long SSL_CTX_ctrl(IntPtr ctx, int cmd, long larg, IntPtr parg);

    [LibraryImport(LibSsl)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    public static partial long SSL_CTX_set_timeout(IntPtr ctx, long t);

    public static int SetSessionCacheMode(IntPtr ctx, int mode)
        => (int)SSL_CTX_ctrl(ctx, SSL_CTRL_SET_SESS_CACHE_MODE, mode, IntPtr.Zero);

    public static long SetSessionCacheSize(IntPtr ctx, long size)
        => SSL_CTX_ctrl(ctx, SSL_CTRL_SET_SESS_CACHE_SIZE, size, IntPtr.Zero);

    // ---- Session ----
    [LibraryImport(LibSsl)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    public static partial IntPtr SSL_new(IntPtr ctx);

    [LibraryImport(LibSsl)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    public static partial void SSL_free(IntPtr ssl);

    [LibraryImport(LibSsl)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    public static partial int SSL_set_fd(IntPtr ssl, int fd);

    [LibraryImport(LibSsl)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    public static partial void SSL_set_accept_state(IntPtr ssl);

    [LibraryImport(LibSsl)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    public static partial int SSL_do_handshake(IntPtr ssl);

    [LibraryImport(LibSsl)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    public static partial int SSL_read(IntPtr ssl, byte* buf, int num);

    [LibraryImport(LibSsl)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    public static partial int SSL_write(IntPtr ssl, byte* buf, int num);

    [LibraryImport(LibSsl)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    public static partial int SSL_get_error(IntPtr ssl, int ret);

    [LibraryImport(LibSsl)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    public static partial int SSL_shutdown(IntPtr ssl);

    // ---- Init & errors ----
    [LibraryImport(LibSsl)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    public static partial int OPENSSL_init_ssl(ulong opts, IntPtr settings);

    [LibraryImport(LibCrypto)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    public static partial ulong ERR_get_error();

    [LibraryImport(LibCrypto)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    public static partial IntPtr ERR_error_string(ulong e, byte* buf);

    public static string GetLastErrorString()
    {
        ulong error = ERR_get_error();
        if (error == 0) return "No error";
        byte* buffer = stackalloc byte[256];
        ERR_error_string(error, buffer);
        return Marshal.PtrToStringAnsi((IntPtr)buffer) ?? "Unknown error";
    }

    public static void Initialize()
    {
        OPENSSL_init_ssl(0, IntPtr.Zero);
    }
}
