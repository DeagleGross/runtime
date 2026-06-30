// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Buffers;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Jobs;
using BenchmarkDotNet.Running;
using BenchmarkDotNet.Toolchains.InProcess.Emit;

using Microsoft.Win32.SafeHandles;

namespace TlsPersistentBench;

public static class Program
{
    public static void Main(string[] args)
    {
        // BenchmarkDotNet doesn't recognize the net11.0 moniker yet, so we run in-process.
        // For an I/O-bound persistent-roundtrip workload the difference vs out-of-process is negligible.
        IConfig config = DefaultConfig.Instance
            .AddJob(Job.Default
                .WithToolchain(InProcessEmitToolchain.Instance)
                // Persistent roundtrips are very fast (~us each). Cap iteration time so BDN
                // doesn't spin forever auto-scaling InvocationCount.
                .WithIterationCount(15)
                .WithWarmupCount(5)
                .WithInvocationCount(16)
                .WithUnrollFactor(1))
            .WithOptions(ConfigOptions.DisableOptimizationsValidator);

        BenchmarkSwitcher.FromAssembly(typeof(PersistentRoundtripsBench).Assembly).Run(args, config);

        // After the run, dump any accumulated counters (no-op unless DEBUG_INTEROP_COUNTERS).
        Console.WriteLine();
        Console.WriteLine(InteropProbe.Dump("Final accumulated (across all iterations)"));
    }
}

[MemoryDiagnoser]
public class PersistentRoundtripsBench
{
    private const int ScratchSize = 64 * 1024;
    private const string ServerName = "tlsbench.local";

    private static PersistentRoundtripsBench? s_current;

    private X509Certificate2 _cert = null!;
    private SslServerAuthenticationOptions _serverOptions = null!;
    private SslClientAuthenticationOptions _clientOptions = null!;
    private TlsContext _ctxBuffered = null!;
    private TlsContext _ctxFd = null!;
    private IntPtr _opensslCtx;          // raw OpenSSL SSL_CTX*, owned for the lifetime of GlobalSetup→Cleanup
    private string _certPemPath = null!; // temp file paths for SSL_CTX_use_certificate_file
    private string _keyPemPath = null!;
    private IPEndPoint _listenerEp = null!;
    private Socket _listener = null!;

    // Pre-built connection state — set up in IterationSetup, torn down in IterationCleanup.
    // The [Benchmark] body uses these and measures ONLY the persistent roundtrip cost.
    private Socket? _clientSocket;
    private Socket? _serverSocket;
    private NetworkStream? _clientStream;
    private NetworkStream? _serverStream;
    private SslStream? _clientSsl;
    private SslStream? _serverSsl;
    private TlsSession? _serverSession;
    private IntPtr _opensslSsl;          // raw OpenSSL SSL*, owned for the iteration only
    private byte[] _payload = null!;

    [Params(SslProtocols.Tls13)]
    public SslProtocols Protocol { get; set; }

    [Params(64, 4096)]
    public int PayloadSize { get; set; }

    [Params(10, 100)]
    public int RequestCount { get; set; }

    // Which engine drives the server side for this iteration.
    // Selected per-benchmark; the [Benchmark] methods set this before IterationSetup runs.
    public enum Engine { SslStream, TlsSessionBuffered, TlsSessionFd, RawOpenSsl }

    private Engine _engine;

    [GlobalSetup]
    public void GlobalSetup()
    {
        s_current = this;
        _cert = CreateSelfSignedCert();

        _serverOptions = new SslServerAuthenticationOptions
        {
            ServerCertificate = _cert,
            ClientCertificateRequired = false,
            EnabledSslProtocols = Protocol,
            AllowTlsResume = true,
        };
        _clientOptions = new SslClientAuthenticationOptions
        {
            TargetHost = ServerName,
            EnabledSslProtocols = Protocol,
            RemoteCertificateValidationCallback = static (_, _, _, _) => true,
            AllowTlsResume = true,
        };

        // TlsContext is allocated once and reused; SSL_CTX caching is the design point.
        _ctxBuffered = TlsContext.Create(_serverOptions);
        _ctxFd = TlsContext.Create(_serverOptions);

        // Raw OpenSSL context: build a peer SSL_CTX that mirrors the aspnetcore-side
        // OpenSslDirect engine — TLS_server_method + PEM cert/key on disk + session cache.
        // Done lazily so non-Linux runs (where libssl.so.3 won't load) don't crash setup
        // before we even reach the benchmarks that need it.
        SetupRawOpenSsl();

        _listener = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        _listener.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        _listener.Listen(128);
        _listenerEp = (IPEndPoint)_listener.LocalEndPoint!;

        _payload = new byte[PayloadSize];
        new Random(42).NextBytes(_payload);
    }

    [GlobalCleanup]
    public void GlobalCleanup()
    {
        _listener?.Dispose();
        _ctxBuffered?.Dispose();
        _ctxFd?.Dispose();
        _cert?.Dispose();

        if (_opensslCtx != IntPtr.Zero)
        {
            OpenSslInterop.SSL_CTX_free(_opensslCtx);
            _opensslCtx = IntPtr.Zero;
        }
        try { if (!string.IsNullOrEmpty(_certPemPath) && File.Exists(_certPemPath)) File.Delete(_certPemPath); } catch { }
        try { if (!string.IsNullOrEmpty(_keyPemPath) && File.Exists(_keyPemPath)) File.Delete(_keyPemPath); } catch { }
    }

    private void SetupRawOpenSsl()
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
        {
            // Library names (libssl.so.3) are Linux-specific. Skip — the RawOpenSsl bench
            // will throw PlatformNotSupportedException, which BDN surfaces clearly.
            return;
        }

        try
        {
            OpenSslInterop.Initialize();
        }
        catch (DllNotFoundException)
        {
            // OpenSSL 3.x not installed on this host. Same behaviour as Windows path.
            return;
        }

        // Export the self-signed cert + key to temp files (the SSL_CTX_use_*_file APIs
        // need on-disk PEM; using BIO_new_mem_buf + PEM_read_bio_X509 instead would be
        // strictly equivalent but adds 4 more P/Invokes for no benefit at setup time).
        _certPemPath = Path.GetTempFileName();
        _keyPemPath = Path.GetTempFileName();
        File.WriteAllText(_certPemPath, _cert.ExportCertificatePem());
        using (RSA? rsa = _cert.GetRSAPrivateKey())
        {
            if (rsa is null) throw new InvalidOperationException("cert has no RSA private key");
            File.WriteAllText(_keyPemPath, rsa.ExportRSAPrivateKeyPem());
        }

        IntPtr method = OpenSslInterop.TLS_server_method();
        if (method == IntPtr.Zero) throw new InvalidOperationException("TLS_server_method failed");
        _opensslCtx = OpenSslInterop.SSL_CTX_new(method);
        if (_opensslCtx == IntPtr.Zero) throw new InvalidOperationException("SSL_CTX_new failed: " + OpenSslInterop.GetLastErrorString());

        if (OpenSslInterop.SSL_CTX_use_certificate_file(_opensslCtx, _certPemPath, OpenSslInterop.SSL_FILETYPE_PEM) <= 0)
            throw new InvalidOperationException("SSL_CTX_use_certificate_file: " + OpenSslInterop.GetLastErrorString());
        if (OpenSslInterop.SSL_CTX_use_PrivateKey_file(_opensslCtx, _keyPemPath, OpenSslInterop.SSL_FILETYPE_PEM) <= 0)
            throw new InvalidOperationException("SSL_CTX_use_PrivateKey_file: " + OpenSslInterop.GetLastErrorString());
        if (OpenSslInterop.SSL_CTX_check_private_key(_opensslCtx) <= 0)
            throw new InvalidOperationException("SSL_CTX_check_private_key: " + OpenSslInterop.GetLastErrorString());

        // Match aspnetcore-side OpenSslDirect: server-side session cache, 1h timeout, 20000 entries.
        OpenSslInterop.SetSessionCacheMode(_opensslCtx, OpenSslInterop.SSL_SESS_CACHE_SERVER);
        OpenSslInterop.SSL_CTX_set_timeout(_opensslCtx, 3600);
        OpenSslInterop.SetSessionCacheSize(_opensslCtx, 20000);
    }

    // ---- Benchmark methods ----
    // Each method picks an engine, then BDN re-runs IterationSetup → Benchmark → IterationCleanup
    // for that engine's row in the report.

    [Benchmark(Baseline = true)]
    public async Task SslStream_Roundtrips()
    {
        // Engine was set in IterationSetup. Just drive the roundtrips.
        await DriveSslStreamRoundtripsAsync(_clientSsl!, _serverSsl!, RequestCount, PayloadSize);
    }

    [Benchmark]
    public async Task TlsSession_Buffered_Roundtrips()
    {
        await DriveBufferedRoundtripsAsync(_clientSsl!, _serverSession!, _serverSocket!, RequestCount, PayloadSize);
    }

    [Benchmark]
    public async Task TlsSession_Fd_Roundtrips()
    {
        await DriveFdRoundtripsAsync(_clientSsl!, _serverSession!, _serverSocket!, RequestCount, PayloadSize);
    }

    [Benchmark]
    public async Task RawOpenSsl_Roundtrips()
    {
        await DriveRawOpenSslRoundtripsAsync(_clientSsl!, _opensslSsl, _serverSocket!, RequestCount, PayloadSize);
    }

    // ---- IterationSetup / IterationCleanup: one for each benchmark target ----
    // BDN supports [IterationSetup(Target = nameof(MethodName))] for per-method setup.

    [IterationSetup(Target = nameof(SslStream_Roundtrips))]
    public void SetupSslStream()
    {
        _engine = Engine.SslStream;
        InteropProbe.Reset();
        BuildConnectionAsync().GetAwaiter().GetResult();
    }

    [IterationSetup(Target = nameof(TlsSession_Buffered_Roundtrips))]
    public void SetupBuffered()
    {
        _engine = Engine.TlsSessionBuffered;
        InteropProbe.Reset();
        BuildConnectionAsync().GetAwaiter().GetResult();
    }

    [IterationSetup(Target = nameof(TlsSession_Fd_Roundtrips))]
    public void SetupFd()
    {
        _engine = Engine.TlsSessionFd;
        InteropProbe.Reset();
        BuildConnectionAsync().GetAwaiter().GetResult();
    }

    [IterationSetup(Target = nameof(RawOpenSsl_Roundtrips))]
    public void SetupRawOpenSslConn()
    {
        if (_opensslCtx == IntPtr.Zero)
            throw new PlatformNotSupportedException(
                "RawOpenSsl_Roundtrips requires Linux with libssl.so.3 / libcrypto.so.3 installed.");
        _engine = Engine.RawOpenSsl;
        InteropProbe.Reset();
        BuildConnectionAsync().GetAwaiter().GetResult();
    }

    [IterationCleanup]
    public void CleanupIteration()
    {
        // Dump probe BEFORE tearing the connection down so per-iteration counts are visible.
        // BDN swallows stdout from IterationCleanup unless --logBuildOutput is set; that's fine,
        // we also print a summary at process exit in Program.Main.
        try
        {
            _clientSsl?.Dispose();
            _serverSsl?.Dispose();
            _serverSession?.Dispose();
            if (_opensslSsl != IntPtr.Zero)
            {
                OpenSslInterop.SSL_shutdown(_opensslSsl);
                OpenSslInterop.SSL_free(_opensslSsl);
                _opensslSsl = IntPtr.Zero;
            }
            _clientStream?.Dispose();
            _serverStream?.Dispose();
            _clientSocket?.Dispose();
            _serverSocket?.Dispose();
        }
        catch { /* ignore teardown noise */ }
        finally
        {
            _clientSsl = null;
            _serverSsl = null;
            _serverSession = null;
            _clientStream = null;
            _serverStream = null;
            _clientSocket = null;
            _serverSocket = null;
        }
    }

    private async Task BuildConnectionAsync()
    {
        (Socket cs, Socket ss) = await ConnectPairAsync();
        _clientSocket = cs;
        _serverSocket = ss;

        _clientStream = new NetworkStream(cs, ownsSocket: false);
        _clientSsl = new SslStream(_clientStream, leaveInnerStreamOpen: true);

        switch (_engine)
        {
            case Engine.SslStream:
                _serverStream = new NetworkStream(ss, ownsSocket: false);
                _serverSsl = new SslStream(_serverStream, leaveInnerStreamOpen: true);
                Task c1 = _clientSsl.AuthenticateAsClientAsync(_clientOptions);
                Task s1 = _serverSsl.AuthenticateAsServerAsync(_serverOptions);
                await Task.WhenAll(c1, s1);
                break;

            case Engine.TlsSessionBuffered:
                ss.Blocking = false;
                _serverSession = TlsSession.Create(_ctxBuffered);
                Task c2 = _clientSsl.AuthenticateAsClientAsync(_clientOptions);
                Task s2 = RunOnDedicatedThreadAsync(() =>
                {
                    DriveBufferedHandshake(_serverSession, ss);
                    // After handshake, ensure any post-handshake records (TLS 1.3 NewSessionTicket)
                    // are flushed so they don't get measured as part of the first roundtrip.
                    DrainPending(_serverSession, ss, new byte[ScratchSize]);
                });
                await Task.WhenAll(c2, s2);
                break;

            case Engine.TlsSessionFd:
                ss.Blocking = false;
                _serverSession = TlsSession.Create(_ctxFd, ss.SafeHandle);
                Task c3 = _clientSsl.AuthenticateAsClientAsync(_clientOptions);
                Task s3 = RunOnDedicatedThreadAsync(() => DriveFdHandshake(_serverSession, ss));
                await Task.WhenAll(c3, s3);
                break;

            case Engine.RawOpenSsl:
                // Blocking socket on the server side — SSL_do_handshake/SSL_read/SSL_write
                // will block on the underlying recv/send themselves, matching the
                // single-threaded direct-SSL pattern (no epoll, no awaitable).
                _opensslSsl = OpenSslInterop.SSL_new(_opensslCtx);
                if (_opensslSsl == IntPtr.Zero)
                    throw new InvalidOperationException("SSL_new failed: " + OpenSslInterop.GetLastErrorString());
                int fd = (int)ss.Handle;
                if (OpenSslInterop.SSL_set_fd(_opensslSsl, fd) <= 0)
                    throw new InvalidOperationException("SSL_set_fd failed: " + OpenSslInterop.GetLastErrorString());
                OpenSslInterop.SSL_set_accept_state(_opensslSsl);
                Task c4 = _clientSsl.AuthenticateAsClientAsync(_clientOptions);
                Task s4 = RunOnDedicatedThreadAsync(() => DriveRawHandshake(_opensslSsl, ss));
                await Task.WhenAll(c4, s4);
                break;
        }
    }

    // -------- Persistent-roundtrip drivers (the actual measured workload) --------

    /// <summary>
    /// Baseline: SslStream on both ends, N request/response roundtrips through a single connection.
    /// </summary>
    private static async Task DriveSslStreamRoundtripsAsync(SslStream client, SslStream server, int count, int size)
    {
        byte[] tx = new byte[size];
        byte[] rx = new byte[size];
        for (int i = 0; i < count; i++)
        {
            // Client → server
            Task cw = TimedWriteAsync(client, tx, InteropProbe.SslStreamWriteAsync);
            Task<int> sr = TimedReadFullAsync(server, rx, InteropProbe.SslStreamReadAsync);
            await Task.WhenAll(cw, sr);
            if (sr.Result != size) throw new IOException($"sslstream server short read {sr.Result}/{size}");

            // Server → client (echo)
            Task sw = TimedWriteAsync(server, rx, InteropProbe.SslStreamWriteAsync);
            Task<int> cr = TimedReadFullAsync(client, tx, InteropProbe.SslStreamReadAsync);
            await Task.WhenAll(sw, cr);
            if (cr.Result != size) throw new IOException($"sslstream client short read {cr.Result}/{size}");
        }
    }

    private static async Task TimedWriteAsync(SslStream s, byte[] buf, InteropProbe.Bucket bucket)
    {
        long t = InteropProbe.Start();
        await s.WriteAsync(buf);
        InteropProbe.Stop(bucket, t, bytesIn: 0, bytesOut: buf.Length);
    }

    private static async Task<int> TimedReadFullAsync(SslStream s, byte[] buf, InteropProbe.Bucket bucket)
    {
        int total = 0;
        while (total < buf.Length)
        {
            long t = InteropProbe.Start();
            int n = await s.ReadAsync(buf.AsMemory(total, buf.Length - total));
            InteropProbe.Stop(bucket, t, bytesIn: n, bytesOut: 0);
            if (n == 0) break;
            total += n;
        }
        return total;
    }

    /// <summary>
    /// TlsSession buffered: client is SslStream, server uses ProcessHandshake/Encrypt/Decrypt
    /// + DrainPendingOutput against a non-blocking socket.
    /// </summary>
    private static async Task DriveBufferedRoundtripsAsync(SslStream client, TlsSession session, Socket socket, int count, int size)
    {
        byte[] tx = new byte[size];
        Task clientTask = ClientRoundtripsAsync(client, tx, count);
        Task serverTask = RunOnDedicatedThreadAsync(() => BufferedServerRoundtrips(session, socket, count, size));
        await Task.WhenAll(clientTask, serverTask);
    }

    internal static async Task ClientRoundtripsAsync(SslStream client, byte[] tx, int count)
    {
        byte[] rx = new byte[tx.Length];
        for (int i = 0; i < count; i++)
        {
            await client.WriteAsync(tx);
            int total = 0;
            while (total < rx.Length)
            {
                int n = await client.ReadAsync(rx.AsMemory(total));
                if (n == 0) throw new IOException("client eof");
                total += n;
            }
        }
    }

    private static void BufferedServerRoundtrips(TlsSession session, Socket socket, int count, int size)
    {
        byte[] netIn = ArrayPool<byte>.Shared.Rent(ScratchSize);
        byte[] netOut = ArrayPool<byte>.Shared.Rent(ScratchSize);
        byte[] plain = ArrayPool<byte>.Shared.Rent(size);
        try
        {
            int inUsed = 0;
            for (int i = 0; i < count; i++)
            {
                // ---- Decrypt one full request of `size` bytes ----
                int decryptedTotal = 0;
                while (decryptedTotal < size)
                {
                    long t = InteropProbe.Start();
                    TlsOperationStatus s = session.Decrypt(
                        netIn.AsSpan(0, inUsed),
                        plain.AsSpan(decryptedTotal, size - decryptedTotal),
                        out int consumed, out int produced);
                    InteropProbe.Stop(InteropProbe.SessionDecrypt, t, bytesIn: consumed, bytesOut: produced);

                    if (consumed > 0)
                    {
                        if (consumed < inUsed) Buffer.BlockCopy(netIn, consumed, netIn, 0, inUsed - consumed);
                        inUsed -= consumed;
                    }
                    if (produced > 0)
                    {
                        decryptedTotal += produced;
                        continue;
                    }
                    switch (s)
                    {
                        case TlsOperationStatus.WantRead:
                            inUsed += NonBlockingReceiveSome(socket, netIn, inUsed);
                            continue;
                        case TlsOperationStatus.WantWrite:
                            DrainPending(session, socket, netOut);
                            continue;
                        case TlsOperationStatus.Complete:
                            // Possible when Decrypt drained PAL-buffered plaintext fully with no input.
                            continue;
                        case TlsOperationStatus.Closed:
                            throw new IOException("closed during request decrypt");
                    }
                }

                // ---- Encrypt the response (echo back the same bytes) ----
                int sent = 0;
                while (sent < size)
                {
                    long t = InteropProbe.Start();
                    TlsOperationStatus s = session.Encrypt(plain.AsSpan(sent, size - sent), netOut, out int consumed, out int produced);
                    InteropProbe.Stop(InteropProbe.SessionEncrypt, t, bytesIn: consumed, bytesOut: produced);

                    sent += consumed;
                    if (produced > 0) NonBlockingSendAll(socket, netOut, 0, produced);
                    if (s == TlsOperationStatus.WantWrite) DrainPending(session, socket, netOut);
                }
                // Make sure all ciphertext is flushed before the next roundtrip starts;
                // otherwise the client's blocking SslStream.ReadAsync stalls and we measure
                // socket buffering instead of crypto.
                DrainPending(session, socket, netOut);
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(plain);
            ArrayPool<byte>.Shared.Return(netOut);
            ArrayPool<byte>.Shared.Return(netIn);
        }
    }

    /// <summary>
    /// TlsSession fd-mode: client is SslStream, server uses Session.Read/Write directly.
    /// </summary>
    private static async Task DriveFdRoundtripsAsync(SslStream client, TlsSession session, Socket socket, int count, int size)
    {
        byte[] tx = new byte[size];
        Task clientTask = ClientRoundtripsAsync(client, tx, count);
        Task serverTask = RunOnDedicatedThreadAsync(() => FdServerRoundtrips(session, socket, count, size));
        await Task.WhenAll(clientTask, serverTask);
    }

    internal static void FdServerRoundtrips(TlsSession session, Socket socket, int count, int size)
    {
        byte[] buf = ArrayPool<byte>.Shared.Rent(size);
        try
        {
            for (int i = 0; i < count; i++)
            {
                // Read `size` bytes
                int got = 0;
                while (got < size)
                {
                    long t = InteropProbe.Start();
                    TlsOperationStatus s = session.Read(buf.AsSpan(got, size - got), out int produced);
                    InteropProbe.Stop(InteropProbe.SessionRead, t, bytesIn: produced, bytesOut: 0);

                    if (produced > 0) { got += produced; continue; }
                    switch (s)
                    {
                        case TlsOperationStatus.WantRead:
                            long tp = InteropProbe.Start();
                            socket.Poll(-1, SelectMode.SelectRead);
                            InteropProbe.Stop(InteropProbe.SocketPollRead, tp);
                            continue;
                        case TlsOperationStatus.WantWrite:
                            long tpw = InteropProbe.Start();
                            socket.Poll(-1, SelectMode.SelectWrite);
                            InteropProbe.Stop(InteropProbe.SocketPollWrite, tpw);
                            continue;
                        default:
                            throw new IOException($"fd read status {s}");
                    }
                }
                // Write `size` bytes back
                int sent = 0;
                while (sent < size)
                {
                    long t = InteropProbe.Start();
                    TlsOperationStatus s = session.Write(buf.AsSpan(sent, size - sent), out int consumed);
                    InteropProbe.Stop(InteropProbe.SessionWrite, t, bytesIn: 0, bytesOut: consumed);

                    sent += consumed;
                    if (sent == size) break;
                    switch (s)
                    {
                        case TlsOperationStatus.WantRead:
                            long tp = InteropProbe.Start();
                            socket.Poll(-1, SelectMode.SelectRead);
                            InteropProbe.Stop(InteropProbe.SocketPollRead, tp);
                            continue;
                        case TlsOperationStatus.WantWrite:
                            long tpw = InteropProbe.Start();
                            socket.Poll(-1, SelectMode.SelectWrite);
                            InteropProbe.Stop(InteropProbe.SocketPollWrite, tpw);
                            continue;
                        default:
                            throw new IOException($"fd write status {s}");
                    }
                }
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buf);
        }
    }

    // -------- Raw OpenSSL P/Invoke roundtrips (apples-to-apples with aspnetcore OpenSslDirect) --------

    private static async Task DriveRawOpenSslRoundtripsAsync(SslStream client, IntPtr ssl, Socket socket, int count, int size)
    {
        byte[] tx = new byte[size];
        Task clientTask = ClientRoundtripsAsync(client, tx, count);
        Task serverTask = RunOnDedicatedThreadAsync(() => RawOpenSslServerRoundtrips(ssl, socket, count, size));
        await Task.WhenAll(clientTask, serverTask);
    }

    internal static unsafe void RawOpenSslServerRoundtrips(IntPtr ssl, Socket socket, int count, int size)
    {
        byte[] buf = ArrayPool<byte>.Shared.Rent(size);
        try
        {
            for (int i = 0; i < count; i++)
            {
                // Read `size` bytes via SSL_read (blocking; matches the aspnetcore OpenSslDirect pattern
                // when the pump has already detected EPOLLIN and is calling SSL_read once).
                int got = 0;
                while (got < size)
                {
                    int n;
                    long t = InteropProbe.Start();
                    fixed (byte* p = &buf[got])
                    {
                        n = OpenSslInterop.SSL_read(ssl, p, size - got);
                    }
                    InteropProbe.Stop(InteropProbe.OpenSslRead, t, bytesIn: n > 0 ? n : 0, bytesOut: 0);

                    if (n > 0) { got += n; continue; }
                    int err = OpenSslInterop.SSL_get_error(ssl, n);
                    switch (err)
                    {
                        case OpenSslInterop.SSL_ERROR_WANT_READ:
                            long tp = InteropProbe.Start();
                            socket.Poll(-1, SelectMode.SelectRead);
                            InteropProbe.Stop(InteropProbe.SocketPollRead, tp);
                            continue;
                        case OpenSslInterop.SSL_ERROR_WANT_WRITE:
                            long tpw = InteropProbe.Start();
                            socket.Poll(-1, SelectMode.SelectWrite);
                            InteropProbe.Stop(InteropProbe.SocketPollWrite, tpw);
                            continue;
                        default:
                            throw new IOException($"SSL_read err={err}: {OpenSslInterop.GetLastErrorString()}");
                    }
                }

                // Write `size` bytes via SSL_write.
                int sent = 0;
                while (sent < size)
                {
                    int n;
                    long t = InteropProbe.Start();
                    fixed (byte* p = &buf[sent])
                    {
                        n = OpenSslInterop.SSL_write(ssl, p, size - sent);
                    }
                    InteropProbe.Stop(InteropProbe.OpenSslWrite, t, bytesIn: 0, bytesOut: n > 0 ? n : 0);

                    if (n > 0) { sent += n; continue; }
                    int err = OpenSslInterop.SSL_get_error(ssl, n);
                    switch (err)
                    {
                        case OpenSslInterop.SSL_ERROR_WANT_READ:
                            long tp = InteropProbe.Start();
                            socket.Poll(-1, SelectMode.SelectRead);
                            InteropProbe.Stop(InteropProbe.SocketPollRead, tp);
                            continue;
                        case OpenSslInterop.SSL_ERROR_WANT_WRITE:
                            long tpw = InteropProbe.Start();
                            socket.Poll(-1, SelectMode.SelectWrite);
                            InteropProbe.Stop(InteropProbe.SocketPollWrite, tpw);
                            continue;
                        default:
                            throw new IOException($"SSL_write err={err}: {OpenSslInterop.GetLastErrorString()}");
                    }
                }
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buf);
        }
    }

    internal static void DriveRawHandshake(IntPtr ssl, Socket socket)
    {
        while (true)
        {
            long t = InteropProbe.Start();
            int rc = OpenSslInterop.SSL_do_handshake(ssl);
            InteropProbe.Stop(InteropProbe.OpenSslDoHandshake, t);

            if (rc == 1) return; // handshake complete
            int err = OpenSslInterop.SSL_get_error(ssl, rc);
            switch (err)
            {
                case OpenSslInterop.SSL_ERROR_WANT_READ:
                    long tp = InteropProbe.Start();
                    socket.Poll(-1, SelectMode.SelectRead);
                    InteropProbe.Stop(InteropProbe.SocketPollRead, tp);
                    continue;
                case OpenSslInterop.SSL_ERROR_WANT_WRITE:
                    long tpw = InteropProbe.Start();
                    socket.Poll(-1, SelectMode.SelectWrite);
                    InteropProbe.Stop(InteropProbe.SocketPollWrite, tpw);
                    continue;
                default:
                    throw new IOException($"SSL_do_handshake err={err}: {OpenSslInterop.GetLastErrorString()}");
            }
        }
    }

    // -------- Reusable helpers (cribbed from TlsHandshakeBench, instrumented) --------

    private async ValueTask<(Socket Client, Socket Server)> ConnectPairAsync()
    {
        var client = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        client.NoDelay = true;
        Task<Socket> acceptTask = _listener.AcceptAsync();
        await client.ConnectAsync(_listenerEp);
        Socket server = await acceptTask;
        server.NoDelay = true;
        return (client, server);
    }

    internal static Task RunOnDedicatedThreadAsync(Action action)
    {
        var tcs = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var t = new Thread(() =>
        {
            try { action(); tcs.SetResult(); }
            catch (Exception ex) { tcs.SetException(ex); }
        }) { IsBackground = true };
        t.Start();
        return tcs.Task;
    }

    private static void DriveBufferedHandshake(TlsSession session, Socket socket)
    {
        byte[] netIn = ArrayPool<byte>.Shared.Rent(ScratchSize);
        byte[] netOut = ArrayPool<byte>.Shared.Rent(ScratchSize);
        int inUsed = 0;
        try
        {
            while (!session.IsHandshakeComplete)
            {
                long t = InteropProbe.Start();
                TlsOperationStatus status = session.ProcessHandshake(
                    netIn.AsSpan(0, inUsed), netOut, out int consumed, out int produced);
                InteropProbe.Stop(InteropProbe.SessionProcessHandshake, t, bytesIn: consumed, bytesOut: produced);

                if (consumed > 0)
                {
                    if (consumed < inUsed) Buffer.BlockCopy(netIn, consumed, netIn, 0, inUsed - consumed);
                    inUsed -= consumed;
                }
                if (produced > 0) NonBlockingSendAll(socket, netOut, 0, produced);

                switch (status)
                {
                    case TlsOperationStatus.Complete: continue;
                    case TlsOperationStatus.NeedsCertificateValidation:
                        session.AcceptWithDefaultValidation();
                        continue;
                    case TlsOperationStatus.WantWrite: DrainPending(session, socket, netOut); continue;
                    case TlsOperationStatus.WantRead:
                        inUsed += NonBlockingReceiveSome(socket, netIn, inUsed);
                        continue;
                    case TlsOperationStatus.Closed: throw new IOException("Closed in handshake.");
                }
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(netOut);
            ArrayPool<byte>.Shared.Return(netIn);
        }
    }

    internal static void DriveFdHandshake(TlsSession session, Socket socket)
    {
        while (true)
        {
            long t = InteropProbe.Start();
            TlsOperationStatus s = session.Handshake();
            InteropProbe.Stop(InteropProbe.SessionHandshake, t);

            switch (s)
            {
                case TlsOperationStatus.Complete: return;
                case TlsOperationStatus.NeedsCertificateValidation:
                    session.AcceptWithDefaultValidation();
                    continue;
                case TlsOperationStatus.WantRead:
                    long tp = InteropProbe.Start();
                    socket.Poll(-1, SelectMode.SelectRead);
                    InteropProbe.Stop(InteropProbe.SocketPollRead, tp);
                    continue;
                case TlsOperationStatus.WantWrite:
                    long tpw = InteropProbe.Start();
                    socket.Poll(-1, SelectMode.SelectWrite);
                    InteropProbe.Stop(InteropProbe.SocketPollWrite, tpw);
                    continue;
                default: throw new IOException($"Unexpected handshake status: {s}");
            }
        }
    }

    private static void DrainPending(TlsSession session, Socket socket, byte[] scratch)
    {
        while (session.HasPendingOutput)
        {
            long t = InteropProbe.Start();
            session.DrainPendingOutput(scratch, out int n);
            InteropProbe.Stop(InteropProbe.SessionDrainPendingOutput, t, bytesIn: 0, bytesOut: n);
            if (n > 0) NonBlockingSendAll(socket, scratch, 0, n);
        }
    }

    private static void NonBlockingSendAll(Socket socket, byte[] buffer, int offset, int count)
    {
        while (count > 0)
        {
            try
            {
                long t = InteropProbe.Start();
                int n = socket.Send(buffer, offset, count, SocketFlags.None);
                InteropProbe.Stop(InteropProbe.SocketSend, t, bytesIn: 0, bytesOut: n);
                offset += n; count -= n;
            }
            catch (SocketException ex) when (ex.SocketErrorCode == SocketError.WouldBlock)
            {
                long t = InteropProbe.Start();
                socket.Poll(-1, SelectMode.SelectWrite);
                InteropProbe.Stop(InteropProbe.SocketPollWrite, t);
            }
        }
    }

    private static int NonBlockingReceiveSome(Socket socket, byte[] buffer, int offset)
    {
        while (true)
        {
            try
            {
                long t = InteropProbe.Start();
                int n = socket.Receive(buffer, offset, buffer.Length - offset, SocketFlags.None);
                InteropProbe.Stop(InteropProbe.SocketReceive, t, bytesIn: n, bytesOut: 0);
                if (n == 0) throw new IOException("Unexpected EOF.");
                return n;
            }
            catch (SocketException ex) when (ex.SocketErrorCode == SocketError.WouldBlock)
            {
                long t = InteropProbe.Start();
                socket.Poll(-1, SelectMode.SelectRead);
                InteropProbe.Stop(InteropProbe.SocketPollRead, t);
            }
        }
    }

    internal static X509Certificate2 CreateSelfSignedCert()
    {
        using RSA rsa = RSA.Create(2048);
        var req = new CertificateRequest(
            $"CN={ServerName}",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        var san = new SubjectAlternativeNameBuilder();
        san.AddDnsName(ServerName);
        req.CertificateExtensions.Add(san.Build());
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        req.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, false));
        req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") }, false));
        DateTimeOffset now = DateTimeOffset.UtcNow;
        return req.CreateSelfSigned(now.AddMinutes(-5), now.AddYears(1));
    }
}
