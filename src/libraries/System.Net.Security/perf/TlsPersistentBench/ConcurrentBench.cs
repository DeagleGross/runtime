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
using BenchmarkDotNet.Toolchains.InProcess.Emit;

namespace TlsPersistentBench;

/// <summary>
/// BDN config for <see cref="ConcurrentRoundtripsBench"/>. Lighter iteration counts than the
/// global config because each invocation drives N concurrent connections × RequestCount
/// roundtrips — at ConnectionCount=200 and RequestCount=100 that is 20k roundtrips per
/// invocation. We only need enough samples to spot a multi-x throughput gap, not nanosecond
/// precision.
/// </summary>
internal sealed class ConcurrentConfig : ManualConfig
{
    public ConcurrentConfig()
    {
        AddJob(Job.Default
            .WithToolchain(InProcessEmitToolchain.Instance)
            .WithIterationCount(5)
            .WithWarmupCount(2)
            .WithInvocationCount(1)
            .WithUnrollFactor(1));
        WithOptions(ConfigOptions.DisableOptimizationsValidator);
    }
}

/// <summary>
/// Multi-connection variant of <see cref="PersistentRoundtripsBench"/>.
///
/// Drives <see cref="ConnectionCount"/> concurrent persistent TLS sessions through a SINGLE
/// shared <see cref="TlsContext"/> (TlsSession_Fd engine) or a single shared SSL_CTX*
/// (RawOpenSsl engine), and measures aggregate throughput.
///
/// Purpose: falsify the hypothesis that the 52x persistent-throughput gap observed in the
/// aspnetcore DirectSsl A/B (TlsSession vs OpenSslDirect) comes from TlsSession serializing
/// across connections. The single-connection bench cannot expose this — only a multi-connection
/// workload exercising the SAME TlsContext can.
///
/// Apples-to-apples by design: both engines run with the same harness shape (N dedicated server
/// threads, N async client tasks on the ThreadPool), the same shared server-side context, and
/// the same request size + count. If TlsSession_Fd shows a per-connection slowdown that
/// RawOpenSsl does not, the regression is inside System.Net.Security. If both scale equally,
/// the regression is in aspnetcore's epoll-pump wiring.
/// </summary>
[Config(typeof(ConcurrentConfig))]
[MemoryDiagnoser]
public class ConcurrentRoundtripsBench
{
    private const string ServerName = "tlsbench.local";

    // ---- Shared per-process state (allocated once in GlobalSetup, lives until GlobalCleanup)
    private X509Certificate2 _cert = null!;
    private SslServerAuthenticationOptions _serverOptions = null!;
    private SslClientAuthenticationOptions _clientOptions = null!;
    private TlsContext _ctxFd = null!;
    private IntPtr _opensslCtx;
    private string _certPemPath = null!;
    private string _keyPemPath = null!;
    private IPEndPoint _listenerEp = null!;
    private Socket _listener = null!;
    private byte[] _payload = null!;

    // ---- Per-iteration state (built in IterationSetup, torn down in IterationCleanup)
    private Socket[]? _clientSockets;
    private Socket[]? _serverSockets;
    private NetworkStream[]? _clientStreams;
    private SslStream[]? _clientSsls;
    private TlsSession?[]? _serverSessions;     // TlsSessionFd engine
    private IntPtr[]? _serverOpensslSsls;        // RawOpenSsl engine

    [Params(SslProtocols.Tls13)]
    public SslProtocols Protocol { get; set; }

    [Params(64)]
    public int PayloadSize { get; set; }

    [Params(100)]
    public int RequestCount { get; set; }

    // Sweep the concurrency axis. 1 is the control (= single-connection numbers we already have).
    // 200 matches the wrk -c200 used in the aspnetcore A/B.
    [Params(1, 8, 50, 200)]
    public int ConnectionCount { get; set; }

    public enum Engine { TlsSessionFd, RawOpenSsl }
    private Engine _engine;

    [GlobalSetup]
    public void GlobalSetup()
    {
        _cert = PersistentRoundtripsBench.CreateSelfSignedCert();

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

        // ONE shared TlsContext drives all N TlsSession instances; same design point as
        // aspnetcore's DirectSslTransportFactory where one TlsContext is reused per listener.
        _ctxFd = TlsContext.Create(_serverOptions);

        SetupRawOpenSsl();

        _listener = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        _listener.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        _listener.Listen(512); // backlog large enough for 200 concurrent inbound
        _listenerEp = (IPEndPoint)_listener.LocalEndPoint!;

        _payload = new byte[PayloadSize];
        new Random(42).NextBytes(_payload);
    }

    [GlobalCleanup]
    public void GlobalCleanup()
    {
        _listener?.Dispose();
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
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Linux)) return;

        try { OpenSslInterop.Initialize(); }
        catch (DllNotFoundException) { return; }

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

        OpenSslInterop.SetSessionCacheMode(_opensslCtx, OpenSslInterop.SSL_SESS_CACHE_SERVER);
        OpenSslInterop.SSL_CTX_set_timeout(_opensslCtx, 3600);
        OpenSslInterop.SetSessionCacheSize(_opensslCtx, 20000);
    }

    // ---- Benchmark methods ----

    [Benchmark]
    public Task TlsSessionFd_Concurrent() =>
        DriveConcurrentFdAsync();

    [Benchmark]
    public Task RawOpenSsl_Concurrent() =>
        DriveConcurrentRawAsync();

    // ---- Per-iteration setup/teardown ----

    [IterationSetup(Target = nameof(TlsSessionFd_Concurrent))]
    public void SetupFd()
    {
        _engine = Engine.TlsSessionFd;
        InteropProbe.Reset();
        BuildAllConnectionsAsync().GetAwaiter().GetResult();
    }

    [IterationSetup(Target = nameof(RawOpenSsl_Concurrent))]
    public void SetupRaw()
    {
        if (_opensslCtx == IntPtr.Zero)
            throw new PlatformNotSupportedException(
                "RawOpenSsl_Concurrent requires Linux with libssl.so.3 / libcrypto.so.3 installed.");
        _engine = Engine.RawOpenSsl;
        InteropProbe.Reset();
        BuildAllConnectionsAsync().GetAwaiter().GetResult();
    }

    [IterationCleanup]
    public void Cleanup()
    {
        int n = ConnectionCount;
        try
        {
            for (int i = 0; i < n; i++)
            {
                try { _clientSsls?[i]?.Dispose(); } catch { }
                try { _serverSessions?[i]?.Dispose(); } catch { }
                if (_serverOpensslSsls is { } arr && arr[i] != IntPtr.Zero)
                {
                    try { OpenSslInterop.SSL_shutdown(arr[i]); } catch { }
                    try { OpenSslInterop.SSL_free(arr[i]); } catch { }
                    arr[i] = IntPtr.Zero;
                }
                try { _clientStreams?[i]?.Dispose(); } catch { }
                try { _clientSockets?[i]?.Dispose(); } catch { }
                try { _serverSockets?[i]?.Dispose(); } catch { }
            }
        }
        finally
        {
            _clientSockets = null;
            _serverSockets = null;
            _clientStreams = null;
            _clientSsls = null;
            _serverSessions = null;
            _serverOpensslSsls = null;
        }
    }

    // ---- Connection construction ----
    //
    // Build N pairs sequentially. Each pair: connect socket, handshake (client SslStream +
    // server TlsSession-fd or raw SSL*). Sequential setup keeps the inbound accept-queue
    // ordering deterministic and avoids hammering the listener; the actual measured workload
    // is the concurrent I/O phase that follows.

    private async Task BuildAllConnectionsAsync()
    {
        int n = ConnectionCount;
        _clientSockets = new Socket[n];
        _serverSockets = new Socket[n];
        _clientStreams = new NetworkStream[n];
        _clientSsls = new SslStream[n];
        if (_engine == Engine.TlsSessionFd) _serverSessions = new TlsSession?[n];
        else _serverOpensslSsls = new IntPtr[n];

        for (int i = 0; i < n; i++)
        {
            (Socket cs, Socket ss) = await ConnectPairAsync();
            _clientSockets[i] = cs;
            _serverSockets[i] = ss;
            _clientStreams[i] = new NetworkStream(cs, ownsSocket: false);
            _clientSsls[i] = new SslStream(_clientStreams[i], leaveInnerStreamOpen: true);

            if (_engine == Engine.TlsSessionFd)
            {
                ss.Blocking = false;
                TlsSession session = TlsSession.Create(_ctxFd, ss.SafeHandle);
                _serverSessions![i] = session;
                Task cAuth = _clientSsls[i].AuthenticateAsClientAsync(_clientOptions);
                Task sHs = PersistentRoundtripsBench.RunOnDedicatedThreadAsync(
                    () => PersistentRoundtripsBench.DriveFdHandshake(session, ss));
                await Task.WhenAll(cAuth, sHs);
            }
            else
            {
                IntPtr ssl = OpenSslInterop.SSL_new(_opensslCtx);
                if (ssl == IntPtr.Zero)
                    throw new InvalidOperationException("SSL_new failed: " + OpenSslInterop.GetLastErrorString());
                int fd = (int)ss.Handle;
                if (OpenSslInterop.SSL_set_fd(ssl, fd) <= 0)
                    throw new InvalidOperationException("SSL_set_fd failed: " + OpenSslInterop.GetLastErrorString());
                OpenSslInterop.SSL_set_accept_state(ssl);
                _serverOpensslSsls![i] = ssl;
                Task cAuth = _clientSsls[i].AuthenticateAsClientAsync(_clientOptions);
                Task sHs = PersistentRoundtripsBench.RunOnDedicatedThreadAsync(
                    () => PersistentRoundtripsBench.DriveRawHandshake(ssl, ss));
                await Task.WhenAll(cAuth, sHs);
            }
        }
    }

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

    // ---- Concurrent drivers ----
    //
    // Fire all N client tasks and all N server worker threads at once; wait for all of them.
    // RPS-equivalent throughput = ConnectionCount * RequestCount / WallClock.

    private async Task DriveConcurrentFdAsync()
    {
        int n = ConnectionCount;
        var tasks = new Task[n * 2];
        for (int i = 0; i < n; i++)
        {
            int idx = i;
            tasks[i] = PersistentRoundtripsBench.ClientRoundtripsAsync(_clientSsls![idx], _payload, RequestCount);
            tasks[n + i] = PersistentRoundtripsBench.RunOnDedicatedThreadAsync(
                () => PersistentRoundtripsBench.FdServerRoundtrips(
                    _serverSessions![idx]!, _serverSockets![idx], RequestCount, PayloadSize));
        }
        await Task.WhenAll(tasks);
    }

    private async Task DriveConcurrentRawAsync()
    {
        int n = ConnectionCount;
        var tasks = new Task[n * 2];
        for (int i = 0; i < n; i++)
        {
            int idx = i;
            tasks[i] = PersistentRoundtripsBench.ClientRoundtripsAsync(_clientSsls![idx], _payload, RequestCount);
            tasks[n + i] = PersistentRoundtripsBench.RunOnDedicatedThreadAsync(
                () => PersistentRoundtripsBench.RawOpenSslServerRoundtrips(
                    _serverOpensslSsls![idx], _serverSockets![idx], RequestCount, PayloadSize));
        }
        await Task.WhenAll(tasks);
    }
}
