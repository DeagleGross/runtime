// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

namespace TlsPersistentBench;

/// <summary>
/// Reproduction of the aspnetcore Kestrel DirectSsl pump pattern in isolation.
///
/// Runs ONE server thread that owns ONE epoll fd and dispatches N accepted TLS
/// connections. For each ready fd it does SSL_read + echo SSL_write. Counts
/// per-connection reads over a fixed wall-clock window.
///
/// Two engines:
///   Raw      — SSL_new + SSL_set_fd + raw SSL_read/SSL_write (mirrors OSD)
///   TlsSess  — TlsSession.Create(ctx, safeSocket) + DangerousGetHandle + raw
///              SSL_read/SSL_write on the extracted pointer (mirrors Hybrid-E)
///
/// If the TlsSess variant shows unfair per-connection distribution and Raw
/// shows fair, we have isolated the bug to a runtime-level side-effect of
/// keeping TlsSession alive per connection. Otherwise the bug is elsewhere.
/// </summary>
internal static partial class EpollFairnessBench
{
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    private struct EpollEvent
    {
        public uint Events;
        public int Fd;
        public int _pad;
    }

    private const int EPOLL_CLOEXEC = 0x80000;
    private const int EPOLL_CTL_ADD = 1;
    private const uint EPOLLIN = 0x001;
    private const uint EPOLLRDHUP = 0x2000;

    [LibraryImport("libc", EntryPoint = "epoll_create1", SetLastError = true)]
    private static partial int epoll_create1(int flags);

    [LibraryImport("libc", EntryPoint = "epoll_ctl", SetLastError = true)]
    private static partial int epoll_ctl(int epfd, int op, int fd, ref EpollEvent ev);

    [LibraryImport("libc", EntryPoint = "epoll_wait", SetLastError = true)]
    private static partial int epoll_wait(int epfd, [Out] EpollEvent[] events, int maxevents, int timeout);

    [LibraryImport("libc", EntryPoint = "close")]
    private static partial int close(int fd);

    public static void Run(int connectionCount, int durationSec, string engine)
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
        {
            Console.Error.WriteLine("EpollFairnessBench is Linux-only.");
            return;
        }

        Console.WriteLine($"[EpollFairnessBench] engine={engine} conns={connectionCount} durationSec={durationSec}");

        OpenSslInterop.Initialize();

        using var cert = PersistentRoundtripsBench.CreateSelfSignedCert();
        var serverOptions = new SslServerAuthenticationOptions
        {
            ServerCertificate = cert,
            ClientCertificateRequired = false,
            EnabledSslProtocols = SslProtocols.Tls13,
            AllowTlsResume = true,
        };
        var clientOptions = new SslClientAuthenticationOptions
        {
            TargetHost = "tlsbench.local",
            EnabledSslProtocols = SslProtocols.Tls13,
            RemoteCertificateValidationCallback = static (_, _, _, _) => true,
            AllowTlsResume = true,
        };

        using TlsContext tlsCtx = TlsContext.Create(serverOptions);
        IntPtr opensslCtx = engine.Equals("Raw", StringComparison.OrdinalIgnoreCase)
            ? SetupRawSslCtx(cert)
            : IntPtr.Zero;

        try
        {
            using var listener = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            listener.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            listener.Listen(Math.Max(512, connectionCount * 2));
            var listenerEp = (IPEndPoint)listener.LocalEndPoint!;

            var pairs = new ConnPair[connectionCount];
            for (int i = 0; i < connectionCount; i++)
            {
                pairs[i] = BuildPair(listener, listenerEp, tlsCtx, opensslCtx, clientOptions, engine);
            }
            for (int i = 0; i < connectionCount; i++)
            {
                Console.WriteLine($"[EpollFairnessBench]   conn[{i}] serverFd={pairs[i].ServerFd}");
            }

            var stop = new CancellationTokenSource();
            long[] readCounts = new long[connectionCount];
            long[] readBytes = new long[connectionCount];
            long[] wantReadCounts = new long[connectionCount];

            bool singleReadPerWake = Environment.GetEnvironmentVariable("SINGLE_READ") == "1";
            bool useTlsSessionApi = Environment.GetEnvironmentVariable("USE_SESSION_API") == "1";
            Console.WriteLine($"[EpollFairnessBench] singleReadPerWake={singleReadPerWake} useTlsSessionApi={useTlsSessionApi}");
            var pumpThread = new Thread(() =>
                PumpLoop(pairs, readCounts, readBytes, wantReadCounts, stop.Token, singleReadPerWake, useTlsSessionApi))
            {
                Name = "epoll-pump",
                IsBackground = true,
            };
            pumpThread.Start();

            byte[] payload = new byte[64];
            new Random(42).NextBytes(payload);
            var clientStops = new CancellationTokenSource();
            Task[] clientTasks = new Task[connectionCount];
            for (int i = 0; i < connectionCount; i++)
            {
                int idx = i;
                clientTasks[i] = Task.Run(() => ClientLoop(pairs[idx].ClientSsl, payload, clientStops.Token));
            }

            Thread.Sleep(TimeSpan.FromSeconds(durationSec));
            clientStops.Cancel();
            try { Task.WaitAll(clientTasks, TimeSpan.FromSeconds(5)); } catch { }
            stop.Cancel();
            pumpThread.Join(TimeSpan.FromSeconds(2));

            long min = long.MaxValue, max = 0, total = 0;
            for (int i = 0; i < connectionCount; i++)
            {
                long c = readCounts[i];
                if (c < min) min = c;
                if (c > max) max = c;
                total += c;
            }
            Console.WriteLine();
            Console.WriteLine($"[EpollFairnessBench] ===== RESULT engine={engine} conns={connectionCount} durationSec={durationSec} =====");
            for (int i = 0; i < connectionCount; i++)
            {
                Console.WriteLine($"[EpollFairnessBench]   conn[{i}] fd={pairs[i].ServerFd} reads={readCounts[i]} bytes={readBytes[i]} wantRead={wantReadCounts[i]}");
            }
            double ratio = min > 0 ? (double)max / min : double.PositiveInfinity;
            Console.WriteLine($"[EpollFairnessBench] SUMMARY min={min} max={max} total={total} ratio={ratio:F2}x avgReadsPerSec={(double)total / durationSec:N0}");

            foreach (var p in pairs) p.Dispose();
        }
        finally
        {
            if (opensslCtx != IntPtr.Zero) OpenSslInterop.SSL_CTX_free(opensslCtx);
        }
    }

    private static IntPtr SetupRawSslCtx(X509Certificate2 cert)
    {
        string certPem = Path.GetTempFileName();
        string keyPem = Path.GetTempFileName();
        File.WriteAllText(certPem, cert.ExportCertificatePem());
        using (var rsa = cert.GetRSAPrivateKey()!)
        {
            File.WriteAllText(keyPem, rsa.ExportRSAPrivateKeyPem());
        }
        try
        {
            IntPtr method = OpenSslInterop.TLS_server_method();
            IntPtr ctx = OpenSslInterop.SSL_CTX_new(method);
            if (ctx == IntPtr.Zero) throw new InvalidOperationException("SSL_CTX_new: " + OpenSslInterop.GetLastErrorString());
            if (OpenSslInterop.SSL_CTX_use_certificate_file(ctx, certPem, OpenSslInterop.SSL_FILETYPE_PEM) <= 0)
                throw new InvalidOperationException("SSL_CTX_use_certificate_file: " + OpenSslInterop.GetLastErrorString());
            if (OpenSslInterop.SSL_CTX_use_PrivateKey_file(ctx, keyPem, OpenSslInterop.SSL_FILETYPE_PEM) <= 0)
                throw new InvalidOperationException("SSL_CTX_use_PrivateKey_file: " + OpenSslInterop.GetLastErrorString());
            if (OpenSslInterop.SSL_CTX_check_private_key(ctx) <= 0)
                throw new InvalidOperationException("SSL_CTX_check_private_key: " + OpenSslInterop.GetLastErrorString());
            OpenSslInterop.SetSessionCacheMode(ctx, OpenSslInterop.SSL_SESS_CACHE_SERVER);
            OpenSslInterop.SSL_CTX_set_timeout(ctx, 3600);
            OpenSslInterop.SetSessionCacheSize(ctx, 20000);
            return ctx;
        }
        finally
        {
            try { File.Delete(certPem); } catch { }
            try { File.Delete(keyPem); } catch { }
        }
    }

    private sealed class ConnPair : IDisposable
    {
        public Socket ClientSocket = null!;
        public Socket ServerSocket = null!;
        public NetworkStream ClientStream = null!;
        public SslStream ClientSsl = null!;
        public TlsSession? Session;
        public IntPtr RawSsl;
        public int ServerFd;
        public bool OwnsServerSocket;

        public void Dispose()
        {
            try { ClientSsl?.Dispose(); } catch { }
            if (Session is not null)
            {
                try { Session.Dispose(); } catch { }
            }
            else if (RawSsl != IntPtr.Zero)
            {
                try { OpenSslInterop.SSL_shutdown(RawSsl); } catch { }
                try { OpenSslInterop.SSL_free(RawSsl); } catch { }
                if (OwnsServerSocket) { try { ServerSocket?.Dispose(); } catch { } }
            }
            try { ClientStream?.Dispose(); } catch { }
            try { ClientSocket?.Dispose(); } catch { }
        }
    }

    private static ConnPair BuildPair(
        Socket listener,
        IPEndPoint listenerEp,
        TlsContext tlsCtx,
        IntPtr opensslCtx,
        SslClientAuthenticationOptions clientOptions,
        string engine)
    {
        var client = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        client.NoDelay = true;
        Task<Socket> acceptTask = listener.AcceptAsync();
        client.Connect(listenerEp);
        Socket server = acceptTask.GetAwaiter().GetResult();
        server.NoDelay = true;

        var pair = new ConnPair
        {
            ClientSocket = client,
            ServerSocket = server,
            ClientStream = new NetworkStream(client, ownsSocket: false),
            ServerFd = (int)server.Handle,
        };
        pair.ClientSsl = new SslStream(pair.ClientStream, leaveInnerStreamOpen: true);

        if (engine.Equals("TlsSess", StringComparison.OrdinalIgnoreCase))
        {
            server.Blocking = false;
            var session = TlsSession.Create(tlsCtx, server.SafeHandle);
            pair.Session = session;

            Task clientAuth = pair.ClientSsl.AuthenticateAsClientAsync(clientOptions);
            Task serverHs = PersistentRoundtripsBench.RunOnDedicatedThreadAsync(
                () => PersistentRoundtripsBench.DriveFdHandshake(session, server));
            Task.WaitAll(new[] { clientAuth, serverHs });

            var secCtx = (SafeHandle?)typeof(TlsSession)
                .GetField("_securityContext", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)!
                .GetValue(session);
            pair.RawSsl = secCtx?.DangerousGetHandle() ?? IntPtr.Zero;
            if (pair.RawSsl == IntPtr.Zero) throw new InvalidOperationException("TlsSession._securityContext handle is zero after handshake");
        }
        else if (engine.Equals("Raw", StringComparison.OrdinalIgnoreCase))
        {
            server.Blocking = false;
            IntPtr ssl = OpenSslInterop.SSL_new(opensslCtx);
            if (ssl == IntPtr.Zero) throw new InvalidOperationException("SSL_new: " + OpenSslInterop.GetLastErrorString());
            if (OpenSslInterop.SSL_set_fd(ssl, pair.ServerFd) <= 0)
                throw new InvalidOperationException("SSL_set_fd: " + OpenSslInterop.GetLastErrorString());
            OpenSslInterop.SSL_set_accept_state(ssl);
            pair.RawSsl = ssl;
            pair.OwnsServerSocket = true;

            Task clientAuth = pair.ClientSsl.AuthenticateAsClientAsync(clientOptions);
            Task serverHs = PersistentRoundtripsBench.RunOnDedicatedThreadAsync(
                () => PersistentRoundtripsBench.DriveRawHandshake(ssl, server));
            Task.WaitAll(new[] { clientAuth, serverHs });
        }
        else
        {
            throw new ArgumentException($"Unknown engine '{engine}'. Use 'Raw' or 'TlsSess'.");
        }

        return pair;
    }

    private static void ClientLoop(SslStream client, byte[] payload, CancellationToken ct)
    {
        byte[] recvArr = new byte[4096];
        try
        {
            while (!ct.IsCancellationRequested)
            {
                client.Write(payload, 0, payload.Length);
                int need = payload.Length;
                int got = 0;
                while (got < need)
                {
                    int n = client.Read(recvArr, got, need - got);
                    if (n <= 0) return;
                    got += n;
                }
            }
        }
        catch (Exception ex) when (ct.IsCancellationRequested || ex is IOException || ex is ObjectDisposedException)
        {
        }
    }

    private static void PumpLoop(
        ConnPair[] pairs,
        long[] readCounts,
        long[] readBytes,
        long[] wantReadCounts,
        CancellationToken ct,
        bool singleReadPerWake,
        bool useTlsSessionApi)
    {
        int epfd = epoll_create1(EPOLL_CLOEXEC);
        if (epfd < 0) throw new InvalidOperationException("epoll_create1 failed: errno=" + Marshal.GetLastPInvokeError());

        var fdToIdx = new System.Collections.Generic.Dictionary<int, int>(pairs.Length);
        for (int i = 0; i < pairs.Length; i++)
        {
            var ev = new EpollEvent { Events = EPOLLIN | EPOLLRDHUP, Fd = pairs[i].ServerFd };
            if (epoll_ctl(epfd, EPOLL_CTL_ADD, pairs[i].ServerFd, ref ev) < 0)
                throw new InvalidOperationException($"epoll_ctl ADD fd={pairs[i].ServerFd} failed: errno={Marshal.GetLastPInvokeError()}");
            fdToIdx[pairs[i].ServerFd] = i;
        }

        const int MaxEvents = 64;
        var events = new EpollEvent[MaxEvents];
        byte[] scratch = new byte[16 * 1024];
        int scratchLen = scratch.Length;

        while (!ct.IsCancellationRequested)
        {
            int n = epoll_wait(epfd, events, MaxEvents, 100);
            if (n <= 0) continue;

            for (int i = 0; i < n; i++)
            {
                int fd = events[i].Fd;
                if (!fdToIdx.TryGetValue(fd, out int idx)) continue;
                IntPtr ssl = pairs[idx].RawSsl;
                if (ssl == IntPtr.Zero) continue;

                if (useTlsSessionApi && pairs[idx].Session is not null)
                {
                    DrainOneSession(pairs[idx].Session!, idx, scratch, readCounts, readBytes, wantReadCounts, singleReadPerWake);
                }
                else
                {
                    unsafe
                    {
                        fixed (byte* buf = scratch)
                        {
                            DrainOneRaw(ssl, idx, buf, scratchLen, readCounts, readBytes, wantReadCounts, singleReadPerWake);
                        }
                    }
                }
            }
        }

        close(epfd);
    }

    private static unsafe void DrainOneRaw(IntPtr ssl, int idx, byte* buf, int bufLen,
                                        long[] readCounts, long[] readBytes, long[] wantReadCounts,
                                        bool singleReadPerWake)
    {
        while (true)
        {
            int r = OpenSslInterop.SSL_read(ssl, buf, bufLen);
            if (r > 0)
            {
                readCounts[idx]++;
                readBytes[idx] += r;
                int off = 0;
                while (off < r)
                {
                    int w = OpenSslInterop.SSL_write(ssl, buf + off, r - off);
                    if (w > 0) { off += w; continue; }
                    int werr = OpenSslInterop.SSL_get_error(ssl, w);
                    if (werr == OpenSslInterop.SSL_ERROR_WANT_WRITE || werr == OpenSslInterop.SSL_ERROR_WANT_READ)
                    {
                        Thread.SpinWait(50);
                        continue;
                    }
                    return;
                }
                if (singleReadPerWake) return;
                continue;
            }
            int err = OpenSslInterop.SSL_get_error(ssl, r);
            if (err == OpenSslInterop.SSL_ERROR_WANT_READ)
            {
                wantReadCounts[idx]++;
                return;
            }
            return;
        }
    }

    // Managed variant: uses TlsSession.Read / TlsSession.Write (the actual API path
    // aspnetcore Hybrid Step 4/5 exercises). This is the path we want to compare
    // against DrainOneRaw to prove/disprove per-call TlsSession overhead on
    // WANT_READ-heavy workloads (request-response persistent conns).
    private static void DrainOneSession(TlsSession session, int idx, byte[] scratch,
                                        long[] readCounts, long[] readBytes, long[] wantReadCounts,
                                        bool singleReadPerWake)
    {
        Span<byte> buf = scratch;
        while (true)
        {
            TlsOperationStatus rstatus = session.Read(buf, out int bytesRead);
            if (rstatus == TlsOperationStatus.Complete && bytesRead > 0)
            {
                readCounts[idx]++;
                readBytes[idx] += bytesRead;
                int off = 0;
                while (off < bytesRead)
                {
                    TlsOperationStatus wstatus = session.Write(buf.Slice(off, bytesRead - off), out int written);
                    if (wstatus == TlsOperationStatus.Complete && written > 0) { off += written; continue; }
                    if (wstatus == TlsOperationStatus.WantWrite || wstatus == TlsOperationStatus.WantRead)
                    {
                        Thread.SpinWait(50);
                        continue;
                    }
                    return;
                }
                if (singleReadPerWake) return;
                continue;
            }
            if (rstatus == TlsOperationStatus.WantRead)
            {
                wantReadCounts[idx]++;
                return;
            }
            return;
        }
    }
}
