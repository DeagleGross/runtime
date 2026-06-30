// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Text;

namespace TlsPersistentBench;

/// <summary>
/// Per-interop call counters and timings, broken down by which API the bench is exercising.
///
/// Gated behind the <c>DEBUG_INTEROP_COUNTERS</c> compile flag. When the flag is not defined,
/// every method is a no-op the JIT can fully elide. The cost of leaving the call sites in
/// when the flag is enabled is one <c>Stopwatch.GetTimestamp</c> pair and two
/// <c>Interlocked.Increment</c>s per measured native call.
///
/// Counters are static + process-global on purpose. The bench framework drives one workload
/// at a time, and dumping a per-iteration snapshot post-<see cref="Reset"/> avoids any
/// dictionary lookup in the hot path.
/// </summary>
internal static class InteropProbe
{
    public sealed class Bucket
    {
        public long Calls;
        public long TotalTicks;       // sum of Stopwatch.GetTimestamp deltas
        public long MinTicks = long.MaxValue;
        public long MaxTicks;
        public long BytesIn;          // sum of input/produced bytes
        public long BytesOut;         // sum of output/consumed bytes

        public void Record(long ticks, long bytesIn, long bytesOut)
        {
            Calls++;
            TotalTicks += ticks;
            if (ticks < MinTicks) MinTicks = ticks;
            if (ticks > MaxTicks) MaxTicks = ticks;
            BytesIn += bytesIn;
            BytesOut += bytesOut;
        }

        public void Reset()
        {
            Calls = 0;
            TotalTicks = 0;
            MinTicks = long.MaxValue;
            MaxTicks = 0;
            BytesIn = 0;
            BytesOut = 0;
        }
    }

    // SslStream baseline counters
    public static readonly Bucket SslStreamReadAsync = new();
    public static readonly Bucket SslStreamWriteAsync = new();

    // TlsSession buffered path counters
    public static readonly Bucket SessionEncrypt = new();
    public static readonly Bucket SessionDecrypt = new();
    public static readonly Bucket SessionDrainPendingOutput = new();
    public static readonly Bucket SessionProcessHandshake = new();

    // TlsSession fd-mode counters
    public static readonly Bucket SessionRead = new();
    public static readonly Bucket SessionWrite = new();
    public static readonly Bucket SessionHandshake = new();

    // Syscall counters (the same ones Tomas's bench tracks, kept compatible here)
    public static readonly Bucket SocketSend = new();
    public static readonly Bucket SocketReceive = new();
    public static readonly Bucket SocketPollRead = new();
    public static readonly Bucket SocketPollWrite = new();

    private static readonly Bucket[] s_all =
    [
        SslStreamReadAsync, SslStreamWriteAsync,
        SessionEncrypt, SessionDecrypt, SessionDrainPendingOutput, SessionProcessHandshake,
        SessionRead, SessionWrite, SessionHandshake,
        SocketSend, SocketReceive, SocketPollRead, SocketPollWrite,
    ];

    private static readonly string[] s_names =
    [
        "SslStream.ReadAsync", "SslStream.WriteAsync",
        "TlsSession.Encrypt", "TlsSession.Decrypt", "TlsSession.DrainPendingOutput", "TlsSession.ProcessHandshake",
        "TlsSession.Read", "TlsSession.Write", "TlsSession.Handshake",
        "Socket.Send", "Socket.Receive", "Socket.Poll(Read)", "Socket.Poll(Write)",
    ];

    public static void Reset()
    {
        foreach (Bucket b in s_all)
        {
            b.Reset();
        }
    }

    /// <summary>
    /// Render a human-readable summary of the active buckets. Skips buckets with zero calls.
    /// </summary>
    public static string Dump(string label, int? requestCountForPerOp = null)
    {
        var sb = new StringBuilder();
        sb.Append("==== ").Append(label).AppendLine(" ====");
        sb.AppendFormat("{0,-32} {1,>10} {2,>12} {3,>10} {4,>10} {5,>12} {6,>12}",
            "Bucket", "Calls", "TotalNs", "AvgNs", "MinNs", "MaxNs", "BytesIn/Out").AppendLine();
        for (int i = 0; i < s_all.Length; i++)
        {
            Bucket b = s_all[i];
            if (b.Calls == 0) continue;
            long totalNs = TicksToNs(b.TotalTicks);
            long avgNs = b.Calls == 0 ? 0 : totalNs / b.Calls;
            long minNs = TicksToNs(b.MinTicks);
            long maxNs = TicksToNs(b.MaxTicks);
            sb.AppendFormat("{0,-32} {1,10} {2,12} {3,10} {4,10} {5,12} {6,12}",
                s_names[i], b.Calls, totalNs, avgNs, minNs, maxNs,
                $"{b.BytesIn}/{b.BytesOut}").AppendLine();
        }
        if (requestCountForPerOp.HasValue && requestCountForPerOp.Value > 0)
        {
            sb.AppendFormat("(per request, RequestCount={0})", requestCountForPerOp.Value).AppendLine();
            for (int i = 0; i < s_all.Length; i++)
            {
                Bucket b = s_all[i];
                if (b.Calls == 0) continue;
                double callsPer = (double)b.Calls / requestCountForPerOp.Value;
                double nsPer = (double)TicksToNs(b.TotalTicks) / requestCountForPerOp.Value;
                sb.AppendFormat("  {0,-30} {1,8:F2} calls/req  {2,10:F0} ns/req", s_names[i], callsPer, nsPer).AppendLine();
            }
        }
        return sb.ToString();
    }

    private static readonly double s_nsPerTick = 1_000_000_000.0 / Stopwatch.Frequency;

    private static long TicksToNs(long ticks)
    {
        if (ticks == long.MaxValue) return 0;
        return (long)(ticks * s_nsPerTick);
    }

#if DEBUG_INTEROP_COUNTERS
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static long Start() => Stopwatch.GetTimestamp();

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void Stop(Bucket bucket, long startTicks, long bytesIn = 0, long bytesOut = 0)
    {
        long elapsed = Stopwatch.GetTimestamp() - startTicks;
        bucket.Record(elapsed, bytesIn, bytesOut);
    }
#else
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static long Start() => 0L;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void Stop(Bucket bucket, long startTicks, long bytesIn = 0, long bytesOut = 0) { }
#endif
}
