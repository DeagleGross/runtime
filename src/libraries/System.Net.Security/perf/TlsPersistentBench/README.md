# TlsPersistentBench

Persistent-connection TLS benchmark comparing `SslStream` (baseline) against `TlsSession`
in both buffered and fd-bound modes. Distinct from the sibling `TlsHandshakeBench`:

| Project              | Measures                                       |
|----------------------|------------------------------------------------|
| TlsHandshakeBench    | One handshake + 1-byte ping/pong per iteration |
| TlsPersistentBench   | One handshake + **N request/response roundtrips** through the same connection (handshake done in IterationSetup, only the roundtrips are measured) |

The motivation is to isolate steady-state per-call cost from handshake cost. An
aspnetcore-side prototype showed a ~50x gap on persistent keep-alive between
direct `SSL_read/SSL_write` P/Invoke and the new `TlsSession` API even though
handshake-heavy scenarios were at parity — this bench is intended to localize
that gap without speculation.

> Like `TlsHandshakeBench`, this project is **temporary** and not part of the
> regular libraries build. It is not referenced from any solution or test list.

## Run

The benchmark depends on the live-built `System.Net.Security` (TlsSession is not
in any shipped runtime), so it must run against the in-tree testhost.

```bash
# 1) Baseline build (once; populates a release runtime layout).
./build.sh clr+libs+libs.pretest -rc release

# 2) Build the benchmark.
./dotnet.sh build -c Release \
    src/libraries/System.Net.Security/perf/TlsPersistentBench/TlsPersistentBench.csproj

# 3) Run with the local testhost.
artifacts/bin/testhost/net11.0-linux-Release-x64/dotnet \
    artifacts/bin/TlsPersistentBench/Release/net11.0/TlsPersistentBench.dll --filter '*'
```

To run a single engine:

```bash
... TlsPersistentBench.dll --filter '*Fd_Roundtrips*'
```

## Counters

Per-interop call counts + timings are gated behind the `DEBUG_INTEROP_COUNTERS`
compile flag. By default it is **off** so the bench measures pure performance
without `Stopwatch.GetTimestamp` overhead in the hot path.

To enable:

```bash
./dotnet.sh build -c Release \
    /p:DefineConstants=DEBUG_INTEROP_COUNTERS \
    src/libraries/System.Net.Security/perf/TlsPersistentBench/TlsPersistentBench.csproj
```

When enabled, each native-boundary call (`TlsSession.Read`, `Session.Write`,
`Session.Encrypt`, `Session.Decrypt`, `Session.ProcessHandshake`,
`Session.DrainPendingOutput`, `Session.Handshake`, plus `Socket.Send/Receive/Poll`
and `SslStream.ReadAsync/WriteAsync` for the baseline) records:

- Call count
- Total / min / max nanoseconds (via `Stopwatch.GetTimestamp`)
- Bytes consumed / produced

A final summary is printed to stdout after BDN finishes:

```
==== Final accumulated (across all iterations) ====
Bucket                                Calls      TotalNs      AvgNs      MinNs        MaxNs   BytesIn/Out
TlsSession.Read                       16800     19200000       1142        842         9417     1075200/0
TlsSession.Write                      16800     17100000       1017        801         8201     0/1075200
...
```

## Parameters

- `Protocol` — `Tls13` (Tls12 can be added back via `[Params(Tls12, Tls13)]` if needed)
- `PayloadSize` — `64`, `4096` bytes
- `RequestCount` — `10`, `100` roundtrips per measured iteration

The matrix is small on purpose; widen it after the first run identifies what to drill into.

## Engines

- `SslStream_Roundtrips` (baseline) — `SslStream` on both ends
- `TlsSession_Buffered_Roundtrips` — server uses `TlsSession.Encrypt/Decrypt` against a non-blocking socket
- `TlsSession_Fd_Roundtrips` — server uses `TlsSession.Read/Write` on a socket bound via `SSL_set_fd`
  (Linux/FreeBSD only — throws PlatformNotSupportedException on Windows)
- `RawOpenSsl_Roundtrips` — server uses direct `libssl.so.3` P/Invoke (`SSL_read`/`SSL_write`) on
  a blocking socket bound via `SSL_set_fd`. This is the apples-to-apples baseline against the
  aspnetcore-side OpenSslDirect engine that was the comparison target in the original investigation.
  (Linux only, requires OpenSSL 3.x installed.)

In every variant the client side is `SslStream` over loopback TCP. Both sides have
`NoDelay = true`.

## Caveats

- Loopback TCP eliminates network noise but also eliminates real-world batching that
  affects RPS — interpret absolute numbers cautiously. Call-count *ratios* between
  engines are the trustworthy signal.
- `IterationSetup` builds a fresh connection per iteration. With `InvocationCount=16`
  that's 16 roundtrips × N requests × 15 iterations per row — plenty for stable means.
- `MemoryDiagnoser` reports allocations per measured invocation (i.e. per
  `RequestCount` roundtrips). Divide by `RequestCount` to get per-request alloc.
