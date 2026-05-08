// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.IO;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace System.Threading
{
    /// <summary>
    /// A managed wrapper over the platform's readiness polling mechanism
    /// (epoll on Linux, kqueue on macOS/FreeBSD).
    /// </summary>
    /// <remarks>
    /// <para>
    /// Enables a single thread to efficiently wait for readiness events on multiple
    /// file descriptors (sockets, pipes, etc.). The consumer owns the wait loop
    /// thread and calls <see cref="Wait"/> directly — there is no automatic
    /// ThreadPool dispatch.
    /// </para>
    /// <para>
    /// <see cref="TryAdd"/>, <see cref="TryModify"/>, and <see cref="Remove"/> are
    /// thread-safe at the kernel level. <see cref="Wait"/> should be called from
    /// one thread at a time per <see cref="SafePollHandle"/> instance.
    /// </para>
    /// <para>
    /// This is a power-user API. The caller is responsible for not calling
    /// <see cref="TryModify"/> or <see cref="Remove"/> on handles that were
    /// never registered. <see cref="Remove"/> is idempotent.
    /// </para>
    /// </remarks>
    [UnsupportedOSPlatform("windows")]
    [UnsupportedOSPlatform("browser")]
    [UnsupportedOSPlatform("wasi")]
    [UnsupportedOSPlatform("android")]
    [UnsupportedOSPlatform("ios")]
    [UnsupportedOSPlatform("tvos")]
    public sealed class SafePollHandle : SafeHandle
    {
        private unsafe Interop.Sys.SocketEvent* _nativeBuffer;
        private int _nativeBufferCount;

        public static bool IsSupported =>
            OperatingSystem.IsLinux() ||
            OperatingSystem.IsMacOS() ||
            OperatingSystem.IsFreeBSD();

        private SafePollHandle() : base(IntPtr.Zero, ownsHandle: true) { }

        public override bool IsInvalid => handle == IntPtr.Zero || handle == new IntPtr(-1);

        protected override unsafe bool ReleaseHandle()
        {
            if (_nativeBuffer is not null)
            {
                Interop.Sys.FreeSocketEventBuffer(_nativeBuffer);
                _nativeBuffer = null;
            }

            IntPtr h = handle;
            SetHandle(IntPtr.Zero);

            if (h != IntPtr.Zero && h != new IntPtr(-1))
            {
                Interop.Sys.CloseSocketEventPort(h);
            }

            return true;
        }

        /// <summary>Creates a new <see cref="SafePollHandle"/>.</summary>
        public static unsafe SafePollHandle Create(int maxEventsPerWait = 256)
        {
            if (!IsSupported)
            {
                throw new PlatformNotSupportedException("SafePollHandle requires Linux, macOS, or FreeBSD.");
            }

            ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxEventsPerWait);

            var pollHandle = new SafePollHandle();

            try
            {
                IntPtr port;
                Interop.Error err = Interop.Sys.CreateSocketEventPort(&port);
                if (err != Interop.Error.SUCCESS)
                {
                    throw CreateIOException(err);
                }

                pollHandle.SetHandle(port);

                Interop.Sys.SocketEvent* buffer;
                err = Interop.Sys.CreateSocketEventBuffer(maxEventsPerWait, &buffer);
                if (err != Interop.Error.SUCCESS)
                {
                    throw CreateIOException(err);
                }

                pollHandle._nativeBuffer = buffer;
                pollHandle._nativeBufferCount = maxEventsPerWait;
            }
            catch
            {
                pollHandle.Dispose();
                throw;
            }

            return pollHandle;
        }

        /// <summary>Attempts to register a handle for readiness monitoring.</summary>
        /// <param name="handle">The handle to monitor.</param>
        /// <param name="events">The events to monitor for.</param>
        /// <param name="options">Registration options (immutable for the lifetime of the registration).</param>
        /// <param name="state">Opaque value echoed back in <see cref="PollNotification.State"/>.</param>
        /// <param name="error">On failure, receives the reason. On success, <see cref="PollError.None"/>.</param>
        /// <returns><see langword="true"/> on success; <see langword="false"/> if the kernel call failed.</returns>
        public bool TryAdd(SafeHandle handle, PollEvents events, PollRegistrationOptions options, nint state, out PollError error)
        {
            ObjectDisposedException.ThrowIf(IsInvalid || IsClosed, this);
            ArgumentNullException.ThrowIfNull(handle);

            bool addedRef = false;
            try
            {
                handle.DangerousAddRef(ref addedRef);

                Interop.Error err = Interop.Sys.TryChangeSocketEventRegistrationWithFlags(
                    this.handle,
                    handle.DangerousGetHandle(),
                    currentEvents: (int)PollEvents.None,
                    newEvents: (int)events,
                    data: state,
                    flags: (int)options);

                error = MapError(err);
                return err == Interop.Error.SUCCESS;
            }
            finally
            {
                if (addedRef)
                {
                    handle.DangerousRelease();
                }
            }
        }

        /// <summary>Attempts to modify the monitored events for a previously registered handle.</summary>
        /// <param name="handle">The handle whose monitored events to change.</param>
        /// <param name="events">The new set of events to monitor for.</param>
        /// <param name="state">The state to associate with this handle.</param>
        /// <param name="error">On failure, receives the reason. On success, <see cref="PollError.None"/>.</param>
        /// <returns><see langword="true"/> on success; <see langword="false"/> if the kernel call failed.</returns>
        public bool TryModify(SafeHandle handle, PollEvents events, nint state, out PollError error)
        {
            ObjectDisposedException.ThrowIf(IsInvalid || IsClosed, this);
            ArgumentNullException.ThrowIfNull(handle);

            bool addedRef = false;
            try
            {
                handle.DangerousAddRef(ref addedRef);

                Interop.Error err = Interop.Sys.TryChangeSocketEventRegistrationWithFlags(
                    this.handle,
                    handle.DangerousGetHandle(),
                    currentEvents: -1,
                    newEvents: (int)events,
                    data: state,
                    flags: 0);

                error = MapError(err);
                return err == Interop.Error.SUCCESS;
            }
            finally
            {
                if (addedRef)
                {
                    handle.DangerousRelease();
                }
            }
        }

        /// <summary>Removes a handle from readiness monitoring. Idempotent.</summary>
        public void Remove(SafeHandle handle)
        {
            if (IsInvalid || IsClosed)
            {
                return;
            }

            ArgumentNullException.ThrowIfNull(handle);

            bool addedRef = false;
            try
            {
                handle.DangerousAddRef(ref addedRef);

                Interop.Sys.TryChangeSocketEventRegistrationWithFlags(
                    this.handle,
                    handle.DangerousGetHandle(),
                    currentEvents: -1,
                    newEvents: (int)PollEvents.None,
                    data: 0,
                    flags: 0);
            }
            finally
            {
                if (addedRef)
                {
                    handle.DangerousRelease();
                }
            }
        }

        /// <summary>Waits for readiness events on registered handles.</summary>
        /// <returns>
        /// A <see cref="ReadOnlySpan{T}"/> of <see cref="PollNotification"/> backed
        /// directly by the internal native event buffer. The span is only valid until
        /// the next call to <see cref="Wait"/> on the same handle.
        /// </returns>
        public unsafe ReadOnlySpan<PollNotification> Wait(TimeSpan timeout)
        {
            ObjectDisposedException.ThrowIf(IsInvalid || IsClosed, this);

            int timeoutMs;
            if (timeout == Timeout.InfiniteTimeSpan)
            {
                timeoutMs = -1;
            }
            else if (timeout == TimeSpan.Zero)
            {
                timeoutMs = 0;
            }
            else
            {
                ArgumentOutOfRangeException.ThrowIfLessThan(timeout, TimeSpan.Zero);
                timeoutMs = (int)Math.Min(timeout.TotalMilliseconds, int.MaxValue);
            }

            int count = _nativeBufferCount;

            Interop.Error err = Interop.Sys.WaitForSocketEventsWithTimeout(
                handle, _nativeBuffer, &count, timeoutMs);

            if (err != Interop.Error.SUCCESS)
            {
                throw CreateIOException(err);
            }

            // PollNotification has identical layout to SocketEvent — cast directly.
            return new ReadOnlySpan<PollNotification>(_nativeBuffer, count);
        }

        private static PollError MapError(Interop.Error error) => error switch
        {
            Interop.Error.SUCCESS => PollError.None,
            Interop.Error.EBADF => PollError.BadFileDescriptor,
            Interop.Error.EEXIST => PollError.AlreadyExists,
            Interop.Error.ENOENT => PollError.NotFound,
            Interop.Error.EPERM => PollError.PermissionDenied,
            Interop.Error.ENOMEM or Interop.Error.ENOSPC => PollError.OutOfResources,
            Interop.Error.EINVAL => PollError.InvalidArgument,
            _ => PollError.Unknown,
        };

        private static IOException CreateIOException(Interop.Error error)
        {
            Interop.ErrorInfo info = new Interop.ErrorInfo(error);
            string msg = info.GetErrorMessage();

            return new IOException(msg, info.RawErrno);
        }
    }
}