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
    /// <see cref="Add"/>, <see cref="Modify"/>, and <see cref="Remove"/> are
    /// thread-safe at the kernel level. <see cref="Wait"/> should be called from
    /// one thread at a time per <see cref="SafePollHandle"/> instance.
    /// </para>
    /// <para>
    /// A handle registered with a <see cref="SafePollHandle"/> must not
    /// simultaneously be driven by <c>Socket.AcceptAsync</c>,
    /// <c>Socket.SendAsync</c>, or other <c>SocketAsyncEventArgs</c>-based
    /// operations — both would compete for readiness notifications on the
    /// same file descriptor.
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

        /// <summary>
        /// Gets a value indicating whether <see cref="SafePollHandle"/> is
        /// supported on the current platform.
        /// </summary>
        /// <value>
        /// <see langword="true"/> on Linux, macOS, and FreeBSD;
        /// <see langword="false"/> on all other platforms.
        /// </value>
        public static bool IsSupported =>
            OperatingSystem.IsLinux() ||
            OperatingSystem.IsMacOS() ||
            OperatingSystem.IsFreeBSD();

        private SafePollHandle() : base(IntPtr.Zero, ownsHandle: true)
        {
        }

        /// <inheritdoc/>
        public override bool IsInvalid => handle == IntPtr.Zero || handle == new IntPtr(-1);

        /// <inheritdoc/>
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

        /// <summary>
        /// Creates a new <see cref="SafePollHandle"/> backed by the platform's
        /// readiness polling mechanism (epoll on Linux, kqueue on macOS/FreeBSD).
        /// </summary>
        /// <param name="maxEventsPerWait">
        /// The maximum number of events returned by a single <see cref="Wait"/>
        /// call. Determines the size of the internal native event buffer.
        /// Typical values: 64–1024.
        /// </param>
        /// <returns>A new <see cref="SafePollHandle"/>.</returns>
        /// <exception cref="PlatformNotSupportedException">
        /// <see cref="IsSupported"/> is <see langword="false"/>.
        /// </exception>
        /// <exception cref="IOException">
        /// The underlying system call (<c>epoll_create1</c> or <c>kqueue</c>) failed.
        /// </exception>
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

        /// <summary>
        /// Registers a file descriptor for readiness monitoring.
        /// </summary>
        /// <param name="handle">
        /// The handle to monitor. Must be a file descriptor that the kernel's
        /// polling mechanism supports (sockets, pipes, eventfds, timerfd, etc.).
        /// The caller retains ownership of the handle and must keep it alive
        /// for as long as it is registered.
        /// </param>
        /// <param name="events">The events to monitor for.</param>
        /// <param name="options">
        /// Registration options. These are immutable for the lifetime of the
        /// registration — to change them, call <see cref="Remove"/> then
        /// <see cref="Add"/> again.
        /// </param>
        /// <param name="token">
        /// An opaque value echoed back in <see cref="PollNotification.Token"/>
        /// when events fire. Typically <c>(IntPtr)fd</c>, a
        /// <see cref="GCHandle"/>, or an index into a side table.
        /// </param>
        /// <exception cref="ObjectDisposedException">
        /// This <see cref="SafePollHandle"/> has been disposed.
        /// </exception>
        /// <exception cref="IOException">
        /// The underlying <c>epoll_ctl</c> or <c>kevent</c> call failed.
        /// </exception>
        public void Add(SafeHandle handle, PollEvents events, PollRegistrationOptions options, IntPtr token)
        {
            ObjectDisposedException.ThrowIf(IsInvalid || IsClosed, this);
            ArgumentNullException.ThrowIfNull(handle);

            bool addedRef = false;
            try
            {
                handle.DangerousAddRef(ref addedRef);

                int flags = (int)options;
                Interop.Error err = Interop.Sys.TryChangeSocketEventRegistrationWithFlags(
                    this.handle,
                    handle.DangerousGetHandle(),
                    currentEvents: (int)PollEvents.None,
                    newEvents: (int)events,
                    data: token,
                    flags: flags);

                if (err != Interop.Error.SUCCESS)
                {
                    throw CreateIOException(err);
                }
            }
            finally
            {
                if (addedRef)
                {
                    handle.DangerousRelease();
                }
            }
        }

        /// <summary>
        /// Modifies the monitored events for a previously registered handle.
        /// </summary>
        /// <remarks>
        /// Registration options (e.g., <see cref="PollRegistrationOptions.ExclusiveWakeup"/>)
        /// cannot be changed via <see cref="Modify"/>. To change them, call
        /// <see cref="Remove"/> then <see cref="Add"/>.
        /// </remarks>
        /// <param name="handle">The handle whose monitored events to change.</param>
        /// <param name="events">The new set of events to monitor for.</param>
        /// <param name="token">
        /// The token to associate with this handle (echoed back in notifications).
        /// </param>
        /// <exception cref="ObjectDisposedException">
        /// This <see cref="SafePollHandle"/> has been disposed.
        /// </exception>
        /// <exception cref="IOException">
        /// The underlying <c>epoll_ctl</c> or <c>kevent</c> call failed.
        /// </exception>
        public void Modify(SafeHandle handle, PollEvents events, IntPtr token)
        {
            ObjectDisposedException.ThrowIf(IsInvalid || IsClosed, this);
            ArgumentNullException.ThrowIfNull(handle);

            bool addedRef = false;
            try
            {
                handle.DangerousAddRef(ref addedRef);

                // Use flags=0 for Modify — options are immutable from Add.
                Interop.Error err = Interop.Sys.TryChangeSocketEventRegistrationWithFlags(
                    this.handle,
                    handle.DangerousGetHandle(),
                    currentEvents: -1, // non-zero + non-None → forces EPOLL_CTL_MOD path
                    newEvents: (int)events,
                    data: token,
                    flags: 0);

                if (err != Interop.Error.SUCCESS)
                {
                    throw CreateIOException(err);
                }
            }
            finally
            {
                if (addedRef)
                {
                    handle.DangerousRelease();
                }
            }
        }

        /// <summary>
        /// Removes a handle from readiness monitoring.
        /// </summary>
        /// <remarks>
        /// Safe to call if the handle has already been removed or closed —
        /// the operation is idempotent.
        /// </remarks>
        /// <param name="handle">The handle to remove.</param>
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

                // Ignore errors — the fd may already have been removed or closed.
                // This matches how SocketAsyncEngine handles unregistration:
                // the kernel auto-removes closed fds from epoll/kqueue.
                Interop.Sys.TryChangeSocketEventRegistrationWithFlags(
                    this.handle,
                    handle.DangerousGetHandle(),
                    currentEvents: -1, // non-zero → not ADD
                    newEvents: (int)PollEvents.None, // None → DEL
                    data: IntPtr.Zero,
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

        /// <summary>
        /// Waits for readiness events on registered handles.
        /// </summary>
        /// <param name="notifications">
        /// A buffer to receive the events. Up to <c>notifications.Length</c>
        /// events will be returned (capped by the <c>maxEventsPerWait</c>
        /// passed to <see cref="Create"/>).
        /// </param>
        /// <param name="timeoutMs">
        /// Timeout in milliseconds. <c>-1</c> for infinite wait; <c>0</c>
        /// for immediate (non-blocking) check.
        /// </param>
        /// <returns>
        /// The number of notifications written to <paramref name="notifications"/>.
        /// Zero on timeout.
        /// </returns>
        /// <exception cref="ObjectDisposedException">
        /// This <see cref="SafePollHandle"/> has been disposed.
        /// </exception>
        /// <exception cref="IOException">
        /// The underlying <c>epoll_wait</c> or <c>kevent</c> call failed.
        /// </exception>
        public unsafe int Wait(Span<PollNotification> notifications, int timeoutMs)
        {
            ObjectDisposedException.ThrowIf(IsInvalid || IsClosed, this);

            int count = Math.Min(notifications.Length, _nativeBufferCount);
            if (count <= 0)
            {
                return 0;
            }

            Interop.Error err = Interop.Sys.WaitForSocketEventsWithTimeout(
                handle, _nativeBuffer, &count, timeoutMs);

            if (err != Interop.Error.SUCCESS)
            {
                throw CreateIOException(err);
            }

            // Copy from the internal native-layout buffer into the public
            // PollNotification span. This avoids exposing the native struct
            // layout (which differs between epoll and kqueue) across the
            // public API boundary.
            for (int i = 0; i < count; i++)
            {
                notifications[i] = new PollNotification(
                    token: _nativeBuffer[i].Data,
                    events: (PollEvents)(int)_nativeBuffer[i].Events);
            }

            return count;
        }

        private static IOException CreateIOException(Interop.Error error)
        {
            Interop.ErrorInfo info = new Interop.ErrorInfo(error);
            string msg = info.GetErrorMessage();

            return new IOException(msg, info.RawErrno);
        }
    }
}
