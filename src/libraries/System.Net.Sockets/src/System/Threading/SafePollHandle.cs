// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace System.Threading
{
    /// <summary>
    /// A managed wrapper over a readiness polling mechanism (epoll on Linux, kqueue on macOS/FreeBSD).
    /// <para>
    /// Enables a single thread to efficiently wait for readiness events on multiple
    /// file descriptors (sockets, pipes, etc.). The consumer owns the wait loop thread
    /// and calls <see cref="Wait"/> directly — no ThreadPool dispatch.
    /// </para>
    /// </summary>
    /// <remarks>
    /// <para>
    /// <see cref="Add"/>/<see cref="Modify"/>/<see cref="Remove"/> are thread-safe at the
    /// kernel level. <see cref="Wait"/> should be called from a single thread at a time
    /// per <see cref="SafePollHandle"/> instance.
    /// </para>
    /// <para>
    /// A handle registered with a <see cref="SafePollHandle"/> must not simultaneously be
    /// driven by <see cref="System.Net.Sockets.Socket"/> async operations
    /// (<see cref="System.Net.Sockets.Socket.AcceptAsync(System.Net.Sockets.SocketAsyncEventArgs)"/>,
    /// <see cref="System.Net.Sockets.Socket.SendAsync(System.Net.Sockets.SocketAsyncEventArgs)"/>, etc.)
    /// — both would fight for readiness notifications.
    /// </para>
    /// </remarks>
    [UnsupportedOSPlatform("windows")]
    [UnsupportedOSPlatform("browser")]
    [UnsupportedOSPlatform("wasi")]
    public sealed class SafePollHandle : SafeHandle
    {
        private unsafe Interop.Sys.SocketEvent* _nativeBuffer;
        private int _nativeBufferCount;

        /// <summary>
        /// Gets a value indicating whether <see cref="SafePollHandle"/> is supported on the current platform.
        /// </summary>
        /// <value><see langword="true"/> on Linux, macOS, and FreeBSD; <see langword="false"/> on Windows, Browser, and WASI.</value>
        public static bool IsSupported => OperatingSystem.IsLinux() || OperatingSystem.IsMacOS() || OperatingSystem.IsFreeBSD();

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
            Interop.Sys.CloseSocketEventPort(h);

            return true;
        }

        /// <summary>
        /// Creates a new <see cref="SafePollHandle"/> backed by the platform's readiness polling mechanism.
        /// </summary>
        /// <param name="maxEventsPerWait">
        /// The maximum number of events that can be returned by a single <see cref="Wait"/> call.
        /// Determines the size of the internal native event buffer. Typical values: 64–1024.
        /// </param>
        /// <returns>A new <see cref="SafePollHandle"/>.</returns>
        /// <exception cref="PlatformNotSupportedException"><see cref="IsSupported"/> is <see langword="false"/>.</exception>
        /// <exception cref="InvalidOperationException">The kernel call to create the poll port failed.</exception>
        public static unsafe SafePollHandle Create(int maxEventsPerWait = 256)
        {
            if (!IsSupported)
            {
                throw new PlatformNotSupportedException(SR.net_sockets_platform_unsupported);
            }

            ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxEventsPerWait);

            var pollHandle = new SafePollHandle();

            try
            {
                IntPtr port;
                Interop.Error err = Interop.Sys.CreateSocketEventPort(&port);
                if (err != Interop.Error.SUCCESS)
                {
                    throw new InvalidOperationException($"Failed to create poll port: {err}");
                }

                pollHandle.SetHandle(port);

                Interop.Sys.SocketEvent* buffer;
                err = Interop.Sys.CreateSocketEventBuffer(maxEventsPerWait, &buffer);
                if (err != Interop.Error.SUCCESS)
                {
                    throw new InvalidOperationException($"Failed to create event buffer: {err}");
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
        /// Registers a handle for readiness monitoring.
        /// </summary>
        /// <param name="handle">The handle to monitor (typically a socket or pipe fd).</param>
        /// <param name="events">The events to monitor for.</param>
        /// <param name="options">
        /// Registration options. These are immutable for the lifetime of the registration —
        /// to change them, call <see cref="Remove"/> then <see cref="Add"/> again.
        /// </param>
        /// <param name="token">
        /// An opaque value echoed back in <see cref="PollNotification.Token"/> when events
        /// fire. Typically <c>(IntPtr)fd</c>, a <see cref="GCHandle"/>, or an index.
        /// </param>
        /// <exception cref="ObjectDisposedException">This <see cref="SafePollHandle"/> has been disposed.</exception>
        /// <exception cref="InvalidOperationException">The kernel registration call failed.</exception>
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
                    throw new InvalidOperationException($"Failed to add handle to poll: {err}");
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
        /// Registration options (e.g., <see cref="PollRegistrationOptions.ExclusiveWakeup"/>)
        /// cannot be changed — to change them, call <see cref="Remove"/> then <see cref="Add"/>.
        /// </summary>
        /// <param name="handle">The handle whose monitored events to change.</param>
        /// <param name="events">The new set of events to monitor for.</param>
        /// <param name="token">The token to associate with this handle (echoed back in notifications).</param>
        /// <exception cref="ObjectDisposedException">This <see cref="SafePollHandle"/> has been disposed.</exception>
        /// <exception cref="InvalidOperationException">The kernel modification call failed.</exception>
        public void Modify(SafeHandle handle, PollEvents events, IntPtr token)
        {
            ObjectDisposedException.ThrowIf(IsInvalid || IsClosed, this);
            ArgumentNullException.ThrowIfNull(handle);

            bool addedRef = false;
            try
            {
                handle.DangerousAddRef(ref addedRef);

                // Use the non-flags variant for Modify — flags are immutable at Add time.
                Interop.Error err = Interop.Sys.TryChangeSocketEventRegistration(
                    this.handle,
                    handle.DangerousGetHandle(),
                    currentEvents: -1,   // "any" — forces EPOLL_CTL_MOD path
                    newEvents: (int)events,
                    data: token);

                if (err != Interop.Error.SUCCESS)
                {
                    throw new InvalidOperationException($"Failed to modify handle in poll: {err}");
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

                Interop.Sys.TryChangeSocketEventRegistration(
                    this.handle,
                    handle.DangerousGetHandle(),
                    currentEvents: -1,   // "any" — forces removal
                    newEvents: (int)PollEvents.None,
                    data: IntPtr.Zero);

                // Ignore errors — the fd may already have been removed or closed.
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
        /// A buffer to receive the events. Up to <c>notifications.Length</c> events
        /// will be returned (capped by the <c>maxEventsPerWait</c> passed to <see cref="Create"/>).
        /// </param>
        /// <param name="timeoutMs">
        /// Timeout in milliseconds. <c>-1</c> for infinite wait; <c>0</c> for immediate (non-blocking) check.
        /// </param>
        /// <returns>The number of notifications written to <paramref name="notifications"/>. Zero on timeout.</returns>
        /// <exception cref="ObjectDisposedException">This <see cref="SafePollHandle"/> has been disposed.</exception>
        /// <exception cref="InvalidOperationException">The kernel wait call failed.</exception>
        public unsafe int Wait(Span<PollNotification> notifications, int timeoutMs)
        {
            ObjectDisposedException.ThrowIf(IsInvalid || IsClosed, this);

            int count = Math.Min(notifications.Length, _nativeBufferCount);
            if (count <= 0)
            {
                return 0;
            }

            Interop.Error err = Interop.Sys.WaitForSocketEventsWithTimeout(handle, _nativeBuffer, &count, timeoutMs);
            if (err != Interop.Error.SUCCESS)
            {
                throw new InvalidOperationException($"WaitForSocketEventsWithTimeout failed: {err}");
            }

            // Copy from the internal native-layout buffer into the public PollNotification span.
            for (int i = 0; i < count; i++)
            {
                notifications[i] = new PollNotification(
                    token: _nativeBuffer[i].Data,
                    events: (PollEvents)(int)_nativeBuffer[i].Events);
            }

            return count;
        }
    }
}
