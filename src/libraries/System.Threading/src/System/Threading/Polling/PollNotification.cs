// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Runtime.InteropServices;

namespace System.Threading
{
    /// <summary>
    /// Represents a single readiness notification returned by
    /// <see cref="SafePollHandle.Wait"/>.
    /// </summary>
    /// <remarks>
    /// The memory layout is identical to the internal <c>Interop.Sys.SocketEvent</c>
    /// struct, enabling zero-copy access to the native event buffer via
    /// <see cref="ReadOnlySpan{T}"/>.
    /// </remarks>
    [StructLayout(LayoutKind.Sequential)]
    public readonly struct PollNotification
    {
        private readonly nint _data;
        private readonly PollEvents _events;
        private readonly int _padding;

        /// <summary>
        /// Initializes a new instance of the <see cref="PollNotification"/> struct.
        /// </summary>
        /// <param name="state">The opaque state supplied to <see cref="SafePollHandle.TryAdd"/>.</param>
        /// <param name="events">The readiness events that occurred.</param>
        public PollNotification(nint state, PollEvents events)
        {
            _data = state;
            _events = events;
        }

        /// <summary>
        /// Gets the opaque state that was supplied when the handle was registered.
        /// Typically a <see cref="GCHandle"/> value, a small integer index into
        /// a side table, or a raw file descriptor.
        /// </summary>
        public nint State => _data;

        /// <summary>
        /// Gets the readiness events that occurred on the registered handle.
        /// </summary>
        public PollEvents Events => _events;
    }
}
