// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Runtime.InteropServices;

namespace System.Threading
{
    /// <summary>
    /// Represents a single readiness notification returned by
    /// <see cref="SafePollHandle.Wait"/>.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public readonly struct PollNotification
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="PollNotification"/> struct.
        /// </summary>
        /// <param name="state">The opaque state supplied to <see cref="SafePollHandle.Add"/>.</param>
        /// <param name="events">The readiness events that occurred.</param>
        public PollNotification(nint state, PollEvents events)
        {
            State = state;
            Events = events;
        }

        /// <summary>
        /// Gets the opaque state that was supplied when the handle was registered.
        /// Typically <c>(IntPtr)fd</c>, a <see cref="GCHandle"/>, or an index
        /// into a side table.
        /// </summary>
        public nint State { get; }

        /// <summary>
        /// Gets the readiness events that occurred on the registered handle.
        /// </summary>
        public PollEvents Events { get; }
    }
}
