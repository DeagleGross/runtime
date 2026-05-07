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
        /// <param name="token">The opaque token supplied to <see cref="SafePollHandle.Add"/>.</param>
        /// <param name="events">The readiness events that occurred.</param>
        public PollNotification(IntPtr token, PollEvents events)
        {
            Token = token;
            Events = events;
        }

        /// <summary>
        /// Gets the opaque token that was supplied when the handle was registered.
        /// Typically <c>(IntPtr)fd</c>, a <see cref="GCHandle"/>, or an index
        /// into a side table.
        /// </summary>
        public IntPtr Token { get; }

        /// <summary>
        /// Gets the readiness events that occurred on the registered handle.
        /// </summary>
        public PollEvents Events { get; }
    }
}
