// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

namespace System.Threading
{
    /// <summary>
    /// Options for registering a handle with a <see cref="SafePollHandle"/>.
    /// These options are immutable once a handle is registered — to change them,
    /// remove the handle and re-add it.
    /// </summary>
    [Flags]
    public enum PollRegistrationOptions
    {
        /// <summary>No special options. Level-triggered notifications.</summary>
        None = 0,

        /// <summary>
        /// Only one poll handle wakes per event on the registered handle.
        /// Intended for shared listen sockets where multiple workers each own
        /// a <see cref="SafePollHandle"/> and register the same listen socket.
        /// The kernel picks one to wake, preventing thundering herd.
        /// <para>Supported on Linux (epoll <c>EPOLLEXCLUSIVE</c>). On platforms
        /// where this is not supported, it is silently ignored.</para>
        /// </summary>
        ExclusiveWakeup = 1,
    }
}
