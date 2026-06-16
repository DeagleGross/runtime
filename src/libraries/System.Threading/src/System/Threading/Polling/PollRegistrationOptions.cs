// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

namespace System.Threading
{
    /// <summary>
    /// Options for registering a handle with a <see cref="SafePollHandle"/>.
    /// These options are immutable for the lifetime of the registration — to
    /// change them, call <see cref="SafePollHandle.Remove"/> then
    /// <see cref="SafePollHandle.Add"/> again.
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
        /// <para>On Linux, maps to <c>EPOLLEXCLUSIVE</c> (Linux &gt;= 4.5).
        /// On macOS/FreeBSD (kqueue), this flag is silently ignored — kqueue
        /// naturally distributes events among waiters.</para>
        /// </summary>
        ExclusiveWakeup = 1,
    }
}
