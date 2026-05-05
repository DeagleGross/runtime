// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

namespace System.Threading
{
    /// <summary>
    /// Specifies the readiness events to monitor for a handle registered with a <see cref="SafePollHandle"/>.
    /// </summary>
    [Flags]
    public enum PollEvents : int
    {
        /// <summary>No events.</summary>
        None = 0x00,

        /// <summary>The handle is ready for reading.</summary>
        Read = 0x01,

        /// <summary>The handle is ready for writing.</summary>
        Write = 0x02,

        /// <summary>The remote end has closed its write side (half-close / EOF).</summary>
        ReadClose = 0x04,

        /// <summary>The handle has been closed.</summary>
        Close = 0x08,

        /// <summary>An error has occurred on the handle.</summary>
        Error = 0x10,
    }
}
