// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

namespace System.Threading
{
    /// <summary>
    /// Describes why a <see cref="SafePollHandle"/> registration operation failed.
    /// </summary>
    public enum PollError
    {
        /// <summary>The operation succeeded.</summary>
        None = 0,

        /// <summary>The file descriptor is invalid or closed.</summary>
        BadFileDescriptor,

        /// <summary>The file descriptor is already registered with this poll handle.</summary>
        AlreadyExists,

        /// <summary>The file descriptor was not found (e.g., <see cref="SafePollHandle.TryModify"/> on an unregistered handle).</summary>
        NotFound,

        /// <summary>The caller does not have permission to monitor this file descriptor.</summary>
        PermissionDenied,

        /// <summary>The system has insufficient resources (e.g., too many registered fds).</summary>
        OutOfResources,

        /// <summary>An invalid argument was passed to the kernel.</summary>
        InvalidArgument,

        /// <summary>An unrecognized error occurred. Use the exception-throwing overload for details.</summary>
        Unknown,
    }
}
