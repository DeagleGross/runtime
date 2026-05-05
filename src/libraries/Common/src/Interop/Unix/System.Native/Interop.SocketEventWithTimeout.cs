// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class Sys
    {
        [LibraryImport(Libraries.SystemNative, EntryPoint = "SystemNative_WaitForSocketEventsWithTimeout")]
        internal static unsafe partial Error WaitForSocketEventsWithTimeout(IntPtr port, SocketEvent* buffer, int* count, int timeoutMs);

        [LibraryImport(Libraries.SystemNative, EntryPoint = "SystemNative_TryChangeSocketEventRegistrationWithFlags")]
        internal static partial Error TryChangeSocketEventRegistrationWithFlags(IntPtr port, IntPtr socket, int currentEvents, int newEvents, IntPtr data, int flags);
    }
}
