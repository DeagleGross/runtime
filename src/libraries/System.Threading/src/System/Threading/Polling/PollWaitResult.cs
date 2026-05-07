// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

namespace System.Threading
{
    /// <summary>
    /// The result of a <see cref="SafePollHandle.Wait"/> call. Provides
    /// zero-copy access to the readiness notifications by reading directly
    /// from the internal native event buffer.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This is a <see langword="ref struct"/> — it cannot escape to the heap,
    /// be stored in fields, or be captured by async methods. This enforces
    /// the lifetime constraint: the result is only valid until the next call
    /// to <see cref="SafePollHandle.Wait"/> on the same handle.
    /// </para>
    /// </remarks>
    public unsafe ref struct PollWaitResult
    {
        private readonly Interop.Sys.SocketEvent* _buffer;
        private readonly int _count;

        internal PollWaitResult(Interop.Sys.SocketEvent* buffer, int count)
        {
            _buffer = buffer;
            _count = count;
        }

        /// <summary>Gets the number of notifications in this result.</summary>
        public int Count => _count;

        /// <summary>Gets the notification at the specified index.</summary>
        /// <param name="index">The zero-based index of the notification.</param>
        /// <returns>The notification, translated from the native event format.</returns>
        /// <exception cref="ArgumentOutOfRangeException"><paramref name="index"/> is out of range.</exception>
        public PollNotification this[int index]
        {
            get
            {
                ArgumentOutOfRangeException.ThrowIfNegative(index);
                ArgumentOutOfRangeException.ThrowIfGreaterThanOrEqual(index, _count);

                return new PollNotification(
                    state: _buffer[index].Data,
                    events: (PollEvents)(int)_buffer[index].Events);
            }
        }

        /// <summary>Returns an enumerator that iterates through the notifications.</summary>
        public Enumerator GetEnumerator() => new Enumerator(_buffer, _count);

        /// <summary>Enumerates readiness notifications with zero copy from the native buffer.</summary>
        public ref struct Enumerator
        {
            private readonly Interop.Sys.SocketEvent* _buffer;
            private readonly int _count;
            private int _index;

            internal Enumerator(Interop.Sys.SocketEvent* buffer, int count)
            {
                _buffer = buffer;
                _count = count;
                _index = -1;
            }

            /// <summary>Gets the current notification.</summary>
            public PollNotification Current
            {
                get
                {
                    return new PollNotification(
                        state: _buffer[_index].Data,
                        events: (PollEvents)(int)_buffer[_index].Events);
                }
            }

            /// <summary>Advances the enumerator to the next notification.</summary>
            /// <returns><see langword="true"/> if there are more notifications; otherwise <see langword="false"/>.</returns>
            public bool MoveNext()
            {
                int next = _index + 1;
                if (next < _count)
                {
                    _index = next;
                    return true;
                }

                return false;
            }
        }
    }
}
