using System;

namespace Renci.SshNet.Security.Cryptography.InternalMD5
{
    internal abstract class HashProviderBase : IHashProvider
    {
        private bool _disposed;
        private byte[] _hashValue;

        /// <summary>
        /// Gets the value of the computed hash code.
        /// </summary>
        /// <value>
        /// The current value of the computed hash code.
        /// </value>
        /// <exception cref="ObjectDisposedException">The object has already been disposed.</exception>
        public byte[] Hash
        {
            get
            {
                if (_disposed)
                    throw new ObjectDisposedException(GetType().FullName);
                return (byte[])_hashValue.Clone();
            }
        }

        /// <summary>
        /// Computes the hash value for the specified region of the input byte array and copies the specified
        /// region of the input byte array to the specified region of the output byte array.
        /// </summary>
        /// <param name="inputBuffer">The input to compute the hash code for.</param>
        /// <param name="inputOffset">The offset into the input byte array from which to begin using data.</param>
        /// <param name="inputCount">The number of bytes in the input byte array to use as data.</param>
        /// <param name="outputBuffer">A copy of the part of the input array used to compute the hash code.</param>
        /// <param name="outputOffset">The offset into the output byte array from which to begin writing data.</param>
        /// <returns>
        /// The number of bytes written.
        /// </returns>
        /// <exception cref="ArgumentException">
        /// <para><paramref name="inputCount"/> uses an invalid value.</para>
        /// <para>-or-</para>
        /// <para><paramref name="inputBuffer"/> has an invalid length.</para>
        /// </exception>
        /// <exception cref="ArgumentNullException"><paramref name="inputBuffer"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentOutOfRangeException"><paramref name="inputOffset"/> is out of range. This parameter requires a non-negative number.</exception>
        /// <exception cref="ObjectDisposedException">The object has already been disposed.</exception>
        public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
        {
            if (_disposed)
                throw new ObjectDisposedException(GetType().FullName);
            if (inputBuffer == null)
                throw new ArgumentNullException("inputBuffer");
            if (inputOffset < 0)
                throw new ArgumentOutOfRangeException("inputOffset");
            if (inputCount < 0 || (inputCount > inputBuffer.Length))
                throw new ArgumentException("XX");
            if ((inputBuffer.Length - inputCount) < inputOffset)
                throw new ArgumentException("xx");

            HashCore(inputBuffer, inputOffset, inputCount);

            // todo: optimize this by taking into account that inputBuffer and outputBuffer can be the same
            Buffer.BlockCopy(inputBuffer, inputOffset, outputBuffer, outputOffset, inputCount);
            return inputCount;
        }

        /// <summary>
        /// Computes the hash value for the specified region of the specified byte array.
        /// </summary>
        /// <param name="inputBuffer">The input to compute the hash code for.</param>
        /// <param name="inputOffset">The offset into the byte array from which to begin using data.</param>
        /// <param name="inputCount">The number of bytes in the byte array to use as data.</param>
        /// <returns>
        /// An array that is a copy of the part of the input that is hashed.
        /// </returns>
        /// <exception cref="ArgumentException">
        /// <para><paramref name="inputCount"/> uses an invalid value.</para>
        /// <para>-or-</para>
        /// <para><paramref name="inputBuffer"/> has an invalid length.</para>
        /// </exception>
        /// <exception cref="ArgumentNullException"><paramref name="inputBuffer"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentOutOfRangeException"><paramref name="inputOffset"/> is out of range. This parameter requires a non-negative number.</exception>
        /// <exception cref="ObjectDisposedException">The object has already been disposed.</exception>
        public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
        {
            if (_disposed)
                throw new ObjectDisposedException(GetType().FullName);
            if (inputBuffer == null)
                throw new ArgumentNullException("inputBuffer");
            if (inputOffset < 0)
                throw new ArgumentOutOfRangeException("inputOffset");
            if (inputCount < 0 || (inputCount > inputBuffer.Length))
                throw new ArgumentException("XX");
            if ((inputBuffer.Length - inputCount) < inputOffset)
                throw new ArgumentException("xx");

            HashCore(inputBuffer, inputOffset, inputCount);
            _hashValue = HashFinal();

            // from the MSDN docs:
            // the return value of this method is not the hash value, but only a copy of the hashed part of the input data
            var outputBytes = new byte[inputCount];
            Buffer.BlockCopy(inputBuffer, inputOffset, outputBytes, 0, inputCount);
            return outputBytes;
        }

        /// <summary>
        /// Computes the hash value for the input data.
        /// </summary>
        /// <param name="buffer">The input to compute the hash code for.</param>
        /// <returns>
        /// The computed hash code.
        /// </returns>
        /// <exception cref="ArgumentNullException"><paramref name="buffer"/> is <c>null</c>.</exception>
        /// <exception cref="ObjectDisposedException">The object has already been disposed.</exception>
        public byte[] ComputeHash(byte[] buffer)
        {
            if (_disposed)
                throw new ObjectDisposedException(GetType().FullName);
            if (buffer == null)
                throw new ArgumentNullException("buffer");

            HashCore(buffer, 0, buffer.Length);
            _hashValue = HashFinal();
            Reset();
            return Hash;
        }

        /// <summary>
        /// Releases all resources used by the current instance of the <see cref="HashProviderBase"/> class.
        /// </summary>
        public void Dispose()
        {
            GC.SuppressFinalize(this);
            Dispose(true);
        }

        /// <summary>
        /// Releases the unmanaged resources used by the <see cref="HashProviderBase"/> and optionally releases the managed resources.
        /// </summary>
        /// <param name="disposing"><c>true</c> to release both managed and unmanaged resources; <c>false</c> to release only unmanaged resources.</param>
        protected virtual void Dispose(bool disposing)
        {
            if (disposing)
            {
                _hashValue = null;
            }

            _disposed = true;
        }

        /// <summary>
        /// Gets the size, in bits, of the computed hash code.
        /// </summary>
        /// <returns>
        /// The size, in bits, of the computed hash code.
        /// </returns>
        public abstract int HashSize { get; }

        /// <summary>
        /// Gets the input block size.
        /// </summary>
        /// <returns>
        /// The input block size.
        /// </returns>
        public abstract int InputBlockSize { get; }

        /// <summary>
        /// Gets the output block size.
        /// </summary>
        /// <returns>
        /// The output block size.
        /// </returns>
        public abstract int OutputBlockSize { get; }

        /// <summary>
        /// Resets an implementation of <see cref="HashProviderBase"/> to its initial state.
        /// </summary>
        public abstract void Reset();

        /// <summary>
        /// Routes data written to the object into the hash algorithm for computing the hash.
        /// </summary>
        /// <param name="array">The input to compute the hash code for.</param>
        /// <param name="ibStart">The offset into the byte array from which to begin using data.</param>
        /// <param name="cbSize">The number of bytes in the byte array to use as data.</param>
        public abstract void HashCore(byte[] array, int ibStart, int cbSize);

        /// <summary>
        /// Finalizes the hash computation after the last data is processed by the cryptographic stream object.
        /// </summary>
        /// <returns>
        /// The computed hash code.
        /// </returns>
        public abstract byte[] HashFinal();
    }
}