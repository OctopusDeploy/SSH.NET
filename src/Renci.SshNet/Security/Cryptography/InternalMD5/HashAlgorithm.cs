using System;
using System.IO;

namespace Renci.SshNet.Security.Cryptography.InternalMD5
{
    /// <summary>
    /// Represents the base class from which all implementations of cryptographic
    /// hash algorithms must derive.
    /// </summary>
    public abstract class HashAlgorithm : IDisposable
    {
        /// <summary>
        /// Gets the size, in bits, of the computed hash code.
        /// </summary>
        /// <returns>
        /// The size, in bits, of the computed hash code.
        /// </returns>
        public virtual int HashSize
        {
            get
            {
                return 0;  // For desktop compatibility, return 0 as this property was always initialized by a subclass.
            }
        }

        /// <summary>
        /// Gets the input block size.
        /// </summary>
        /// <returns>
        /// The input block size.
        /// </returns>
        public virtual int InputBlockSize
        {
            get { return 0; }
        }

        /// <summary>
        /// Gets the output block size.
        /// </summary>
        /// <returns>
        /// The output block size.
        /// </returns>
        public virtual int OutputBlockSize
        {
            get { return 0; }
        }

        /// <summary>
        /// Gets a value indicating whether the current transform can be reused.
        /// </summary>
        /// <returns>
        /// Always true.
        /// </returns>
        public virtual bool CanReuseTransform
        {
            get { return true; }
        }

        /// <summary>
        /// Gets a value indicating whether multiple blocks can be transformed.
        /// </summary>
        /// <returns>
        /// true if multiple blocks can be transformed; otherwise, false.
        /// </returns>
        public virtual bool CanTransformMultipleBlocks
        {
            get { return true; }
        }

        /// <summary>
        /// Computes the hash value for the specified byte array.
        /// </summary>
        /// <param name="buffer">The input to compute the hash code for. </param>
        /// <returns>
        /// The computed hash code.
        /// </returns>
        /// <exception cref="ArgumentNullException"><paramref name="buffer"/> is <c>null</c>.</exception>
        /// <exception cref="ObjectDisposedException">The object has already been disposed.</exception>
        public byte[] ComputeHash(byte[] buffer)
        {
            if (_disposed)
                throw new ObjectDisposedException(null);
            if (buffer == null)
                throw new ArgumentNullException("buffer");

            HashCore(buffer, 0, buffer.Length);
            return CaptureHashCodeAndReinitialize();
        }

        /// <summary>
        /// Computes the hash value for the specified region of the specified byte array.
        /// </summary>
        /// <param name="buffer">The input to compute the hash code for.</param>
        /// <param name="offset">The offset into the byte array from which to begin using data.</param>
        /// <param name="count">The number of bytes in the array to use as data.</param>
        /// <returns>
        /// The computed hash code.
        /// </returns>
        /// <exception cref="ArgumentException">
        /// <para><paramref name="count"/> is an invalid value.</para>
        /// <para>-or-</para>
        /// <para><paramref name="buffer"/> length is invalid.</para>
        /// </exception>
        /// <exception cref="ArgumentOutOfRangeException"><paramref name="offset"/> is out of range. This parameter requires a non-negative number.</exception>
        /// <exception cref="ArgumentNullException"><paramref name="buffer"/> is <c>null</c>.</exception>
        /// <exception cref="ObjectDisposedException">The object has already been disposed.</exception>
        public byte[] ComputeHash(byte[] buffer, int offset, int count)
        {
            if (buffer == null)
                throw new ArgumentNullException("buffer");
            if (offset < 0)
                throw new ArgumentOutOfRangeException("offset", "Non-negative number required.");
            if (count < 0 || (count > buffer.Length))
                throw new ArgumentException("Value was invalid.");
            if ((buffer.Length - count) < offset)
                throw new ArgumentException("Offset and length were out of bounds for the array or count is greater than the number of elements from index to the end of the source collection.");

            if (_disposed)
                throw new ObjectDisposedException(null);

            HashCore(buffer, offset, count);
            return CaptureHashCodeAndReinitialize();
        }

        /// <summary>
        /// Computes the hash value for the specified <see cref="Stream"/> object.
        /// </summary>
        /// <param name="inputStream">The input to compute the hash code for.</param>
        /// <returns>
        /// The computed hash code.
        /// </returns>
        /// <exception cref="ObjectDisposedException">The object has already been disposed.</exception>
        public byte[] ComputeHash(Stream inputStream)
        {
            if (_disposed)
                throw new ObjectDisposedException(null);

            // Default the buffer size to 4K.
            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = inputStream.Read(buffer, 0, buffer.Length)) > 0)
            {
                HashCore(buffer, 0, bytesRead);
            }
            return CaptureHashCodeAndReinitialize();
        }

        private byte[] CaptureHashCodeAndReinitialize()
        {
            byte[] hashValue = HashFinal();
            // Clone the hash value prior to invoking Initialize in case the user-defined Initialize
            // manipulates the array.
            _hashValue = hashValue = (byte[])hashValue.Clone();
            Initialize();
            return hashValue;
        }

        /// <summary>
        /// Releases all resources used by the current instance of the <see cref="HashAlgorithm"/> class.
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Releases the unmanaged resources used by the <see cref="HashAlgorithm"/> and optionally releases the managed resources.
        /// </summary>
        /// <param name="disposing"><c>true</c> to release both managed and unmanaged resources; <c>false</c> to release only unmanaged resources.</param>
        protected virtual void Dispose(bool disposing)
        {
            if (disposing)
            {
                // Although we don't have any resources to dispose at this level,
                // we need to continue to throw ObjectDisposedExceptions from CalculateHash
                // for compatibility with the desktop framework.
                _disposed = true;
            }
        }

        /// <summary>
        /// Routes data written to the object into the hash algorithm for computing the hash.
        /// </summary>
        /// <param name="array">The input to compute the hash code for.</param>
        /// <param name="ibStart">The offset into the byte array from which to begin using data.</param>
        /// <param name="cbSize">The number of bytes in the byte array to use as data.</param>
        protected abstract void HashCore(byte[] array, int ibStart, int cbSize);

        /// <summary>
        /// Finalizes the hash computation after the last data is processed by the cryptographic stream object.
        /// </summary>
        /// <returns>
        /// The computed hash code.
        /// </returns>
        protected abstract byte[] HashFinal();

        /// <summary>
        /// Initializes an implementation of the <see cref="HashAlgorithm"/> class.
        /// </summary>
        public abstract void Initialize();

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

        private byte[] _hashValue;

        private bool _disposed;
    }
}