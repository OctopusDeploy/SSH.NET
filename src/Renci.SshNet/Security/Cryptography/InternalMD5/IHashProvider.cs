using System;

namespace Renci.SshNet.Security.Cryptography.InternalMD5
{
    internal interface IHashProvider : IDisposable
    {
        /// <summary>
        /// Gets the size, in bits, of the computed hash code.
        /// </summary>
        /// <returns>
        /// The size, in bits, of the computed hash code.
        /// </returns>
        int HashSize { get; }

        /// <summary>
        /// Gets the input block size.
        /// </summary>
        /// <returns>
        /// The input block size.
        /// </returns>
        int InputBlockSize { get; }

        /// <summary>
        /// Gets the output block size.
        /// </summary>
        /// <returns>
        /// The output block size.
        /// </returns>
        int OutputBlockSize { get; }

        /// <summary>
        /// Gets the value of the computed hash code.
        /// </summary>
        /// <value>
        /// The current value of the computed hash code.
        /// </value>
        /// <exception cref="ObjectDisposedException">The object has already been disposed.</exception>
        byte[] Hash { get; }

        /// <summary>
        /// Resets an implementation of the <see cref="IHashProvider"/> to its initial state.
        /// </summary>
        void Reset();

        /// <summary>
        /// Routes data written to the object into the hash algorithm for computing the hash.
        /// </summary>
        /// <param name="array">The input to compute the hash code for.</param>
        /// <param name="ibStart">The offset into the byte array from which to begin using data.</param>
        /// <param name="cbSize">The number of bytes in the byte array to use as data.</param>
        void HashCore(byte[] array, int ibStart, int cbSize);

        /// <summary>
        /// Finalizes the hash computation after the last data is processed by the cryptographic stream object.
        /// </summary>
        /// <returns>
        /// The computed hash code.
        /// </returns>
        byte[] HashFinal();

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
        int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset);

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
        byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount);

        /// <summary>
        /// Computes the hash value for the input data.
        /// </summary>
        /// <param name="buffer">The input to compute the hash code for.</param>
        /// <returns>
        /// The computed hash code.
        /// </returns>
        /// <exception cref="ArgumentNullException"><paramref name="buffer"/> is <c>null</c>.</exception>
        /// <exception cref="ObjectDisposedException">The object has already been disposed.</exception>
        byte[] ComputeHash(byte[] buffer);
    }
}