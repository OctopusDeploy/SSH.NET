namespace Renci.SshNet.Security.Cryptography.InternalMD5
{
    internal class MD5HashProvider : HashProviderBase
    {
        private readonly byte[] _buffer;
        private int _bufferOffset;
        private long _byteCount;
        private int _h1, _h2, _h3, _h4;         // IV's

        /// <summary>
        /// The word buffer.
        /// </summary>
        private readonly int[] _x;
        private int _offset;

        /// <summary>
        /// Initializes a new instance of the <see cref="MD5HashProvider"/> class.
        /// </summary>
        public MD5HashProvider()
        {
            _buffer = new byte[4];
            _x = new int[16];

            InitializeHashValue();
        }

        /// <summary>
        /// Gets the size, in bits, of the computed hash code.
        /// </summary>
        /// <returns>
        /// The size, in bits, of the computed hash code.
        /// </returns>
        public override int HashSize
        {
            get
            {
                return 128;
            }
        }

        /// <summary>
        /// Gets the input block size.
        /// </summary>
        /// <returns>
        /// The input block size.
        /// </returns>
        public override int InputBlockSize
        {
            get
            {
                return 64;
            }
        }

        /// <summary>
        /// Gets the output block size.
        /// </summary>
        /// <returns>
        /// The output block size.
        /// </returns>
        public override int OutputBlockSize
        {
            get
            {
                return 64;
            }
        }

        /// <summary>
        /// Routes data written to the object into the hash algorithm for computing the hash.
        /// </summary>
        /// <param name="array">The input to compute the hash code for.</param>
        /// <param name="ibStart">The offset into the byte array from which to begin using data.</param>
        /// <param name="cbSize">The number of bytes in the byte array to use as data.</param>
        public override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            //  Fill the current word
            while ((_bufferOffset != 0) && (cbSize > 0))
            {
                Update(array[ibStart]);
                ibStart++;
                cbSize--;
            }

            //  Process whole words.
            while (cbSize > _buffer.Length)
            {
                ProcessWord(array, ibStart);

                ibStart += _buffer.Length;
                cbSize -= _buffer.Length;
                _byteCount += _buffer.Length;
            }

            //  Load in the remainder.
            while (cbSize > 0)
            {
                Update(array[ibStart]);

                ibStart++;
                cbSize--;
            }
        }

        /// <summary>
        /// Finalizes the hash computation after the last data is processed by the cryptographic stream object.
        /// </summary>
        /// <returns>
        /// The computed hash code.
        /// </returns>
        public override byte[] HashFinal()
        {
            var bitLength = (_byteCount << 3);

            //  Add the pad bytes.
            Update(128);

            while (_bufferOffset != 0)
                Update(0);

            if (_offset > 14)
            {
                ProcessBlock();
            }

            _x[14] = (int)(bitLength & 0xffffffff);
            _x[15] = (int)((ulong)bitLength >> 32);

            ProcessBlock();

            var output = new byte[16];

            UnpackWord(_h1, output, 0);
            UnpackWord(_h2, output, 4);
            UnpackWord(_h3, output, 8);
            UnpackWord(_h4, output, 12);

            return output;
        }

        /// <summary>
        /// Resets <see cref="MD5HashProvider"/> to its initial state.
        /// </summary>
        public override void Reset()
        {
            InitializeHashValue();

            _byteCount = 0;
            _bufferOffset = 0;
            for (var i = 0; i < 4; i++)
            {
                _buffer[i] = 0;
            }

            _offset = 0;
            for (var i = 0; i != _x.Length; i++)
            {
                _x[i] = 0;
            }
        }

        private void InitializeHashValue()
        {
            _h1 = 0x67452301;
            _h2 = unchecked((int)0xefcdab89);
            _h3 = unchecked((int)0x98badcfe);
            _h4 = 0x10325476;
        }

        private void Update(byte input)
        {
            _buffer[_bufferOffset++] = input;

            if (_bufferOffset == _buffer.Length)
            {
                ProcessWord(_buffer, 0);
                _bufferOffset = 0;
            }

            _byteCount++;
        }

        private void ProcessWord(byte[] input, int inOff)
        {
            _x[_offset++] = (input[inOff] & 0xff) | ((input[inOff + 1] & 0xff) << 8)
                            | ((input[inOff + 2] & 0xff) << 16) | ((input[inOff + 3] & 0xff) << 24);

            if (_offset == 16)
            {
                ProcessBlock();
            }
        }

        private static void UnpackWord(int word, byte[] outBytes, int outOff)
        {
            outBytes[outOff] = (byte)word;
            outBytes[outOff + 1] = (byte)((uint)word >> 8);
            outBytes[outOff + 2] = (byte)((uint)word >> 16);
            outBytes[outOff + 3] = (byte)((uint)word >> 24);
        }

        //
        // round 1 left rotates
        //
        private const int S11 = 7;
        private const int S12 = 12;
        private const int S13 = 17;
        private const int S14 = 22;

        //
        // round 2 left rotates
        //
        private const int S21 = 5;
        private const int S22 = 9;
        private const int S23 = 14;
        private const int S24 = 20;

        //
        // round 3 left rotates
        //
        private const int S31 = 4;
        private const int S32 = 11;
        private const int S33 = 16;
        private const int S34 = 23;

        //
        // round 4 left rotates
        //
        private const int S41 = 6;
        private const int S42 = 10;
        private const int S43 = 15;
        private const int S44 = 21;

        /*
        * rotate int x left n bits.
        */
        private static int RotateLeft(int x, int n)
        {
            return (x << n) | (int)((uint)x >> (32 - n));
        }

        /*
        * F, G, H and I are the basic MD5 functions.
        */
        private static int F(int u, int v, int w)
        {
            return (u & v) | (~u & w);
        }

        private static int G(int u, int v, int w)
        {
            return (u & w) | (v & ~w);
        }

        private static int H(int u, int v, int w)
        {
            return u ^ v ^ w;
        }

        private static int K(int u, int v, int w)
        {
            return v ^ (u | ~w);
        }

        private void ProcessBlock()
        {
            var a = _h1;
            var b = _h2;
            var c = _h3;
            var d = _h4;

            //
            // Round 1 - F cycle, 16 times.
            //
            a = RotateLeft(a + F(b, c, d) + _x[0] + unchecked((int)0xd76aa478), S11) + b;
            d = RotateLeft(d + F(a, b, c) + _x[1] + unchecked((int)0xe8c7b756), S12) + a;
            c = RotateLeft(c + F(d, a, b) + _x[2] + 0x242070db, S13) + d;
            b = RotateLeft(b + F(c, d, a) + _x[3] + unchecked((int)0xc1bdceee), S14) + c;
            a = RotateLeft(a + F(b, c, d) + _x[4] + unchecked((int)0xf57c0faf), S11) + b;
            d = RotateLeft(d + F(a, b, c) + _x[5] + 0x4787c62a, S12) + a;
            c = RotateLeft(c + F(d, a, b) + _x[6] + unchecked((int)0xa8304613), S13) + d;
            b = RotateLeft(b + F(c, d, a) + _x[7] + unchecked((int)0xfd469501), S14) + c;
            a = RotateLeft(a + F(b, c, d) + _x[8] + 0x698098d8, S11) + b;
            d = RotateLeft(d + F(a, b, c) + _x[9] + unchecked((int)0x8b44f7af), S12) + a;
            c = RotateLeft(c + F(d, a, b) + _x[10] + unchecked((int)0xffff5bb1), S13) + d;
            b = RotateLeft(b + F(c, d, a) + _x[11] + unchecked((int)0x895cd7be), S14) + c;
            a = RotateLeft(a + F(b, c, d) + _x[12] + 0x6b901122, S11) + b;
            d = RotateLeft(d + F(a, b, c) + _x[13] + unchecked((int)0xfd987193), S12) + a;
            c = RotateLeft(c + F(d, a, b) + _x[14] + unchecked((int)0xa679438e), S13) + d;
            b = RotateLeft(b + F(c, d, a) + _x[15] + 0x49b40821, S14) + c;

            //
            // Round 2 - G cycle, 16 times.
            //
            a = RotateLeft(a + G(b, c, d) + _x[1] + unchecked((int)0xf61e2562), S21) + b;
            d = RotateLeft(d + G(a, b, c) + _x[6] + unchecked((int)0xc040b340), S22) + a;
            c = RotateLeft(c + G(d, a, b) + _x[11] + 0x265e5a51, S23) + d;
            b = RotateLeft(b + G(c, d, a) + _x[0] + unchecked((int)0xe9b6c7aa), S24) + c;
            a = RotateLeft(a + G(b, c, d) + _x[5] + unchecked((int)0xd62f105d), S21) + b;
            d = RotateLeft(d + G(a, b, c) + _x[10] + 0x02441453, S22) + a;
            c = RotateLeft(c + G(d, a, b) + _x[15] + unchecked((int)0xd8a1e681), S23) + d;
            b = RotateLeft(b + G(c, d, a) + _x[4] + unchecked((int)0xe7d3fbc8), S24) + c;
            a = RotateLeft(a + G(b, c, d) + _x[9] + 0x21e1cde6, S21) + b;
            d = RotateLeft(d + G(a, b, c) + _x[14] + unchecked((int)0xc33707d6), S22) + a;
            c = RotateLeft(c + G(d, a, b) + _x[3] + unchecked((int)0xf4d50d87), S23) + d;
            b = RotateLeft(b + G(c, d, a) + _x[8] + 0x455a14ed, S24) + c;
            a = RotateLeft(a + G(b, c, d) + _x[13] + unchecked((int)0xa9e3e905), S21) + b;
            d = RotateLeft(d + G(a, b, c) + _x[2] + unchecked((int)0xfcefa3f8), S22) + a;
            c = RotateLeft(c + G(d, a, b) + _x[7] + 0x676f02d9, S23) + d;
            b = RotateLeft(b + G(c, d, a) + _x[12] + unchecked((int)0x8d2a4c8a), S24) + c;

            //
            // Round 3 - H cycle, 16 times.
            //
            a = RotateLeft(a + H(b, c, d) + _x[5] + unchecked((int)0xfffa3942), S31) + b;
            d = RotateLeft(d + H(a, b, c) + _x[8] + unchecked((int)0x8771f681), S32) + a;
            c = RotateLeft(c + H(d, a, b) + _x[11] + 0x6d9d6122, S33) + d;
            b = RotateLeft(b + H(c, d, a) + _x[14] + unchecked((int)0xfde5380c), S34) + c;
            a = RotateLeft(a + H(b, c, d) + _x[1] + unchecked((int)0xa4beea44), S31) + b;
            d = RotateLeft(d + H(a, b, c) + _x[4] + 0x4bdecfa9, S32) + a;
            c = RotateLeft(c + H(d, a, b) + _x[7] + unchecked((int)0xf6bb4b60), S33) + d;
            b = RotateLeft(b + H(c, d, a) + _x[10] + unchecked((int)0xbebfbc70), S34) + c;
            a = RotateLeft(a + H(b, c, d) + _x[13] + 0x289b7ec6, S31) + b;
            d = RotateLeft(d + H(a, b, c) + _x[0] + unchecked((int)0xeaa127fa), S32) + a;
            c = RotateLeft(c + H(d, a, b) + _x[3] + unchecked((int)0xd4ef3085), S33) + d;
            b = RotateLeft(b + H(c, d, a) + _x[6] + 0x04881d05, S34) + c;
            a = RotateLeft(a + H(b, c, d) + _x[9] + unchecked((int)0xd9d4d039), S31) + b;
            d = RotateLeft(d + H(a, b, c) + _x[12] + unchecked((int)0xe6db99e5), S32) + a;
            c = RotateLeft(c + H(d, a, b) + _x[15] + 0x1fa27cf8, S33) + d;
            b = RotateLeft(b + H(c, d, a) + _x[2] + unchecked((int)0xc4ac5665), S34) + c;

            //
            // Round 4 - K cycle, 16 times.
            //
            a = RotateLeft(a + K(b, c, d) + _x[0] + unchecked((int)0xf4292244), S41) + b;
            d = RotateLeft(d + K(a, b, c) + _x[7] + 0x432aff97, S42) + a;
            c = RotateLeft(c + K(d, a, b) + _x[14] + unchecked((int)0xab9423a7), S43) + d;
            b = RotateLeft(b + K(c, d, a) + _x[5] + unchecked((int)0xfc93a039), S44) + c;
            a = RotateLeft(a + K(b, c, d) + _x[12] + 0x655b59c3, S41) + b;
            d = RotateLeft(d + K(a, b, c) + _x[3] + unchecked((int)0x8f0ccc92), S42) + a;
            c = RotateLeft(c + K(d, a, b) + _x[10] + unchecked((int)0xffeff47d), S43) + d;
            b = RotateLeft(b + K(c, d, a) + _x[1] + unchecked((int)0x85845dd1), S44) + c;
            a = RotateLeft(a + K(b, c, d) + _x[8] + 0x6fa87e4f, S41) + b;
            d = RotateLeft(d + K(a, b, c) + _x[15] + unchecked((int)0xfe2ce6e0), S42) + a;
            c = RotateLeft(c + K(d, a, b) + _x[6] + unchecked((int)0xa3014314), S43) + d;
            b = RotateLeft(b + K(c, d, a) + _x[13] + 0x4e0811a1, S44) + c;
            a = RotateLeft(a + K(b, c, d) + _x[4] + unchecked((int)0xf7537e82), S41) + b;
            d = RotateLeft(d + K(a, b, c) + _x[11] + unchecked((int)0xbd3af235), S42) + a;
            c = RotateLeft(c + K(d, a, b) + _x[2] + 0x2ad7d2bb, S43) + d;
            b = RotateLeft(b + K(c, d, a) + _x[9] + unchecked((int)0xeb86d391), S44) + c;

            _h1 += a;
            _h2 += b;
            _h3 += c;
            _h4 += d;

            //
            // reset the offset and clean out the word buffer.
            //
            _offset = 0;
            for (var i = 0; i != _x.Length; i++)
            {
                _x[i] = 0;
            }
        }
    }
}