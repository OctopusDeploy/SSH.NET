using System;
using Renci.SshNet.Abstractions;
using Renci.SshNet.Security;

namespace Renci.SshNet.Common
{
    /// <summary>
    /// Provides data for the HostKeyReceived event.
    /// </summary>
    public class HostKeyEventArgs : EventArgs
    {
        private byte[] _fingerPrint;

        private byte[] _fingerPrintSha256;

        /// <summary>
        /// Gets or sets a value indicating whether host key can be trusted.
        /// </summary>
        /// <value>
        ///   <c>true</c> if host key can be trusted; otherwise, <c>false</c>.
        /// </value>
        public bool CanTrust { get; set; }

        /// <summary>
        /// Gets the host key.
        /// </summary>
        public byte[] HostKey { get; private set; }

        /// <summary>
        /// Gets the host key name.
        /// </summary>
        public string HostKeyName{ get; private set; }

        /// <summary>
        /// Gets the finger print.
        /// </summary>
        public byte[] FingerPrint
        {
            get
            {
                if (_fingerPrint == null)
                {
                    using (var md5 = CryptoAbstraction.CreateMD5())
                    {
                        _fingerPrint = md5.ComputeHash(HostKey);
                    }
                }
                return _fingerPrint;
            }
        }

        /// <summary>
        /// Gets the SHA256 finger print.
        /// </summary>
        public byte[] FingerPrintSHA256
        {
            get
            {
                if (_fingerPrintSha256 == null)
                {
                    using (var sha = CryptoAbstraction.CreateSHA256())
                    {
                        _fingerPrintSha256 = sha.ComputeHash(HostKey);
                    }
                }
                return _fingerPrintSha256;
            }
        }

        /// <summary>
        /// Gets the length of the key in bits.
        /// </summary>
        /// <value>
        /// The length of the key in bits.
        /// </value>
        public int KeyLength { get; private set; }

        /// <summary>
        /// Initializes a new instance of the <see cref="HostKeyEventArgs"/> class.
        /// </summary>
        /// <param name="host">The host.</param>
        public HostKeyEventArgs(KeyHostAlgorithm host)
        {
            CanTrust = true;   //  Set default value

            HostKey = host.Data;

            HostKeyName = host.Name;

            KeyLength = host.Key.KeyLength;
        }
    }
}
