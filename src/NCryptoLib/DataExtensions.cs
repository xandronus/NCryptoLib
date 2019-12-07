using NCryptoLib.Hasher;
using System;
using System.Collections.Generic;
using System.Text;

namespace NCryptoLib
{
    public static class DataExtensions
    {
        /// <summary>
        /// Computes a hash of an array of bytes
        /// </summary>
        /// <param name="data">array of bytes</param>
        /// <returns>the hash</returns>
        public static Hash256 Hash(this byte[] data)
        {
            if (data == null)
                throw new ArgumentException($"Invalid paramter to '{nameof(Hash)}'. Parameter '{nameof(data)}' cannot be null");
            MsftHasher hasher = new MsftHasher();
            return hasher.SHA256(data, 0, data.Length);
        }

        /// <summary>
        /// Computes a hash of an array of bytes
        /// </summary>
        /// <param name="data">array of bytes</param>
        /// <returns>the hash</returns>
        public static Hash256 Hash(this Span<byte> data)
        {
            MsftHasher hasher = new MsftHasher();
            return hasher.SHA256(data.ToArray(), 0, data.Length);
        }
    }
}
