using System;
using System.Collections.Generic;
using System.Text;

namespace NCryptoLib
{
    public static class Hash160Extensions
    {
        /// <summary>
        /// Converts a hash to a hex in a string representation
        /// </summary>
        /// <param name="hash">the hash to convert</param>
        /// <returns>the hash in hex</returns>
        public static string ToHexString(this Hash160 hash)
        {
            return hash.Bytes.ToHexString();
        }

        /// <summary>
        /// Sets a hash from a hex hash in a string representation
        /// </summary>
        /// <param name="hash">input hash</param>
        /// <param name="hexHash">hash hex value as a string</param>
        /// <returns>the hash</returns>
        public static Hash160 Set(this Hash160 hash, string hexHash)
        {
            hash.Bytes = hexHash.HexToBytes();
            return hash;
        }

        /// <summary>
        /// Calculates Bitcoin P2PKH address given public key hash and network version bytes
        /// </summary>
        /// <param name="hash">public key hash</param>
        /// <param name="versionBytes">version bytes of network</param>
        /// <returns>base58check address</returns>
        public static string ToP2PKHAddress(this Hash160 hash, Span<byte> versionBytes)
        {
            // TODO: Write base58check encoder
            return null;
        }
    }
}
