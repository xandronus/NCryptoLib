﻿using NCryptoLib.Hasher;
using System;
using System.Collections.Generic;
using System.Text;

namespace NCryptoLib
{
    public static class Hash256Extensions
    {
        /// <summary>
        /// Converts a hash to a hex in a string representation
        /// </summary>
        /// <param name="hash">the hash to convert</param>
        /// <returns>the hash in hex</returns>
        public static string ToHexString(this Hash256 hash)
        {
            return hash.Bytes.ToHexString();
        }

        /// <summary>
        /// Sets a hash from a hex hash in a string representation
        /// </summary>
        /// <param name="hash">input hash</param>
        /// <param name="hexHash">hash hex value as a string</param>
        /// <returns>the hash</returns>
        public static Hash256 Set(this Hash256 hash, string hexHash)
        {
            hash.Bytes = hexHash.HexToBytes();
            return hash;
        }

        /// <summary>
        /// Peforms a RIPEMD160 hash on the hash
        /// </summary>
        /// <param name="hash">input hash</param>
        /// <returns>RIPEMD160 hash of the hash</returns>
        public static Hash160 RIPEMD160(this Hash256 hash)
        {
            MsftHasher hasher = new MsftHasher();
            return hasher.RIPEMD160(hash);
        }
    }
}
