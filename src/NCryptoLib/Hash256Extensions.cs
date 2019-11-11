using System;
using System.Collections.Generic;
using System.Text;

namespace NCryptoLib
{
    public static class Hash256Extensions
    {
        public static string ToHexString(this Hash256 hash)
        {
            return hash.Bytes.ToHexString();
        }

        public static Hash256 Set(this Hash256 hash, string hexHash)
        {
            hash.Bytes = hexHash.HexToBytes();
            return hash;
        }
    }
}
