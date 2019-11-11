using NCryptoLib.Hasher;
using System;
using System.Collections.Generic;
using System.Text;

namespace NCryptoLib
{
    public static class DataExtensions
    {
        public static Hash256 Hash(this byte[] data)
        {
            MsftHasher hasher = new MsftHasher();
            return hasher.SHA256(data, 0, data.Length);
        }
    }
}
