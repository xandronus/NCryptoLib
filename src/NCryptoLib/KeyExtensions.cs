using NCryptoLib.ECDsa;
using System;
using System.Collections.Generic;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace NCryptoLib
{
    public static class KeyExtensions
    {        
        /// <summary>
        /// Converts the key to a ECDsaCng key
        /// </summary>
        /// <param name="key">Key to convert</param>
        /// <returns>ECDsaCng Key</returns>
        public static ECDsaCng ToECDsaCngKey(this Key key)
        {
            var dsa = new ECDsaCng(CngKey.Import(MsftECDsaCng.ConvertToCngKeyData(key), CngKeyBlobFormat.EccPrivateBlob));
            dsa.HashAlgorithm = CngAlgorithm.Sha256;
            return dsa;        
        }

        public static Span<byte> GetX(this Span<byte> key)
        {
            return key.Slice(0, 32);
        }

        public static Span<byte> GetY(this Span<byte> key)
        {
            return key.Slice(32, 32);
        }
    }
}
