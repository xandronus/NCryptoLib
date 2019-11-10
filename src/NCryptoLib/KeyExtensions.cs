using NCryptoLib.ECDsa;
using System;
using System.Collections.Generic;
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
            return new ECDsaCng(CngKey.Import(MsftECDsaCng.ConvertToCngKeyData(key), CngKeyBlobFormat.EccPrivateBlob));
        }
    }
}
