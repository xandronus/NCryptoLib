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
            var dsa = new ECDsaCng(CngKey.Import(MsftECDsaCng.ConvertToCngKeyData(key), CngKeyBlobFormat.EccPrivateBlob));
            dsa.HashAlgorithm = CngAlgorithm.Sha256;
            return dsa;
        
        }

        /// <summary>
        /// Gets the public key hash of the key
        /// </summary>
        /// <param name="key">key</param>
        /// <returns></returns>
        public static Hash160 ToPublicKeyHash(this Key key)
        {
            return key.PublicKey.Hash().RIPEMD160();
        }

        /// <summary>
        /// Gets the Bitcoin P2PKHAddress of this key
        /// RIPEMD160(SHA256(pubkey))
        /// </summary>
        /// <param name="key">Key to get bitcoin address for</param>
        /// <returns>Base58Check encoded address</returns>
        public static string GetBitcoinP2PKHAddress(this Key key)
        {
            return key.ToPublicKeyHash().ToP2PKHAddress(Bitcoin.Network.MainNet.P2PKHAddressVersion);
        }
    }
}
