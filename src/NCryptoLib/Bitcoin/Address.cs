using NCryptoLib.ECDsa;
using System;
using System.Collections.Generic;
using System.Text;

namespace NCryptoLib.Bitcoin
{
    public static class Address
    {
        /// <summary>
        /// Gets P2PKH Bitcoin Address from a key
        /// - Uses the compressed public key format for address generation
        /// </summary>
        /// <param name="key">key containing the public key</param>
        /// <param name="dsa">ECDsa algorithm interface</param>
        /// <param name="version">Version bytes of bitcoin network (0x00 for mainnet)</param>
        /// <param name="context">optional context</param>        
        /// <returns>Base58check bitcoin address</returns>
        public static string GetP2PKHAddress(Key key, IECDsa dsa, Span<byte> version, DisposableContext? context = null)
        {
            return GetP2PKHAddress(key.PublicKey, dsa, version, context);
        }

        /// <summary>
        /// Gets P2PKH Bitcoin Address from a key
        /// - Uses the compressed public key format for address generation
        /// </summary>
        /// <param name="publicKey">uncompressed public key (64 bytes)</param>
        /// <param name="dsa">ECDsa algorithm interface</param>
        /// <param name="version">Version bytes of bitcoin network (0x00 for mainnet)</param>
        /// <param name="context">optional context</param>        
        /// <returns>Base58check bitcoin address</returns>
        public static string GetP2PKHAddress(Span<byte> publicKey, IECDsa dsa, Span<byte> version, DisposableContext? context = null)
        {
            if (dsa == null)
                throw new ArgumentException($"Invalid input parameters to '{nameof(GetP2PKHAddress)}'. '{nameof(dsa)}' cannot be null.");

            var compressedPublicKey = dsa.GetSECCompressedPublicKey(publicKey, context);
            return compressedPublicKey.Hash().RIPEMD160().ToP2PKHAddress(version);
        }
    }
}
