using System;
using System.Collections.Generic;
using System.Numerics;
using System.Text;

namespace NCryptoLib.ECDsa
{
    public static class KeyExtensions
    {
        public static Span<byte> ToSECUncompressedPublicKey(this Span<byte> publicKey)
        {
            if (publicKey.Length != 64)
                throw new ArgumentException("key must be 64 bytes long (uncompressed public key)");

            Span<byte> uncompressed = new byte[65];

            // uncompressed is prefixed with 0x04
            byte[] prefix = { 0x04 };
            prefix.CopyTo(uncompressed);

            // Copy after the prefix
            publicKey.CopyTo(uncompressed.Slice(1));

            // Make big endian
            uncompressed.Slice(1, 32).Reverse();
            uncompressed.Slice(33, 32).Reverse();

            return uncompressed;
        }

        public static Span<byte> ToSECCompressedPublicKey(this Span<byte> publicKey)
        {
            if (publicKey.Length != 64)
                throw new ArgumentException("key must be 64 bytes long (uncompressed public key)");

            // Use Y to figure out prefix
            var yBytes = publicKey.GetY();
            BigInteger y = new BigInteger(yBytes);
            Span<byte> compressed = new byte[33];
            byte[] even = { 0x02 }; // prefix for even Y
            byte[] odd = { 0x03 }; // prefix for odd Y
            if (y % 2 == 0)
                even.CopyTo(compressed);
            else
                odd.CopyTo(compressed);

            // Populate rest with Big Endian version of X
            var x = publicKey.GetX();
            Span<byte> xReversed = new byte[x.Length];
            x.CopyTo(xReversed);
            xReversed.Reverse();
            xReversed.CopyTo(compressed.Slice(1)); // Skip the prefix and write the X

            return compressed;
        }
    }
}
