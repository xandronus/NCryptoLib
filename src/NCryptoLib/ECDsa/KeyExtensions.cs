using System;
using System.Collections.Generic;
using System.Numerics;
using System.Text;

namespace NCryptoLib.ECDsa
{
    public static class KeyExtensions
    {
        public static Span<byte> ToSECUncompressedPublicKey(this Span<byte> key)
        {
            Span<byte> uncompressed = new byte[65];

            // uncompressed is prefixed with 0x04
            byte[] prefix = { 0x04 };
            prefix.CopyTo(uncompressed);

            // Make big endian
            key.Slice(0, 32).Reverse();
            key.Slice(32, 32).Reverse();

            key.CopyTo(uncompressed.Slice(1));

            return uncompressed;
        }

        public static Span<byte> ToSECCompressedPublicKey(this Span<byte> key)
        {
            var yBytes = key.GetY();
            BigInteger y = new BigInteger(yBytes);
            Span<byte> compressed = new byte[33];
            byte[] even = { 0x02 }; // prefix for even Y
            byte[] odd = { 0x03 }; // prefix for odd Y
            if (y % 2 == 0)
                even.CopyTo(compressed);
            else
                odd.CopyTo(compressed);
            var x = key.GetX();
            x.Reverse();
            x.CopyTo(compressed.Slice(1)); // Skip the prefix and write the X
            return compressed;
        }
    }
}
