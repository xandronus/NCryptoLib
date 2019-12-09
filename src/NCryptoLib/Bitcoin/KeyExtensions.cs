using System;
using System.Collections.Generic;
using System.Numerics;
using System.Text;

namespace NCryptoLib.Bitcoin
{
    public static class KeyExtensions 
    {
        public static Span<byte> GetBitcoinCompressedPublicKey(this Span<byte> key)
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
