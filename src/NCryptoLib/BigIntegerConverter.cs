using System;
using System.Collections.Generic;
using System.Numerics;
using System.Text;

namespace NCryptoLib
{
    /// <summary>
    /// <seealso cref="https://github.com/MeadowSuite/Secp256k1.Net/blob/master/Secp256k1.Net.Test/Tests.cs"/>
    /// </summary>
    public abstract class BigIntegerConverter
    {
        /// <summary>
        /// Obtains the bytes that represent the BigInteger as if it was a big endian 256-bit integer.
        /// </summary>
        /// <param name="bigInteger">The BigInteger to obtain the byte representation of.</param>
        /// <returns>Returns the bytes that represent BigInteger as if it was a 256-bit integer.</returns>
        public static byte[] GetBytes(BigInteger bigInteger, int byteCount = 32)
        {
            // Obtain the bytes which represent this BigInteger.
            byte[] result = bigInteger.ToByteArray();

            // We'll operate on the data in little endian (since we'll extend the array anyways and we'd have to copy the data over anyways).
            if (!BitConverter.IsLittleEndian)
                Array.Reverse(result);

            // Store the original size of the data, then resize it to the size of a word.
            int originalSize = result.Length;
            Array.Resize(ref result, byteCount);

            // BigInteger uses the most significant bit as sign and optimizes to return values like -1 as 0xFF instead of as 0xFFFF or larger (since there is no bound size, and negative values have all leading bits set)
            // Instead if we wanted to represent 256 (0xFF), we would add a leading zero byte so the sign bit comes from it, and will be zero (positive) (0x00FF), this way, BigInteger knows to represent this as a positive value.
            // Because we resized the array already, it would have added leading zero bytes which works for positive numbers, but if it's negative, all extended bits should be set, so we check for that case.

            // If the integer is negative, any extended bits should all be set.
            if (bigInteger.Sign < 0)
                for (int i = originalSize; i < result.Length; i++)
                    result[i] = 0xFF;

            // Flip the array so it is in big endian form.
            Array.Reverse(result);

            return result;
        }
    }
}
