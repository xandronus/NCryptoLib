using System;
using System.Collections.Generic;
using System.Text;

namespace NCryptoLib
{
    public static class HexExtensions
    {
        /// <summary>
        /// <seealso cref="https://github.com/MeadowSuite/Secp256k1.Net/blob/master/Secp256k1.Net.Test/Tests.cs"/>
        /// </summary>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Globalization", "CA1308:Normalize strings to uppercase", Justification = "Counter to bitcoin convention")]
        public static string ToHexString(this Span<byte> span)
        {
            return BitConverter.ToString(span.ToArray()).Replace("-", "", StringComparison.InvariantCulture).ToLowerInvariant();
        }

        /// <summary>
        /// <seealso cref="https://github.com/MeadowSuite/Secp256k1.Net/blob/master/Secp256k1.Net.Test/Tests.cs"/>
        /// </summary>
        public static byte[] HexToBytes(this string hexString)
        {
            if (hexString == null)
                throw new ArgumentException($"Invalid arguments in method '{nameof(HexToBytes)}'. Parameter '{nameof(hexString)}' cannot be null.");
            int chars = hexString.Length;
            byte[] bytes = new byte[chars / 2];
            for (int i = 0; i < chars; i += 2)
            {
                bytes[i / 2] = Convert.ToByte(hexString.Substring(i, 2), 16);
            }
            return bytes;
        }
    }
}
