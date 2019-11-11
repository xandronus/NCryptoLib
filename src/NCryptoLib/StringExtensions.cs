using System;
using System.Collections.Generic;
using System.Text;

namespace NCryptoLib
{
    public static class StringExtensions
    {
        /// <summary>
        /// Finds the Hash of a text message
        /// </summary>
        /// <param name="text">text message</param>
        /// <param name="encoding">encoding of the message, default = UTF8</param>
        /// <returns>hash of the message</returns>
        public static Hash256 HashOfText(this string text, Encoding encoding = null)
        {
            if (encoding == null)
                encoding = Encoding.UTF8;
            return encoding.GetBytes(text).Hash();
        }

        /// <summary>
        /// Computes the hash of a hex value
        /// </summary>
        /// <param name="hexString">hex value represented in string form</param>
        /// <returns>hash of the hex value</returns>
        public static Hash256 HashOfHex(this string hexString)
        {
            return hexString.HexToBytes().Hash();   
        }
    }
}
