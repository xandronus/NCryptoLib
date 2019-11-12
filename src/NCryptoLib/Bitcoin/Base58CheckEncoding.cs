using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Text;

namespace NCryptoLib.Bitcoin
{
    public class Base58CheckEncoding : Encoding
    {
        private const int ChecksumLength = 4;
        private const string Digits = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";        

        /// <summary>
        /// Encodes data in Base58Check format
        /// </summary>
        /// <param name="data">The data to be encoded</param>
        /// <returns>base58check string</returns>
        public static string Encode(Span<byte> data)
        {
            var withChecksum = AddChecksum(data);

            // Decode byte[] to BigInteger
            var intData = withChecksum.ToArray().Aggregate<byte, BigInteger>(0, (current, t) => current * 256 + t);

            // Encode BigInteger to Base58 string
            var result = string.Empty;
            while (intData > 0)
            {
                var remainder = (int)(intData % 58);
                intData /= 58;
                result = Digits[remainder] + result;
            }

            // Append `1` for each leading 0 byte
            for (var i = 0; i < withChecksum.Length && withChecksum[i] == 0; i++)
            {
                result = '1' + result;
            }

            return result;
        }

        /// <summary>
        /// Decodes data in Base58Check format (with 4 byte checksum)
        /// </summary>
        /// <param name="data">Data to be decoded</param>
        /// <returns>Returns decoded data if valid; throws CryptoException if invalid</returns>
        public static Span<byte> Decode(string data)
        {
            var dataWithChecksum = Base58ToBytes(data);
            var dataWithoutChecksum = VerifyAndRemoveCheckSum(dataWithChecksum);

            return dataWithoutChecksum;
        }

        /// <summary>
        /// Decodes data in plain Base58 to byte representation
        /// </summary>
        /// <param name="data">Data to be decoded</param>
        /// <returns>Returns decoded data if valid; throws FormatException if invalid</returns>
        public static Span<byte> Base58ToBytes(string data)
        {
            // Decode Base58 string to BigInteger 
            BigInteger intData = 0;
            for (var i = 0; i < data.Length; i++)
            {
                var digit = Digits.IndexOf(data[i]); //Slow

                if (digit < 0)
                {
                    throw new FormatException(string.Format("Invalid Base58 character `{0}` at position {1}", data[i], i));
                }

                intData = intData * 58 + digit;
            }

            // Encode BigInteger to byte[]
            // Leading zero bytes get encoded as leading `1` characters
            var leadingZeroCount = data.TakeWhile(c => c == '1').Count();
            var leadingZeros = Enumerable.Repeat((byte)0, leadingZeroCount);
            var bytesWithoutLeadingZeros =
              intData.ToByteArray()
              .Reverse()// to big endian
              .SkipWhile(b => b == 0);//strip sign byte
            var result = leadingZeros.Concat(bytesWithoutLeadingZeros).ToArray();

            return result;
        }

        private static Span<byte> AddChecksum(Span<byte> data)
        {
            var checkSum = GetChecksum(data);
            Span<byte> output = new byte[data.Length + checkSum.Length];
            data.CopyTo(output);
            checkSum.CopyTo(output.Slice(data.Length));
            return output;
        }

        /// <summary>
        /// Verifies the checksum on a base58check array
        /// Throws CryptoException if invalid checksum
        /// </summary>
        /// <param name="data">input base58check data</param>
        /// <returns>base58check data without checksum</returns>
        /// <exception cref="CryptoException">thrown if invalid checksum present</exception>
        private static Span<byte> VerifyAndRemoveCheckSum(Span<byte> data)
        {
            var result = data.Slice(0, data.Length - ChecksumLength);

            var expectedChecksum = GetChecksum(result);
            var actualChecksum = data.Slice(data.Length - ChecksumLength, ChecksumLength);

            if (!expectedChecksum.SequenceEqual(actualChecksum))
                throw new CryptoException("Base58 checksum mismatch");

            return result;
        }

        private static Span<byte> GetChecksum(Span<byte> data)
        {            
           return data.Hash().Bytes.Hash().Bytes.Slice(0, ChecksumLength); // SHA256(SHA256(data))
        }

        // TODO: Implement encoding methods

        public override int GetByteCount(char[] chars, int index, int count)
        {
            throw new NotImplementedException();
        }

        public override int GetBytes(char[] chars, int charIndex, int charCount, byte[] bytes, int byteIndex)
        {
            throw new NotImplementedException();
        }

        public override int GetCharCount(byte[] bytes, int index, int count)
        {
            throw new NotImplementedException();
        }

        public override int GetChars(byte[] bytes, int byteIndex, int byteCount, char[] chars, int charIndex)
        {
            throw new NotImplementedException();
        }

        public override int GetMaxByteCount(int charCount)
        {
            throw new NotImplementedException();
        }

        public override int GetMaxCharCount(int byteCount)
        {
            throw new NotImplementedException();
        }
    }
}
