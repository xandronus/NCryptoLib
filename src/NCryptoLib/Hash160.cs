using System;

namespace NCryptoLib
{
    public ref struct Hash160
    {
        public Hash160(string hex)
        {
            Bytes = hex.HexToBytes();
        }

        public Hash160(byte[] bytes)
        {
            Bytes = bytes;
        }

        public Span<byte> Bytes;

        public static bool operator ==(Hash160 left, Hash160 right)
        {
            var equals = Equals(left, right);
            return equals;
        }

        public static bool operator !=(Hash160 left, Hash160 right)
        {
            return !(left == right);
        }

        public static bool Equals(Hash160 left, Hash160 right)
        {
            return left.Bytes.SequenceEqual(right.Bytes);
        }
    }
}
