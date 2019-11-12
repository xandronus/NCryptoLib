using System;

namespace NCryptoLib
{
    public ref struct Hash256
    {
        public Hash256(string hex)
        {
            Bytes = hex.HexToBytes();
        }

        public Hash256(byte[] bytes)
        {
            Bytes = bytes;
        }

        public Hash256(Span<byte> bytes)
        {
            Bytes = bytes;
        }

        public Span<byte> Bytes;

        public static bool operator ==(Hash256 left, Hash256 right)
        {
            var equals = Equals(left, right);
            return equals;
        }

        public static bool operator !=(Hash256 left, Hash256 right)
        {
            return !(left == right);
        }

        public static bool Equals(Hash256 left, Hash256 right)
        {
            return left.Bytes.SequenceEqual(right.Bytes);
        }
    }
}
