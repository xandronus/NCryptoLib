using System;

namespace NCryptoLib
{
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1066:Type {0} should implement IEquatable<T> because it overrides Equals", Justification = "struct should not implement IEquatable")]
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

        public Span<byte> Bytes { get; set; }

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

        public override bool Equals(object? obj)
        {
            return Bytes.Equals(obj);
        }

        public override int GetHashCode()
        {
            return Bytes.GetHashCode();
        }

        public bool Equals(Hash256 other)
        {
            return Equals(this, other);
        }
    }
}
