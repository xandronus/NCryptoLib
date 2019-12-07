using System;

namespace NCryptoLib
{
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1066:Type {0} should implement IEquatable<T> because it overrides Equals", Justification = "struct should not implement IEquatable")]
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

        public Hash160(Span<byte> bytes)
        {
            Bytes = bytes;
        }

        public Span<byte> Bytes { get; set; }

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

        public override bool Equals(object? obj)
        {
            return Bytes.Equals(obj);
        }

        public override int GetHashCode()
        {
            return Bytes.GetHashCode();
        }

        public bool Equals(Hash160 other)
        {
            return Equals(this, other);
        }
    }
}
