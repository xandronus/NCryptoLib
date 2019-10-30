using System;

namespace NCryptoLib.ECDsa
{
    public interface IECDsa
    {
        public Span<byte> CreateSecret();
        public Key CreatePrivateKey();
        public Key CreateKey();
        public bool IsPrivateKeyValid(Key key);
        public Span<byte> SignData(byte[] data, Key key);
        public Span<byte> SignHash(Span<byte> hash, Key key);
        public bool VerifyData(byte[] data, byte[] signature, Key key);
        public bool VerifyHash(Span<byte> hash, Span<byte> signature, Key key);
    }
}
