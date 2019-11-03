using System;

namespace NCryptoLib.ECDsa
{
    public interface IECDsa
    {
        public Span<byte> CreateSecret();
        public Key CreatePrivateKey();
        public Key CreateKey();
        public bool IsPrivateKeyValid(Key key);
        public Signature SignData(byte[] data, Key key);
        public Signature SignHash(Span<byte> hash, Key key);
        public bool VerifyData(byte[] data, Signature signature, Key key);
        public bool VerifyHash(Span<byte> hash, Signature signature, Key key);
    }
}
