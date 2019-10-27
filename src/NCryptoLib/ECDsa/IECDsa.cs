using System;

namespace NCryptoLib.ECDsa
{
    public interface IECDsa
    {
        public Span<byte> CreateSecret();
        public Key CreatePrivateKey();
        public bool IsPrivateKeyValid(Key key);
        public Span<byte> SignData(byte[] data, Key key);
    }
}
