using System;

namespace NCryptoLib.ECDsa
{
    public interface IECDsa
    {
        public Span<byte> CreateSecret(ECDsaContext context = null);
        public Key CreatePrivateKey(ECDsaContext context = null);
        public Key CreateKey(ECDsaContext context = null);
        public bool IsPrivateKeyValid(Key key, ECDsaContext context = null);
        public Signature SignData(byte[] data, Key key, ECDsaContext context = null);
        public Signature SignHash(Span<byte> hash, Key key, ECDsaContext context = null);
        public bool VerifyData(byte[] data, Signature signature, Key key, ECDsaContext context = null);
        public bool VerifyHash(Span<byte> hash, Signature signature, Key key, ECDsaContext context = null);
    }
}
