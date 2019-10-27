using System;

namespace NCryptoLib.ECDsa
{
    /// <summary>
    /// Uses Bitcoin Core Secp256k1 native library through Secp256k1.Net package.
    /// <see cref="https://github.com/MeadowSuite/Secp256k1.Net"/>
    /// </summary>
    public class Secp256k1DotNet : IECDsa
    {
        public Span<byte> CreateSecret()
        {           
            return ECDsaKeyGen.CreatePrivateKey(this);
        }

        public Key CreatePrivateKey()
        {
            return new Key
            {
                PrivateKey = this.CreateSecret(),
                PublicKey = null
            };
        }

        public bool IsPrivateKeyValid(Key key)
        {
            using (var secp256k1 = new Secp256k1Net.Secp256k1())
            {
                return secp256k1.SecretKeyVerify(key.PrivateKey);
            }
        }

        public Span<byte> SignData(byte[] data, Key key)
        {
            using (var secp256k1 = new Secp256k1Net.Secp256k1())
            {
                Span<byte> signature = new byte[64];
                if (!secp256k1.Sign(signature, data, key.PrivateKey))
                    throw new CryptoException("Secp256k1 sign failure");
                return signature;
            }            
        }
    }
}
