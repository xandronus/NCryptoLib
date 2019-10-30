using System;

namespace NCryptoLib.ECDsa
{
    /// <summary>
    /// Uses Bitcoin Core Secp256k1 native library through Secp256k1.Net package.
    /// <see cref="https://github.com/MeadowSuite/Secp256k1.Net"/>
    /// </summary>
    public class Secp256k1DotNet : IECDsa
    {
        public const int SignatureLength = Secp256k1Net.Secp256k1.UNSERIALIZED_SIGNATURE_SIZE;
        public const int PublicKeyLength = Secp256k1Net.Secp256k1.PUBKEY_LENGTH;

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

        public Key CreateKey()
        {
            using (var secp256k1 = new Secp256k1Net.Secp256k1())
            {
                Key key = this.CreatePrivateKey();
                key.PublicKey = new byte[PublicKeyLength];
                if (!secp256k1.PublicKeyCreate(key.PublicKey, key.PrivateKey))
                    throw new CryptoException("Secp256k1 can't create public key from private key");
                return key;
            }
        }

        public Span<byte> SignData(byte[] data, Key key)
        {
            using (var secp256k1 = new Secp256k1Net.Secp256k1())
            {
                Span<byte> signature = new byte[SignatureLength];
                if (!secp256k1.Sign(signature, data, key.PrivateKey))
                    throw new CryptoException("Secp256k1 sign failure");
                return signature;
            }
        }

        public Span<byte> SignHash(Span<byte> hash, Key key)
        {
            using (var secp256k1 = new Secp256k1Net.Secp256k1())
            {
                Span<byte> signature = new byte[SignatureLength];
                if (!secp256k1.Sign(signature, hash, key.PrivateKey))
                    throw new CryptoException("Secp256k1 sign failure");
                return signature;
            }
        }

        public bool VerifyData(byte[] data, byte[] signature, Key key)
        {
            using (var secp256k1 = new Secp256k1Net.Secp256k1())
            {
                return secp256k1.Verify(signature, data, key.PublicKey);
            }
        }

        public bool VerifyHash(Span<byte> hash, Span<byte> signature, Key key)
        {
            using (var secp256k1 = new Secp256k1Net.Secp256k1())
            {
                return secp256k1.Verify(signature, hash, key.PublicKey);
            }
        }
    }
}
