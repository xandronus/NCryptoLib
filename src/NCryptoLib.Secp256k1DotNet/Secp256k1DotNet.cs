using NCryptoLib.Hasher;
using System;

// vrs output - checkout secp256k1_pubkey_serialize_compac v=recovery id without 27 constant
// https://bitcoin.stackexchange.com/questions/38351/ecdsa-v-r-s-what-is-v
// Signature = 32 byte R, 32 byte S
namespace NCryptoLib.ECDsa
{
    /// <summary>
    /// Uses Bitcoin Core Secp256k1 native library through Secp256k1.Net package.
    /// <see cref="https://github.com/MeadowSuite/Secp256k1.Net"/>
    /// </summary>
    public class Secp256k1DotNet : IECDsa
    {
        public const int SignatureLength = Secp256k1Net.Secp256k1.SIGNATURE_LENGTH;
        public const int PublicKeyLength = Secp256k1Net.Secp256k1.PUBKEY_LENGTH;
        public const int PublicKeyCompressedLength = Secp256k1Net.Secp256k1.SERIALIZED_COMPRESSED_PUBKEY_LENGTH;
        public const int PublicKeyUncompressedLength = Secp256k1Net.Secp256k1.SERIALIZED_UNCOMPRESSED_PUBKEY_LENGTH;
        public const int HashLength = Secp256k1Net.Secp256k1.HASH_LENGTH;

        public Span<byte> CreateSecret(DisposableContext? context = null)
        {
            return ECDsaKeyGen.CreatePrivateKey(this);
        }

        public Key CreatePrivateKey(DisposableContext? context = null)
        {
            return new Key
            {
                PrivateKey = this.CreateSecret(context),
                PublicKey = null
            };
        }

        public Span<byte> GetSECCompressedPublicKey(Span<byte> uncompressed, DisposableContext? context = null)
        {
            Secp256k1Net.Secp256k1? dsa = context?.Context as Secp256k1Net.Secp256k1;
            if (dsa == null)
            {
                dsa = new Secp256k1Net.Secp256k1();
            }

            try
            {
                Span<byte> compressed = new byte[PublicKeyCompressedLength];
                if (!dsa.PublicKeySerialize(compressed, uncompressed, Secp256k1Net.Flags.SECP256K1_EC_COMPRESSED))
                    throw new CryptoException("Can't create public compressed key from uncompressed key");
                return compressed;
            }
            finally
            {
                if (context == null)
                    dsa?.Dispose();
            }
        }

        public Span<byte> GetSECUncompressedPublicKey(Span<byte> uncompressed, DisposableContext? context = null)
        {
            Secp256k1Net.Secp256k1? dsa = context?.Context as Secp256k1Net.Secp256k1;
            if (dsa == null)
            {
                dsa = new Secp256k1Net.Secp256k1();
            }

            try
            {
                Span<byte> uncompressedBtc = new byte[PublicKeyUncompressedLength];
                if (!dsa.PublicKeySerialize(uncompressedBtc, uncompressed, Secp256k1Net.Flags.SECP256K1_EC_UNCOMPRESSED))
                    throw new CryptoException("Can't create public uncompressed bitcoin key from uncompressed key");
                return uncompressedBtc;
            }
            finally
            {
                if (context == null)
                    dsa?.Dispose();
            }
        }

        public Span<byte> CreatePublicKey(Span<byte> privateKey, DisposableContext? context = null)
        {
            Secp256k1Net.Secp256k1? dsa = context?.Context as Secp256k1Net.Secp256k1;
            if (dsa == null)
            {
                dsa = new Secp256k1Net.Secp256k1();
            }

            try
            {
                Span<byte> publicKey = new byte[PublicKeyLength];
                if (!dsa.PublicKeyCreate(publicKey, privateKey))
                    throw new CryptoException("Can't create public key from private key");
                return publicKey;
            }
            finally
            {
                if (context == null)
                    dsa?.Dispose();
            }
        }

        public bool IsPrivateKeyValid(Key key, DisposableContext? context = null)
        {
            Secp256k1Net.Secp256k1? dsa = context?.Context as Secp256k1Net.Secp256k1;
            if (dsa == null)
            {
                dsa = new Secp256k1Net.Secp256k1();
            }

            try
            {
                return dsa.SecretKeyVerify(key.PrivateKey);
            }
            finally
            {
                if (context == null)
                    dsa?.Dispose();
            }
        }

        public Key CreateKey(DisposableContext? context = null)
        {
            Secp256k1Net.Secp256k1? dsa = context?.Context as Secp256k1Net.Secp256k1;
            if (dsa == null)
            {
                dsa = new Secp256k1Net.Secp256k1();
            }

            try
            {
                Key key = this.CreatePrivateKey();
                key.PublicKey = new byte[PublicKeyLength];
                if (!dsa.PublicKeyCreate(key.PublicKey, key.PrivateKey))
                    throw new CryptoException("Secp256k1 can't create public key from private key");
                return key;
            }
            finally
            {
                if (context == null)
                    dsa?.Dispose();
            }
        }

        public Key CreateKey(Span<byte> privateKey, DisposableContext? context = null)
        {
            return new Key { PrivateKey = privateKey, PublicKey = this.CreatePublicKey(privateKey, context) };
        }

        public Signature SignData(byte[] data, Key key, DisposableContext? context = null)
        {
            return this.SignHash(data.Hash(), key, context);
        }

        public Signature SignData(byte[] data, DisposableContext? context)
        {
            return this.SignHash(data.Hash(), context);
        }

        public Signature SignHash(Hash256 hash, DisposableContext? context)
        {
            throw new CryptoException($"{nameof(Secp256k1DotNet)} requires key, use the method with it as a parameter.");
        }

        public Signature SignHash(Hash256 hash, Key key, DisposableContext? context = null)
        {
            Secp256k1Net.Secp256k1? dsa = context?.Context as Secp256k1Net.Secp256k1;
            if (dsa == null)
            {
                dsa = new Secp256k1Net.Secp256k1();
            }

            try
            {
                Span<byte> signature = new byte[SignatureLength];
                if (!dsa.Sign(signature, hash.Bytes, key.PrivateKey))
                    throw new CryptoException("Secp256k1 sign failure");
                return new Signature { Bytes = signature };
            }
            finally
            {
                if (context == null)
                    dsa?.Dispose();
            }
        }

        public bool VerifyData(byte[] data, Signature signature, Key key, DisposableContext? context = null)
        {
            return this.VerifyHash(data.Hash(), signature, key, context);
        }

        public bool VerifyData(byte[] data, Signature signature, DisposableContext? context)
        {
            return this.VerifyHash(data.Hash(), signature, context);
        }

        public bool VerifyHash(Hash256 hash, Signature signature, Key key, DisposableContext? context = null)
        {
            Secp256k1Net.Secp256k1? dsa = context?.Context as Secp256k1Net.Secp256k1;
            if (dsa == null)
            {
                dsa = new Secp256k1Net.Secp256k1();
            }

            try
            {
                return dsa.Verify(signature.Bytes, hash.Bytes, key.PublicKey);
            }
            finally
            {
                if (context == null)
                    dsa?.Dispose();
            }
        }

        public bool VerifyHash(Hash256 hash, Signature signature, DisposableContext? context)
        {
            throw new CryptoException($"{nameof(Secp256k1DotNet)} requires key, use the method with it as a parameter.");
        }
    }
}
