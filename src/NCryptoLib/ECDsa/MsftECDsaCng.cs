using System;
using System.Collections.Generic;
using System.Text;
using System.Security.Cryptography;
using System.Linq;

namespace NCryptoLib.ECDsa
{
    /// <summary>
    /// Uses Microsofts ECDsaCng in System.Security.Cryptography
    /// </summary>
    public class MsftECDsaCng : IECDsa
    {        
        public Span<byte> CreateSecret(DisposableContext context = null)
        {
            ECDsaCng dsa = context?.Context as ECDsaCng;
            if (dsa == null)
            {
                dsa = new ECDsaCng(256)
                {
                    HashAlgorithm = CngAlgorithm.Sha256
                };
            }

            try
            {
                byte[] keyData = dsa.Key.Export(CngKeyBlobFormat.EccPrivateBlob);
                var key = ConvertEccPrivateBlob(keyData);
                return key.PrivateKey;
            }
            finally
            {
                if (context == null)
                    dsa?.Dispose();
            }
        }

        public Key CreatePrivateKey(DisposableContext context = null)
        {
            return this.CreateKey(context);
        }

        public Key CreateKey(DisposableContext context = null)
        {
            ECDsaCng dsa = context?.Context as ECDsaCng;
            if (dsa == null)
            {
                dsa = new ECDsaCng(256)
                {
                    HashAlgorithm = CngAlgorithm.Sha256
                };
            }

            try
            {
                byte[] keyData = dsa.Key.Export(CngKeyBlobFormat.EccPrivateBlob);
                var key = ConvertEccPrivateBlob(keyData);
                return key;
            }
            finally
            {
                if (context == null)
                    dsa?.Dispose();
            }
        }

        public Key CreateKey(Span<byte> privateKey, DisposableContext context = null)
        {
            return new Key { PrivateKey = privateKey, PublicKey = this.CreatePublicKey(privateKey, context) };
        }

        public bool IsPrivateKeyValid(Key key, DisposableContext context = null)
        {
            try
            {
                using (key.ToECDsaCngKey())
                {
                    return true;
                }
            }
            catch (CryptographicException)
            {
                return false;
            }
        }

        public Signature SignData(byte[] data, Key key, DisposableContext context = null)
        {
            ECDsaCng dsa = context?.Context as ECDsaCng;
            if (dsa == null)
            {
                dsa = key.ToECDsaCngKey();
            }

            try
            { 
                byte[] signature = dsa.SignData(data);
                return new Signature { Bytes = signature };
            }
            finally
            {
                if (context == null)
                    dsa?.Dispose();
            }
        }

        public Signature SignData(byte[] data, DisposableContext context)
        {
            var dsa = context?.Context as ECDsaCng;
            if (dsa == null)
                throw new CryptoException($"A context is required for {nameof(MsftECDsaCng)}");

            byte[] signature = dsa.SignData(data);
            return new Signature { Bytes = signature };
        }

        public Signature SignHash(Hash256 hash, DisposableContext context)
        {
            var dsa = context?.Context as ECDsaCng;
            if (dsa == null)
                throw new CryptoException($"A context is required for {nameof(MsftECDsaCng)}");
 
            byte[] signature = dsa.SignHash(hash.Bytes.ToArray());

            return new Signature { Bytes = signature };
        }

        public Signature SignHash(Hash256 hash, Key key, DisposableContext context = null)
        {
            ECDsaCng dsa = context?.Context as ECDsaCng;
            if (dsa == null)
            {
                dsa = key.ToECDsaCngKey();
            }
            
            try
            {                
                byte[] signature = dsa.SignHash(hash.Bytes.ToArray());

                return new Signature { Bytes = signature };
            }
            finally
            {
                if (context == null)
                    dsa?.Dispose();
            }           
        }

        public bool VerifyData(byte[] data, Signature signature, Key key, DisposableContext context = null)
        {
            ECDsaCng dsa = context?.Context as ECDsaCng;
            if (dsa == null)
            {
                dsa = key.ToECDsaCngKey();
            }

            try
            {
                return dsa.VerifyData(data, signature.Bytes.ToArray());
            }
            finally
            {
                if (context == null)
                    dsa?.Dispose();
            }  
        }

        public bool VerifyData(byte[] data, Signature signature, DisposableContext context)
        {
            var dsa = context?.Context as ECDsaCng;
            if (dsa == null)
                throw new CryptoException($"A context is required for {nameof(MsftECDsaCng)}");

            return dsa.VerifyData(data, signature.Bytes.ToArray());
        }

        public bool VerifyHash(Hash256 hash, Signature signature, Key key, DisposableContext context = null)
        {
            ECDsaCng dsa = context?.Context as ECDsaCng;
            if (dsa == null)
            {
                dsa = key.ToECDsaCngKey();
            }

            try
            {
                return dsa.VerifyHash(hash.Bytes, signature.Bytes.ToArray());
            }
            finally
            {
                if (context == null)
                    dsa?.Dispose();
            } 
        }

        public bool VerifyHash(Hash256 hash, Signature signature, DisposableContext context)
        {
            var dsa = context?.Context as ECDsaCng;
            if (dsa == null)
                throw new CryptoException($"A context is required for {nameof(MsftECDsaCng)}");

            return dsa.VerifyHash(hash.Bytes, signature.Bytes.ToArray());
        }

        public Span<byte> CreatePublicKey(Span<byte> privateKey, DisposableContext context = null)
        {
            // TODO: Implement MSFT public key generation
            throw new NotImplementedException();
        }

        public Span<byte> CompressPublicKey(Span<byte> uncompressed, DisposableContext context = null)
        {
            // TODO: Implement bitcoin compressed format
            throw new NotImplementedException();
        }

        public static ECDsaCng ConvertToCng(Key key)
        {
            var publicPrivateKey = Array.Empty<byte>().Concat(key.PublicKey.ToArray()).Concat(key.PrivateKey.ToArray()).ToArray();

            var keyType = new byte[] { 0x45, 0x43, 0x53, 0x32 };
            var keyLength = new byte[] { 0x20, 0x00, 0x00, 0x00 };

            var keyData = publicPrivateKey.Skip(1).ToArray();

            var keyImport = keyType.Concat(keyLength).Concat(keyData).ToArray();

            var cngKey = CngKey.Import(keyImport, CngKeyBlobFormat.EccPrivateBlob);
            return new ECDsaCng(cngKey);
        }       

        // https://stackoverflow.com/questions/24251336/import-a-public-key-from-somewhere-else-to-cngkey
        public static byte[] ConvertToCngKeyData(Key key)
        {
            var publicPrivateKey = Array.Empty<byte>().Concat(key.PublicKey.ToArray()).Concat(key.PrivateKey.ToArray()).ToArray();

            var keyType = new byte[] { 0x45, 0x43, 0x53, 0x32 };
            var keyLength = new byte[] { 0x20, 0x00, 0x00, 0x00 };

            var keyData = publicPrivateKey.Skip(1).ToArray();

            var keyImport = keyType.Concat(keyLength).Concat(keyData).ToArray();
            return keyImport;
        }

        public static Key ConvertEccPrivateBlob(byte[] keyData)
        { 
            var privateKey = keyData.TakeLast(32).ToArray();
            var publicKeyPrefix = new byte[] { 0x40 };
            var publicKey = publicKeyPrefix.Concat(keyData.Skip(8).Take(keyData.Length - 32 - 8)).ToArray();
            return new Key
            {
                PrivateKey = privateKey,
                PublicKey = publicKey
            };
        }
    }
}
