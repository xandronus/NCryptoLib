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
        
        public Span<byte> CreateSecret(ECDsaContext context = null)
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

        public Key CreatePrivateKey(ECDsaContext context = null)
        {
            return this.CreateKey(context);
        }

        public Key CreateKey(ECDsaContext context = null)
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

        public bool IsPrivateKeyValid(Key key, ECDsaContext context = null)
        {
            try
            {
                using (ConvertToCngKey(key))
                {
                    return true;
                }
            }
            catch (CryptographicException)
            {
                return false;
            }
        }

        public Signature SignData(byte[] data, Key key, ECDsaContext context = null)
        {
            ECDsaCng dsa = context?.Context as ECDsaCng;
            if (dsa == null)
            {
                dsa = ConvertToCngKey(key);
            }

            try
            { 
                byte[] signature = dsa.SignData(data);
                return new Signature { Data = signature };
            }
            finally
            {
                if (context == null)
                    dsa?.Dispose();
            }
        }

        public Signature SignHash(Span<byte> hash, Key key, ECDsaContext context = null)
        {
            ECDsaCng dsa = context?.Context as ECDsaCng;
            if (dsa == null)
            {
                dsa = ConvertToCngKey(key);
            }
            
            try
            {                
                byte[] signature = dsa.SignHash(hash.ToArray());

                return new Signature { Data = signature };
            }
            finally
            {
                if (context == null)
                    dsa?.Dispose();
            }           
        }

        public bool VerifyData(byte[] data, Signature signature, Key key, ECDsaContext context = null)
        {
            ECDsaCng dsa = context?.Context as ECDsaCng;
            if (dsa == null)
            {
                dsa = ConvertToCngKey(key);
            }

            try
            {
                return dsa.VerifyData(data, signature.Data.ToArray());
            }
            finally
            {
                if (context == null)
                    dsa?.Dispose();
            }  
        }

        public bool VerifyHash(Span<byte> hash, Signature signature, Key key, ECDsaContext context = null)
        {
            ECDsaCng dsa = context?.Context as ECDsaCng;
            if (dsa == null)
            {
                dsa = ConvertToCngKey(key);
            }

            try
            {
                return dsa.VerifyHash(hash, signature.Data.ToArray());
            }
            finally
            {
                if (context == null)
                    dsa?.Dispose();
            } 
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

        /// <summary>
        /// Creates a CngKey from a public key
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        public static ECDsaCng ConvertToCngKey(Key key)
        {
            // TODO: Look at moving this to an extension method?
            return new ECDsaCng(CngKey.Import(ConvertToCngKeyData(key), CngKeyBlobFormat.EccPrivateBlob));
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
