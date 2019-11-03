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
        
        public Span<byte> CreateSecret()
        {           
            using (ECDsaCng dsa = new ECDsaCng(256))
            {  
                dsa.HashAlgorithm = CngAlgorithm.Sha256;
                byte[] keyData = dsa.Key.Export(CngKeyBlobFormat.EccPrivateBlob);

                var key = ConvertEccPrivateBlob(keyData);
                return key.PrivateKey;
            }                        
        }

        public Key CreatePrivateKey()
        {
            return this.CreateKey();
        }

        public Key CreateKey()
        {
            using (ECDsaCng dsa = new ECDsaCng(256))
            {
                dsa.HashAlgorithm = CngAlgorithm.Sha256;
                byte[] keyData = dsa.Key.Export(CngKeyBlobFormat.EccPrivateBlob);

                return ConvertEccPrivateBlob(keyData);
            }
        }

        public bool IsPrivateKeyValid(Key key)
        {
            try
            {
                using (ECDsaCng ecsdKey = new ECDsaCng(ConvertToCngKey(key)))
                {
                    return true;
                }
            }
            catch (CryptographicException)
            {
                return false;
            }
        }

        public Signature SignData(byte[] data, Key key)
        {
            using (ECDsaCng ecsdKey = new ECDsaCng(ConvertToCngKey(key)))
            {
                ecsdKey.HashAlgorithm = CngAlgorithm.Sha256;
                byte[] signature = ecsdKey.SignData(data);

                return new Signature { Data = signature };
            }
        }

        public Signature SignHash(Span<byte> hash, Key key)
        {
            using (ECDsaCng ecsdKey = new ECDsaCng(ConvertToCngKey(key)))
            {
                ecsdKey.HashAlgorithm = CngAlgorithm.Sha256;
                byte[] signature = ecsdKey.SignHash(hash.ToArray());

                return new Signature { Data = signature };
            }
        }

        public bool VerifyData(byte[] data, Signature signature, Key key)
        {
            using (ECDsaCng ecsdKey = new ECDsaCng(ConvertToCngKey(key)))
            {
                ecsdKey.HashAlgorithm = CngAlgorithm.Sha256;
                return ecsdKey.VerifyData(data, signature.Data.ToArray());
            }
        }

        public bool VerifyHash(Span<byte> hash, Signature signature, Key key)
        {
            using (ECDsaCng ecsdKey = new ECDsaCng(ConvertToCngKey(key)))
            {
                ecsdKey.HashAlgorithm = CngAlgorithm.Sha256;
                return ecsdKey.VerifyHash(hash, signature.Data.ToArray());                
            }
        }

        // https://stackoverflow.com/questions/24251336/import-a-public-key-from-somewhere-else-to-cngkey
        private CngKey ConvertToCngKey(Key key)
        {       
            var publicPrivateKey = Array.Empty<byte>().Concat(key.PublicKey.ToArray()).Concat(key.PrivateKey.ToArray()).ToArray();

            var keyType = new byte[] { 0x45, 0x43, 0x53, 0x32 };
            var keyLength = new byte[] { 0x20, 0x00, 0x00, 0x00 };

            var keyData = publicPrivateKey.Skip(1).ToArray();

            var keyImport = keyType.Concat(keyLength).Concat(keyData).ToArray();

            var cngKey = CngKey.Import(keyImport, CngKeyBlobFormat.EccPrivateBlob);
            return cngKey;
        }

        private Key ConvertEccPrivateBlob(byte[] keyData)
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
