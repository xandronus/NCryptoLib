using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Text;

namespace NCryptoLib.ECDsa
{
    public static class ECDsaKeyGen
    {
        public static Span<byte> CreatePrivateKey(IECDsa ecdsa, int keyLength = 32)
        {
            if (ecdsa == null)
                throw new CryptoException($"Invalid input to '{nameof(CreatePrivateKey)}'. '{nameof(ecdsa)}' should not be NULL.");

            using (var rnd = RandomNumberGenerator.Create())
            {
                var privateKey = new byte[keyLength];
                Key key;
                do
                {
                    rnd.GetBytes(privateKey);                    
                    key = new Key
                    {
                        PrivateKey = privateKey,
                        PublicKey = null
                    };                    
                }
                while (!ecdsa.IsPrivateKeyValid(key));                

                return privateKey;
            }
        }        
    }
}
