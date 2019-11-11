using System;
using System.Security.Cryptography;

namespace NCryptoLib.Hasher
{
    public class MsftHasher : IHasher
    {
        public Hash160 RIPEMD160(Hash256 hash, DisposableContext context = null)
        {            
            RIPEMD160Managed hashAlgo = context?.Context as RIPEMD160Managed;
            if (hashAlgo == null)
            {
                hashAlgo = new RIPEMD160Managed();
            }

            try
            {
                return new Hash160(hashAlgo.ComputeHash(hash.Bytes.ToArray(), 0, hash.Bytes.Length));
            }
            finally
            {
                if (context == null)
                    hashAlgo?.Dispose();
            }
        }

        public Hash256 SHA256(byte[] data, int offset, int count, DisposableContext context = null)
        {
            SHA256Managed sha = context?.Context as SHA256Managed;
            if (sha == null)
            {
                sha = new SHA256Managed();
            }

            try
            {
                return new Hash256(sha.ComputeHash(data, offset, count));
            }
            finally
            {
                if (context == null)
                    sha?.Dispose();
            }
        }    
    }
}
