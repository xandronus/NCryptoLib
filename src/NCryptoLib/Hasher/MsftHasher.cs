using System;
using System.Security.Cryptography;

namespace NCryptoLib.Hasher
{
    public class MsftHasher : IHasher
    {
        public Hash256 SHA256(byte[] data, int offset, int count, DisposableContext context = null)
        {
            SHA256Managed sha = context?.Context as SHA256Managed;
            if (sha == null)
            {
                sha = new SHA256Managed();
            }

            try
            {
                return new Hash256 { Bytes = sha.ComputeHash(data, offset, count) };
            }
            finally
            {
                if (context == null)
                    sha?.Dispose();
            }
        }    
    }
}
