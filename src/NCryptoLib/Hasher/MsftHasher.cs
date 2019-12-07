using System;
using System.Security.Cryptography;

namespace NCryptoLib.Hasher
{
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Using alternative dispose pattern")]
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Security", "CA5350:Do Not Use Weak Cryptographic Algorithms", Justification = "LOL thanks for the hint MS")]
    public class MsftHasher : IHasher
    {
        public Hash160 RIPEMD160(Hash256 hash, DisposableContext? context = null)
        {            
            var hashAlgo = context?.Context as RIPEMD160Managed;
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

        public Hash256 SHA256(byte[] data, int offset, int count, DisposableContext? context = null)
        {
            var sha = context?.Context as SHA256Managed;
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
