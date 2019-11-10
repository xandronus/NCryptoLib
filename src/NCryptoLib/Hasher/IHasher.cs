using System;
using System.Collections.Generic;
using System.Text;

namespace NCryptoLib.Hasher
{
    /// <summary>
    /// Interface to hashing algorithms
    ///
    /// </summary>
    public interface IHasher
    {        
        /// <summary>
        /// Computes a SHA256 hash on data
        /// </summary>
        /// <param name="data">data to compute hash on</param>
        /// <param name="offset">offset in bytes of data slice</param>
        /// <param name="count">number of bytes of data from offset</param>
        /// <param name="context">optional hash context</param>
        /// <returns>the 32 byte hash</returns>
        public Hash256 SHA256(byte[] data, int offset, int count, DisposableContext context = null);  
    }
}
