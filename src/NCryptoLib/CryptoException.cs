using System;
using System.Collections.Generic;
using System.Text;

namespace NCryptoLib
{
    public class CryptoException : Exception
    {
        public CryptoException(string message) : base(message)
        {
        }

        public CryptoException(string message, Exception innerException) : base(message, innerException)
        {
        }

        public CryptoException()
        {
        }
    }
}
