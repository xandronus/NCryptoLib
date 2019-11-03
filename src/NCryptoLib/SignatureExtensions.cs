using System;
using System.Collections.Generic;
using System.Text;

namespace NCryptoLib
{ 
    public static class SignatureExtensions
    {
        public static Span<byte> GetR(this Signature signature)
        {
            return signature.Data.Slice(0, 32);
        }

        public static Span<byte> GetS(this Signature signature)
        {
            return signature.Data.Slice(32, 32);
        }

        public static Signature Set(this Signature signature, Span<byte> R, Span<byte> S)
        {
            R.CopyTo(signature.Data);
            S.CopyTo(signature.Data.Slice(32));
            return signature;
        }
    }
}
