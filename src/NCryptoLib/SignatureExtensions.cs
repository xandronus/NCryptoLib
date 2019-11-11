using System;
using System.Collections.Generic;
using System.Text;

namespace NCryptoLib
{ 
    public static class SignatureExtensions
    {
        public static Span<byte> GetR(this Signature signature)
        {
            return signature.Bytes.Slice(0, 32);
        }

        public static Span<byte> GetS(this Signature signature)
        {
            return signature.Bytes.Slice(32, 32);
        }

        public static Signature Set(this Signature signature, Span<byte> R, Span<byte> S)
        {
            R.CopyTo(signature.Bytes);
            S.CopyTo(signature.Bytes.Slice(32));
            return signature;
        }
    }
}
