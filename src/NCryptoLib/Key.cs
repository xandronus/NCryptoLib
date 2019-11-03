using System;
using System.Collections.Generic;
using System.Text;

namespace NCryptoLib
{
    public ref struct Key
    {
        public Span<byte> PrivateKey;
        public Span<byte> PublicKey;
    }
}
