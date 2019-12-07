using System;
using System.Collections.Generic;
using System.Text;

namespace NCryptoLib
{
    public ref struct Key
    {
        public Span<byte> PrivateKey { get; set; }
        public Span<byte> PublicKey { get; set; }
    }
}
