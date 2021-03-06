﻿using Secp256k1Net;
using System;
using System.Collections.Generic;
using System.Text;

namespace NCryptoLib.ECDsa
{
    public sealed class Secp256k1DotNetContext : DisposableContext, IDisposable
    {
        public Secp256k1DotNetContext(Secp256k1 context): base(context)
        {
        }

        public void Dispose()
        {
            var context = this.Context as Secp256k1;
            if (context != null)
                context.Dispose();
        }
    }
}
