using System;
using System.Collections.Generic;
using System.Text;

namespace NCryptoLib.ECDsa
{
    public class ECDsaContext
    {
        public ECDsaContext(object context)
        {
            this.Context = context;
        }

        public object Context { get; protected set; }
    }
}
