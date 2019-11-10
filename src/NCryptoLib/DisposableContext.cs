using System;
using System.Collections.Generic;
using System.Text;

namespace NCryptoLib
{
    public class DisposableContext
    {
        public DisposableContext(object context)
        {
            Context = context;
        }

        public object Context { get; protected set; }
    }
}
