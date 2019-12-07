using System;
using System.Collections.Generic;
using System.Text;

namespace NCryptoLib
{
    /// <summary>
    /// Base class that holds the context of IDisposable object
    /// </summary>
    public class DisposableContext
    {
        public DisposableContext(object? context)
        {
            Context = context;
        }

        public object? Context { get; protected set; }
    }
}
