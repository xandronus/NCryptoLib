using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace NCryptoLib.ECDsa
{
    public sealed class MsftECDsaContext : DisposableContext, IDisposable
    {
        public MsftECDsaContext(ECDsaCng context) : base(context)
        { }

        /// <summary>
        /// Creates a ECDsa context from a private/public key pair
        /// </summary>
        /// <param name="key">Private/Public key pair</param>
        public MsftECDsaContext(Key key) : base(null)
        {
            base.Context = key.ToECDsaCngKey();
        }

        public void Dispose()
        {
            var context = this.Context as ECDsaCng;
            context?.Dispose();
        }
    }
}
