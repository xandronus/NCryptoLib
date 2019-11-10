using System.Security.Cryptography;

namespace NCryptoLib.Hasher
{
    public class MsftHasherContext : DisposableContext
    {
        public MsftHasherContext(SHA256Managed context) : base(context)
        { }
    }
}
