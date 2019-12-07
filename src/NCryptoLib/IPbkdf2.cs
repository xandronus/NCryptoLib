using System;
using System.Collections.Generic;
using System.Text;

namespace NCryptoLib
{
    // TODO: Use Rfc2898DeriveBytes
    // https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.rfc2898derivebytes?view=netframework-4.8
    // bytes = KDTable[mnemonic]
    // return Pbkdf2.ComputeDerivedKey(new HMACSHA512(bytes), salt, 2048, 64);
    // https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
    // https://github.com/realindiahotel/BIP39.NET
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1040:Avoid empty interfaces", Justification = "TODO: Item")]
    public interface IPbkdf2
    {
    }
}
