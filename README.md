# NCryptoLib
Purpose of this project is to provide CryptoCurrency and Cryptography related algorithms using the latest C# language features for use in BlockChain development. Initial goals are to cover some key algorithms in use in Bitcoin and Ethereum BlockChains.

Currently targeting C# 8 and .NET Core 3.0 only

| Interface | Implementation | Description |
| --- | --- | --- |
| IECDsa |                 | Elliptical Curve Digital Signature Algorithms |
|       | Secp2561kDotNet | Bitcoin ECDSA algo. |
|       | MsftECDsaCng | Microsofts ECDSA algo. |
| IHasher |                 | Hashing Algorithms |
|       | MsftHasher | Microsofts SHA256Managed algo. |

_Project is currently in development - no published packages or CI at this time._

### **Contributions and suggestions welcome!** ###

---

*Security Disclosure:* xandronus@gmail.com