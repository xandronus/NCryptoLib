# NCryptoLib
Purpose of this project is to provide CryptoCurrency and Cryptography related algorithms using the latest C# language features for use in BlockChain development. Initial goals are to cover some key algorithms in use in Bitcoin and Ethereum BlockChains.

[![Build Status](https://dev.azure.com/xandronus/NCryptoLib/_apis/build/status/xandronus.NCryptoLib?branchName=master)](https://dev.azure.com/xandronus/NCryptoLib/_build/latest?definitionId=1&branchName=master)

Currently targeting C# 8 and .NET Core 3.0 only

| Interface | Implementation | Description |
| --- | --- | --- |
| IECDsa |                 | Elliptical Curve Digital Signature Algorithms |
|       | Secp2561kDotNet | Bitcoin ECDSA algo. |
|       | MsftECDsaCng | Microsofts ECDSA algo. |
| IHasher |                 | Hashing Algorithms |
|       | MsftHasher | Microsofts SHA256 and RIPEMD160 hash algo. |

Library is optimized to use span and stack allocations over heap objects for performance

Sample code to get a P2PKH bitcoin address from a private key:

```c#
// Example address from https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses
var privateKey = "18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321725".HexToBytes();
IECDsa ecdsa = new Secp256k1DotNet();
var key = ecdsa.CreateKey(privateKey);
string p2pkhAddress = Address.GetP2PKHAddress(key, ecdsa, Bitcoin.Network.MainNet.P2PKHAddressVersion);
// returns "1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs"
```

_Project is currently in development - no published packages at this time._

### **Contributions and suggestions welcome!** ###

---

*Security Disclosure:* xandronus@gmail.com
