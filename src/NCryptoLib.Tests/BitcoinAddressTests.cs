using FluentAssertions;
using NCryptoLib.Bitcoin;
using NCryptoLib.ECDsa;
using System;
using System.Collections.Generic;
using System.Text;
using Xunit;

namespace NCryptoLib.Tests
{
    public class BitcoinAddressTests
    {
        [Fact]
        public void TestP2PKHFromKey()
        {
            // Example address from https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses
            var privateKey = "18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321725".HexToBytes();
            IECDsa ecdsa = new Secp256k1DotNet();
            var key = ecdsa.CreateKey(privateKey);            
            string p2pkhAddress = Address.GetP2PKHAddress(key, ecdsa, Bitcoin.Network.MainNet.P2PKHAddressVersion);
            p2pkhAddress.Should().BeEquivalentTo("1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs");
        }

        [Fact]
        public void TestSECCompressedPublicKey()
        {
            // This key should generate a 0x02 compressed public key
            var privateKeyEven = "18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321725".HexToBytes();

            // This key should generate a 0x03 compressed public key
            var privateKeyOdd  = "79FE45D61339181238E49424E905446A35497A8ADEA8B7D5241A1E7F2C95A04D".HexToBytes();

            // Use Secp256k1 to generate the key because MSFT version does not support import privateKey with
            // no public key.
            IECDsa secp256k1 = new Secp256k1DotNet();
            var evenKey = secp256k1.CreateKey(privateKeyEven);

            var msftecdsa = new MsftECDsaCng();
            var evenBtc = secp256k1.GetSECCompressedPublicKey(evenKey.PublicKey);
            var evenMsft = msftecdsa.GetSECCompressedPublicKey(evenKey.PublicKey);
            Assert.Equal(evenBtc.ToArray(), evenMsft.ToArray());

            var oddKey = secp256k1.CreateKey(privateKeyOdd);
            var oddBtc = secp256k1.GetSECCompressedPublicKey(oddKey.PublicKey);
            var oddMsft = msftecdsa.GetSECCompressedPublicKey(oddKey.PublicKey);
            Assert.Equal(oddBtc.ToArray(), oddMsft.ToArray());
        }

        [Fact]
        public void TestSECUncompressedPublicKey()
        {
            // This key should generate a 0x02 compressed public key
            var privateKey = "18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321725".HexToBytes();

            // Use Secp256k1 to generate the key because MSFT version does not support import privateKey with
            // no public key.
            IECDsa secp256k1 = new Secp256k1DotNet();
            var key = secp256k1.CreateKey(privateKey);

            var msftecdsa = new MsftECDsaCng();
            var btc = secp256k1.GetSECUncompressedPublicKey(key.PublicKey);
            var msft = msftecdsa.GetSECUncompressedPublicKey(key.PublicKey);
            Assert.Equal(btc.ToArray(), msft.ToArray());
        }

        [Fact]
        public void TestMsftECsaGenP2PKH()
        {
            var privateKey = "18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321725".HexToBytes();

            // Use Secp256k1 to generate the key because MSFT version does support import privateKey with
            // no public key.
            IECDsa secp256k1 = new Secp256k1DotNet();
            var key = secp256k1.CreateKey(privateKey);

            var msftecdsa = new MsftECDsaCng();
            string p2pkhAddress = Address.GetP2PKHAddress(key, msftecdsa, Bitcoin.Network.MainNet.P2PKHAddressVersion);
            p2pkhAddress.Should().BeEquivalentTo("1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs");
        }
    }
}
