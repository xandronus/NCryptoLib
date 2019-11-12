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
    }
}
