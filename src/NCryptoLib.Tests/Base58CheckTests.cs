using FluentAssertions;
using NCryptoLib.Bitcoin;
using NCryptoLib.ECDsa;
using System;
using System.Collections.Generic;
using System.Text;
using Xunit;

namespace NCryptoLib.Tests
{
    public class Base58CheckTests
    {
        [Fact]
        public void TestEncoding()
        {
            // Example address from https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses
            var addressBytes = "00f54a5851e9372b87810a8e60cdd2e7cfd80b6e31".HexToBytes();
            const string base58Expected = "1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs";

            var base58Actual = Base58CheckEncoding.Encode(addressBytes);
            base58Actual.Should().BeEquivalentTo(base58Expected);
        }

        [Fact]
        public void TestP2PKH()
        {
            // Example address from https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses
            var publicKey = "0250863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352".HexToBytes();
            const string base58Expected = "1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs";

            var base58Actual = publicKey.Hash().RIPEMD160().ToP2PKHAddress(new byte[] { 0x00 });
            base58Actual.Should().BeEquivalentTo(base58Expected);
        }
    }
}
