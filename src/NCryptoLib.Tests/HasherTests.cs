using NCryptoLib.Hasher;
using System;
using System.Collections.Generic;
using FluentAssertions;
using System.Text;
using Xunit;

namespace NCryptoLib.Tests
{
    public class HasherTests
    {
        [Fact]
        public void TestSHA256()
        {
            MsftHasher hasher = new MsftHasher();
            string input = "t6MJu}q<&4Krk,9<";
            const string expectedHash = "EC69618987A118C309AF5C1E880A28366865794C40769345EB3D6D0CFA8681BB";
            var hash = input.HashOfText();
            expectedHash.Should().BeEquivalentTo(hash.ToHexString());
        }

        [Fact]
        public void TestHash256Equality()
        {
            const string expectedHash = "EC69618987A118C309AF5C1E880A28366865794C40769345EB3D6D0CFA8681BB";
            Hash256 hash1 = new Hash256(expectedHash);
            Hash256 hash2 = new Hash256(expectedHash.HexToBytes());
            var hash3 = "a random string".HashOfText();
            Assert.True(hash1 == hash2);
            Assert.False(hash1 == hash3);
        }
    }
}
