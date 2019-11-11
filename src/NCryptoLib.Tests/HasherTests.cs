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
            var bytes = UTF8Encoding.UTF8.GetBytes(input);
            var hash = hasher.SHA256(bytes, 0, input.Length);
            expectedHash.Should().BeEquivalentTo(hash.ToHexString());
        }
    }
}
