using NCryptoLib.ECDsa;
using System;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using Xunit;

namespace NCryptoLib.Tests
{
    public class ECDsaTests
    {
        [Fact]
        public void TestSecp256k1SignAndVerify()
        {
            var signer = new Secp256k1DotNet();
            var signature = this.TestSign(signer);
        }

        [Fact]
        public void TestMsftSignAndVerify()
        {
            var signer = new MsftECDsaCng();
            var signature = this.TestSign(signer);            
        }

        [Fact]
        public void TestMsftRSAccessors()
        {
            var signer = new MsftECDsaCng();
            this.TestRSAccessors(signer);
        }

        [Fact]
        public void TestSecp256k1RSAccessors()
        {
            var signer = new MsftECDsaCng();
            this.TestRSAccessors(signer);
        }

        private void TestRSAccessors(IECDsa signer)
        {
            Key key = signer.CreateKey();
            using var rnd = RandomNumberGenerator.Create();
            var data = new byte[32];
            rnd.GetBytes(data);
            var signature = signer.SignData(data, key);
            var R = signature.GetR();
            var S = signature.GetS();

            Signature RS = new Signature { Data = new byte[64] };
            RS.Set(R, S);

            Assert.Equal(signature.Data.ToArray(), RS.Data.ToArray());
        }

        private Signature TestSign(IECDsa signer)
        {
            Key key = signer.CreateKey();
            using var rnd = RandomNumberGenerator.Create();

            var data = new byte[32];
            rnd.GetBytes(data);
            var signature = signer.SignData(data, key);
            if (signer.VerifyData(data, signature, key))
                return signature;
            throw new Exception();
        }

        /// <summary>
        /// <seealso cref="https://github.com/MeadowSuite/Secp256k1.Net/blob/master/Secp256k1.Net.Test/Tests.cs"/>
        /// </summary>
        [Fact]
        public void SigningTest()
        {
            //using (var secp256k1 = new Secp256k1())
            //{

            //    Span<byte> signature = new byte[Secp256k1.UNSERIALIZED_SIGNATURE_SIZE];
            //    Span<byte> messageHash = new byte[] { 0xc9, 0xf1, 0xc7, 0x66, 0x85, 0x84, 0x5e, 0xa8, 0x1c, 0xac, 0x99, 0x25, 0xa7, 0x56, 0x58, 0x87, 0xb7, 0x77, 0x1b, 0x34, 0xb3, 0x5e, 0x64, 0x1c, 0xca, 0x85, 0xdb, 0x9f, 0xef, 0xd0, 0xe7, 0x1f };
            //    Span<byte> secretKey = "e815acba8fcf085a0b4141060c13b8017a08da37f2eb1d6a5416adbb621560ef".HexToBytes();

            //    bool result = secp256k1.SignRecoverable(signature, messageHash, secretKey);
            //    Assert.True(result);

            //    // Recover the public key
            //    Span<byte> publicKeyOutput = new byte[Secp256k1.PUBKEY_LENGTH];
            //    result = secp256k1.Recover(publicKeyOutput, signature, messageHash);
            //    Assert.True(result);

            //    // Serialize the public key
            //    Span<byte> serializedKey = new byte[Secp256k1.SERIALIZED_UNCOMPRESSED_PUBKEY_LENGTH];
            //    result = secp256k1.PublicKeySerialize(serializedKey, publicKeyOutput);
            //    Assert.True(result);

            //    // Slice off any prefix.
            //    serializedKey = serializedKey.Slice(serializedKey.Length - Secp256k1.PUBKEY_LENGTH);

            //    Assert.Equal("0x3a2361270fb1bdd220a2fa0f187cc6f85079043a56fb6a968dfad7d7032b07b01213e80ecd4fb41f1500f94698b1117bc9f3335bde5efbb1330271afc6e85e92", serializedKey.ToHexString(), true);

            //    // Verify it works with variables generated from our managed code.
            //    BigInteger ecdsa_r = BigInteger.Parse("68932463183462156574914988273446447389145511361487771160486080715355143414637");
            //    BigInteger ecdsa_s = BigInteger.Parse("47416572686988136438359045243120473513988610648720291068939984598262749281683");
            //    byte recoveryId = 1;

            //    byte[] ecdsa_r_bytes = BigIntegerConverter.GetBytes(ecdsa_r);
            //    byte[] ecdsa_s_bytes = BigIntegerConverter.GetBytes(ecdsa_s);
            //    signature = ecdsa_r_bytes.Concat(ecdsa_s_bytes).ToArray();

            //    // Allocate memory for the signature and create a serialized-format signature to deserialize into our native format (platform dependent, hence why we do this).
            //    Span<byte> serializedSignature = ecdsa_r_bytes.Concat(ecdsa_s_bytes).ToArray();
            //    signature = new byte[Secp256k1.UNSERIALIZED_SIGNATURE_SIZE];
            //    result = secp256k1.RecoverableSignatureParseCompact(signature, serializedSignature, recoveryId);
            //    if (!result)
            //        throw new Exception("Unmanaged EC library failed to parse serialized signature.");

            //    // Recover the public key
            //    publicKeyOutput = new byte[Secp256k1.PUBKEY_LENGTH];
            //    result = secp256k1.Recover(publicKeyOutput, signature, messageHash);
            //    Assert.True(result);

            //    // Serialize the public key
            //    serializedKey = new byte[Secp256k1.SERIALIZED_UNCOMPRESSED_PUBKEY_LENGTH];
            //    result = secp256k1.PublicKeySerialize(serializedKey, publicKeyOutput);
            //    Assert.True(result);

            //    // Slice off any prefix.
            //    serializedKey = serializedKey.Slice(serializedKey.Length - Secp256k1.PUBKEY_LENGTH);

            //    // Assert our key
            //    Assert.Equal("0x3a2361270fb1bdd220a2fa0f187cc6f85079043a56fb6a968dfad7d7032b07b01213e80ecd4fb41f1500f94698b1117bc9f3335bde5efbb1330271afc6e85e92", serializedKey.ToHexString(), true);
            //}
        }

        [Fact]
        public void ValidateSameAsBitcoin()
        {
            //Example private key taken from https://en.bitcoin.it/wiki/Private_key
            byte[] privateKey = new byte[32] { 0xE9, 0x87, 0x3D, 0x79, 0xC6, 0xD8, 0x7D, 0xC0, 0xFB, 0x6A, 0x57, 0x78, 0x63, 0x33, 0x89, 0xF4, 0x45, 0x32, 0x13, 0x30, 0x3D, 0xA6, 0x1F, 0x20, 0xBD, 0x67, 0xFC, 0x23, 0x3A, 0xA3, 0x32, 0x62 };
            //Key key1 = new Key(privateKey, -1, false);

            //ISecret wifKey = key1.GetWif(NBitcoin.Network.Main);

            ////Example wif private key taken from https://en.bitcoin.it/wiki/Private_key
            const string expected = "5Kb8kLf9zgWQnogidDA76MzPL6TsZZY36hWXMssSzNydYXYB9KF";
            //Assert.True(wifKey.ToString() == expected);
        }
    }
}