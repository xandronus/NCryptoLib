using System;

namespace NCryptoLib.ECDsa
{
    /// <summary>
    /// Interface for Elliptical Curve Digital Signature algorithms
    /// </summary>
    public interface IECDsa
    {
        public Span<byte> CreateSecret(DisposableContext? context = null);
        public Key CreatePrivateKey(DisposableContext? context = null);
        public Key CreateKey(DisposableContext? context = null);
        public Key CreateKey(Span<byte> privateKey, DisposableContext? context = null);
        public bool IsPrivateKeyValid(Key key, DisposableContext? context = null);
        
        /// <summary>
        /// Signs the data by computing SHA-256 hash and then signing the hash - with the given key
        /// </summary>
        /// <param name="data">Data to sign</param>
        /// <param name="key">key to sign with</param>
        /// <param name="context">optional context</param>
        /// <returns>the signature</returns>
        public Signature SignData(byte[] data, Key key, DisposableContext? context = null);

        /// <summary>
        /// Signs the data by computing SHA-256 hash and then signing the hash - assumes signing key is in the context
        /// Most efficient for MsftECDsaCng as the key is part of the context
        /// </summary>
        /// <param name="data">Data to sign</param>
        /// <param name="context">ECDsa context</param>
        /// <returns>the signature</returns>
        /// <exception cref="CryptoException">thrown if attempted on <see cref="Secp256k1DotNet"/></exception>
        public Signature SignData(byte[] data, DisposableContext? context);

        /// <summary>
        /// Signs the hash - assumes signing key is in the context
        /// Most efficient for MsftECDsaCng as the key is part of the context
        /// </summary>
        /// <param name="hash">hash to sign</param>
        /// <param name="context">ECDsa context</param>
        /// <returns>the signature</returns>
        /// <exception cref="CryptoException">thrown if attempted on <see cref="Secp256k1DotNet"/></exception>
        public Signature SignHash(Hash256 hash, DisposableContext? context);

        /// <summary>
        /// Signs the hash - with the given key
        /// If using MsftECDsaCng the SignHash method with no key is more efficent
        /// </summary>
        /// <param name="hash">hash to sign</param>
        /// <param name="key">key to sign with</param>
        /// <param name="context">optional context</param>
        /// <returns>The signature</returns>
        public Signature SignHash(Hash256 hash, Key key, DisposableContext? context = null);

        /// <summary>
        /// Verify the data signature by computing SHA-256 hash and then verify the hash signature - with the given key
        /// If using MsftECSsaCng the VerifyData method with no key is more efficient        
        /// </summary>
        /// <param name="data">data to verify signature</param>
        /// <param name="signature">signature to verify</param>
        /// <param name="key">key used to verify signature</param>
        /// <param name="context">optional context</param>
        /// <returns>true if valid signature, false if not</returns>
        public bool VerifyData(byte[] data, Signature signature, Key key, DisposableContext? context = null);

        /// <summary>
        /// Verify the data signature by computing SHA-256 hash and then verify the hash signature - assumes signing key is in the context
        /// Most efficient for MsftECDsaCng as the key is part of the context
        /// </summary>
        /// <param name="data">data to verify signature</param>
        /// <param name="signature">signature to verify</param>
        /// <param name="context">ECDsa context</param>
        /// <returns>true if valid signature, false if not</returns>
        /// <exception cref="CryptoException">thrown if attempted on <see cref="Secp256k1DotNet"/></exception>
        public bool VerifyData(byte[] data, Signature signature, DisposableContext? context);
        
        /// <summary>
        /// Verify the signature of a hash - with the given key
        /// If using MsftECSsaCng the VerifyHash method with no key is more efficient
        /// </summary>
        /// <param name="hash">hash to verify</param>
        /// <param name="signature">signature to verify</param>
        /// <param name="key">key to use for verification</param>
        /// <param name="context">optional context</param>
        /// <returns>true if valid signature, false if not</returns>
        public bool VerifyHash(Hash256 hash, Signature signature, Key key, DisposableContext? context = null);

        /// <summary>
        /// Verify the signature of a hash - key is assumed to be in the context
        /// Most efficient for MsftECDsaCng as the key is part of the context
        /// </summary>
        /// <param name="hash">hash to verify</param>
        /// <param name="signature">signature to verify</param>
        /// <param name="context">context containing key</param>
        /// <returns>true if valid signature, false if not</returns>
        /// <exception cref="CryptoException">thrown if attempted on <see cref="Secp256k1DotNet"/></exception>
        public bool VerifyHash(Hash256 hash, Signature signature, DisposableContext? context);

        /// <summary>
        /// Creates a public key from a private key
        /// </summary>
        /// <param name="privateKey">source private key</param>
        /// <param name="context">optional context</param>
        /// <returns>the public key, exception if can't create it</returns>
        /// <exception cref="CryptoException">when public key can't be created</exception>
        public Span<byte> CreatePublicKey(Span<byte> privateKey, DisposableContext? context = null);

        /// <summary>
        /// Derives the compressed public key from the uncompressed public key
        /// </summary>
        /// <param name="uncompressed">uncompressed public key (64 bytes)</param>
        /// <param name="context">optional context</param>
        /// <returns>compressed public key 33 bytes</returns>
        public Span<byte> CompressPublicKey(Span<byte> uncompressed, DisposableContext? context = null);
    }
}
