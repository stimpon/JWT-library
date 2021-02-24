/// <summary>
/// Root library namespace
/// </summary>
namespace JWTLib
{
    // Required namespaces
    using System;
    using System.Text;
    using Newtonsoft.Json;
    using System.Security.Cryptography;

    /// <summary>
    /// Builder for creating JWT tokens using JWE
    /// </summary>
    public static class JWETokenBuilder
    {

        /// <summary>
        /// Builds the token.
        /// </summary>
        /// <param name="mode">The algorithm to use.</param>
        /// <param name="payload">The payload to encrypt</param>
        /// <param name="key">The key<br/>
        ///     <see cref="RSAParameters"/>: If RSA algorithm is used
        /// </param>
        /// <param name="serializePayload">If the payload is an object and needs to be serialized, set to true</param>
        /// <returns></returns>
        public static JWEToken BuildToken(JWEAlgorithms mode, object payload, object key, bool serializePayload = false)
        {
            // If the payload is empty...
            if (payload == null) throw new Exception("No payload has been set");

            // Get the correct encryption mode for this algorithm
            var encMode =
                (JWEEncryptionModes)Enum.Parse(typeof(JWEEncryptionModes), EnumHelpers.ExtractDescriptor(mode));

            // Create the protected header
            var protectedHeader = new JWEProtectedHeader()
            {
                Algorithm = mode,
                EncryptionMode = encMode,
                Type = TokenTypes.JWT
            };

            // Serialize the payload if requested to do so
            if (serializePayload) payload = JsonConvert.SerializeObject(payload);

            // Check what algorithm to use...
            if (mode == 0)
            {
                /// <summary>
                /// RSA with OAEP should be used
                /// </summary>

                // Get a new encryptor and random key
                var encryptorTuple = Data.GetAesGcmEncryptor(int.Parse(EnumHelpers.ExtractDescriptor(encMode)));

                // Create an encryptor
                using (var encryptor = encryptorTuple.aesGcm)
                {
                    // Try to build the compact JWT JWE
                    try
                    {
                        // Create placeholder for the IV/NONCE
                        byte[] NONCE = new byte[12];

                        // Create a random number generator for the NONE/IV
                        using (var RNG = RandomNumberGenerator.Create())
                        {
                            // Fill IV/NONCE array with 12 random bytes
                            RNG.GetBytes(NONCE);
                        }

                        // Arrays to put the ciphertext, tag and protected header in
                        byte[] cipherText = new byte[((string)payload).Length];
                        byte[] tag = new byte[16];
                        byte[] protected_header = Encoding.Default.GetBytes(JsonConvert.SerializeObject(protectedHeader));

                        // Create spans for the encryptor
                        Span<byte> cipherTextSpan = new Span<byte>(cipherText),
                            nonceSpan = new Span<byte>(NONCE),
                            payloadSpan = new Span<byte>(Encoding.UTF8.GetBytes((string)payload)),
                            tagSpan = new Span<byte>(tag),
                            protectedSpan = new Span<byte>(protected_header);

                        // Encrypt the payload and get the authentication tag
                        encryptor.Encrypt(nonceSpan, payloadSpan, cipherTextSpan, tagSpan, protectedSpan);

                        // Create a new token and assign it null
                        JWEToken token = null;

                        // Create a new provider
                        using (var provider = new RSACryptoServiceProvider())
                        {
                            // Import private key
                            provider.ImportParameters((RSAParameters)key);

                            // Create JWE Result
                            token = new JWEToken
                            {
                                ProtectedHeader = JsonConvert.SerializeObject(protectedHeader).ToBase64Url(),
                                EncryptedKey    = provider.Encrypt(encryptorTuple.key, true).ToBase64Url(),
                                IV              = nonceSpan.ToBase64Url(),
                                Ciphertext      = cipherText.ToBase64Url(),
                                Tag             = tag.ToBase64Url(),
                            };
                        }

                        // Return the JWE
                        return token;
                    }
                    // If build failed...
                    catch (Exception ex) { throw new Exception(ex.Message); } // Return error
                }
            }

            throw new Exception();
        }

    }
}
