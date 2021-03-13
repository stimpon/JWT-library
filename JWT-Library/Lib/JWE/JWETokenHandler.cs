/// <summary>
/// Root namespace
/// </summary>
namespace JWTLib
{
    //Required namespaces
    using System;
    using System.Text;
    using Newtonsoft.Json;
    using System.Security.Cryptography;

    /// <summary>
    /// Contains functions for processing JWTs using JWE 
    /// </summary>
    public static class JWETokenHandler
    {
        #region Public properties

        /// <summary>
        /// Decrypts the ciphertext in the token and returns it as plain text
        /// </summary>
        /// <typeparam name="Token">The token type</typeparam>
        /// <param name="token">The token.</param>
        /// <param name="key"> The key<br/>
        ///     <see cref="RSAParameters"/>: If RSA was used for encrypting secret key
        /// </param>
        /// <returns>
        ///     The decrypted text 
        /// </returns>
        /// Not implemented yet
        /// </exception>
        public static string DecryptCipherTextAsString<Token>(Token token, object key)
            where Token: IJWEToken, new()
        {
            // Just decrypt the text and return it
            return DecryptText<Token>(token, key);
        }

        /// <summary>
        /// Decrypts the ciphertext in the token and returns it as the specified object
        /// </summary>
        /// <typeparam name="Token">The token type</typeparam>
        /// <typeparam name="PayloadType">The type to convert the decrypted text into</typeparam>
        /// <param name="token">The token.</param>
        /// <param name="key"> The key<br/>
        ///     <see cref="RSAParameters"/>: If RSA was used for encrypting secret key
        /// </param>
        /// <returns>
        ///     The deserialized object 
        /// </returns>
        /// Not implemented yet
        /// </exception>
        public static PayloadType DecryptCipherTextAsObject<Token, PayloadType>(Token token, object key, PayloadType type)
            where Token : IJWEToken, new() where PayloadType: class, new()
        {
            // Deserialize the object and return it
            return 
                JsonConvert.DeserializeObject<PayloadType>(DecryptText<Token>(token, key));
        }

        /// <summary>
        /// Converts the token string into the spcified object type
        /// </summary>
        /// <typeparam name="Token">The token type</typeparam>
        /// <param name="JWE">The token string (in base64url)</param>
        /// <returns>
        ///     <see cref="JWEToken"/> : If conversion was successful<br/>
        ///     null: If the convertsion failed
        /// </returns>
        public static IJWEToken ToToken<Token>(string JWE)
            where Token: IJWEToken, new()
        {
            // Token string must be 5 pieces split with dots
            if(JWE.Split('.').Length == 5)
            {
                // Create the token
                return new Token()
                {
                    ProtectedHeader = JWE.Split('.')[0],
                    EncryptedKey    = JWE.Split('.')[1],
                    IV              = JWE.Split('.')[2],
                    Ciphertext      = JWE.Split('.')[3],
                    Tag             = JWE.Split('.')[4]
                };
            }

            // return the token or null
            return null;
        }

        /// <summary>
        /// Resolves the header into a usable object
        /// </summary>
        /// <typeparam name="PH">The ptotected header type</typeparam>
        /// <param name="rawProtectedHeader">The raw base64url envoded header</param>
        /// <returns>
        ///     <see cref="JWEToken{PH}"/>: If the conversion was successful<br/>
        ///     null: If conversion failed
        /// </returns>
        public static IJWEProtectedHeader ResolveHeader<PH>(string rawProtectedHeader)
            where PH: IJWEProtectedHeader
        {
            // Try to Deserialize the provided header string
            try
            {
                // Deserialize and return
                return JsonConvert.DeserializeObject<PH>(rawProtectedHeader);
            }
            // If convertsion failed
            catch (Exception)
            {
                // Return null
                return null;
            }
        }

        #endregion

        #region Private functions

        /// <summary>
        /// Decrypts the cipher text in the token
        /// </summary>
        /// <typeparam name="Token">The ttoken type</typeparam>
        /// <param name="token">The token.</param>
        /// <param name="key">The key used for encryption.</param>
        /// <returns>
        /// The decrypted text
        /// </returns>
        /// <exception cref="System.Exception"></exception>
        private static string DecryptText<Token>(Token token, object key)
            where Token : IJWEToken, new()
        {
            // Create key placeholder, clear this when function is complete
            byte[] decryptedKey = new byte[0];

            // Delcare result
            string result = null;

            // Try resolving the payload

            try
            {
                // Extract header as JWE header
                var protHeader = JsonConvert.DeserializeObject<JWEProtectedHeader>(Encoding.Default.GetString(
                    token.ProtectedHeader.FromBase64Url()));

                #region Decrypt encryption key

                // Check algorithm used in JWE

                // RSA
                if ((int)protHeader.Algorithm == 0)
                {
                    /// RSA MODE

                    // Create a new RSA crypto service provider
                    using (var provider = new RSACryptoServiceProvider())
                    {
                        // Import secret key
                        // This will fail if an incorrenct object was provided
                        provider.ImportParameters((RSAParameters)key);

                        // This must be a private key in order to decrypt the secret key
                        if (provider.PublicOnly) throw new System.Exception();

                        // Decrypt the asymetric key
                        decryptedKey = provider.Decrypt(token.EncryptedKey.FromBase64Url(), true);
                    }
                }

                #endregion

                #region Decrypt payload

                // Check encryption algorithm used when encrypting the payload

                // AesGCM
                if ((int)protHeader.EncryptionMode >= 0 && (int)protHeader.EncryptionMode <= 1)
                {
                    /// AesGcm MODE

                    // Get the key size from attriute
                    var dec = int.Parse(
                        EnumHelpers.ExtractDescriptor(protHeader.EncryptionMode));

                    // Span for the plain text
                    byte[] decryptedText = new byte[token.Ciphertext.FromBase64Url().Length];
                    var plainText = new Span<byte>(decryptedText);

                    // Get the correct decryptor
                    Data.GetAesGcmDecryptor(decryptedKey).Decrypt(
                        new Span<byte>(token.IV.FromBase64Url()),         // Import nonce from JWE
                        new Span<byte>(token.Ciphertext.FromBase64Url()), // Import ciphertext from JWE
                        new Span<byte>(token.Tag.FromBase64Url()),        // Import tag from JWE
                        plainText,                                        // Put plain text in here
                        new Span<byte>(token.ProtectedHeader.FromBase64Url())); // Import protected header from JWe 

                    // Convert text bytes to string
                    result = Encoding.Default.GetString(plainText);
                }

                #endregion

                // Return the result
                return result;
            }
            // Error occurred while resolving payload
            catch
            {
                // Could not resolve payload
                return null;
            }
            finally
            {
                // Release arrays (GC will take take care of them after this point)
                decryptedKey = null;
            }
        }

        #endregion
    }
}
