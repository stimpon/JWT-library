/// <summary>
/// Root namespace
/// </summary>
namespace JWTLib
{
    //Required namespaces
    using System;
    using System.Text;
    using System.Text.Json;
    using System.Security.Cryptography;

    /// <summary>
    /// Contains functions for processing JWTs using JWE 
    /// </summary>
    public static class JWETokenHandler
    {
        /// <summary>
        /// Decrypts and returns the payload as a string object
        /// </summary>
        /// <param name="token">
        /// The <see cref="JWEToken"/> object
        /// </param>
        /// <param name="key">
        ///     <see cref="RSAParameters"/>: If RSA was used for encrypting secret key
        /// </param>
        /// <returns></returns>
        public static string ResolveCipherText(JWEToken token, object key)
        {
            // Create key placeholder, clear this when function is complete
            byte[] decryptedKey = new byte[0];

            // Delcare result
            string result = null;

            // Try resolving the payload
            
            try
            {
                // Extract header as JWE header
                var protHeader = JsonSerializer.Deserialize<JWEHeader>(Encoding.Default.GetString(
                    token.ProtectedHeader.FromBase64Url()));

                #region Decrypt encryption key

                // Check algorithm used in JWE

                // RSA
                if ((int)protHeader.alg == 0)
                {
                    /// RSA MODE
                     
                    // Create a new RSA crypto service provider
                    using(var provider = new RSACryptoServiceProvider())
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
                if((int)protHeader.enc >= 0 && (int)protHeader.enc <= 1)
                {
                    /// AesGcm MODE
                    
                    // Get the key size from attriute
                    var dec = int.Parse(
                        EnumHelpers.ExtractDescriptor(protHeader.enc));

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


            throw new System.Exception("Not implemented yet");
        }

        /// <summary>
        /// Converts the token string into a <see cref="JWEToken"/>.
        /// </summary>
        /// <param name="JWE">The jwe.</param>
        /// <returns>
        ///     <see cref="JWEToken"/> : If conversion was successful<br/>
        ///     null: If the convertsion failed
        /// </returns>
        public static JWEToken ToToken(string JWE)
        {
            // Create the token and assign it to null
            JWEToken token = null;

            // Token string must be 5 pieces split with dots
            if(JWE.Split('.').Length == 5)
            {
                // Create the token
                token = new JWEToken()
                {
                    ProtectedHeader = JWE.Split('.')[0],
                    EncryptedKey    = JWE.Split('.')[1],
                    IV              = JWE.Split('.')[2],
                    Ciphertext      = JWE.Split('.')[3],
                    Tag             = JWE.Split('.')[4]
                };
            }

            // return the token or null
            return token;
        }
    }
}
