/// <summary>
/// Root namespace
/// </summary>
namespace JWTLib
{
    //Required namespaces
    using System.Security.Cryptography;

    /// <summary>
    /// Contains functions for processing JWTs using JWE 
    /// </summary>
    public static class JWETokenHandler
    {
        /// <summary>
        /// Function for JWE using <see cref="RSA"/> and <see cref="AesGcm"/><br/>
        /// Resolves the cipher text into the correct object. If the cipher text is <br/>
        /// JWS, then <typeparamref name="T"/> should be set to a <see cref="string"/>
        /// </summary>
        /// <typeparam name="T">The decrypted object type</typeparam>
        /// <param name="privateKey">The RSA private key.</param>
        /// <returns></returns>
        public static T ResolveCipherText<T>(RSAParameters privateKey) where T : class, new() 
        {
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
