/// <summary>
/// Root namespace
/// </summary>
namespace JWTLib
{
    // Required namespaces
    using System.Collections.Generic;
    using System.Security.Cryptography;

    /// <summary>
    /// Contains data required when building tokens
    /// </summary>
    internal static class Data
    {
        /// <summary>
        /// Array that contains available hashers
        /// </summary>
        internal static HashAlgorithm[] Hashers =
        {
            #region SHA hashers
            // SHA hashers are here
            SHA256.Create(), // SHA256 hasher [0]
            SHA384.Create(), // SHA386 hasher [1]
            SHA512.Create(), // SHA512 hasher [2]

            #endregion
        
            #region HMAC hashers
            // HMAC hashers are here
            new HMACSHA256(), // HMACSHA256 [3]
            new HMACSHA384(), // HMACSHA256 [4]
            new HMACSHA512() // HMACSHA256 [5]

            #endregion
        };

        /// <summary>
        /// Gets the AesGcm encryptor.
        /// </summary>
        /// <param name="keySize">Size of the key.</param>
        /// <returns>A tuple containing the key and the encryptor</returns>
        internal static (AesGcm aesGcm, byte[] key) GetAesGcmEncryptor(int keySize)
        {
            // Declare an AesGCM encryptor
            AesGcm alg;

            // Create return object
            (AesGcm, byte[]) obj;

            // Create key placeholder of 256 bits
            byte[] UnencryptedKey = new byte[keySize];
            // Create a random number generator
            using (var RNG = RandomNumberGenerator.Create())
            {
                // Fill byte array with random bytes
                RNG.GetBytes(UnencryptedKey);
            }

            // Create AES encryptor and set the key size
            obj.Item1 = new AesGcm(UnencryptedKey);
            // Save key in tuple
            obj.Item2 = UnencryptedKey;

            // Return the encryptor
            return obj;
        }

        /// <summary>
        /// Returns a new AesGcm decryptor with the provided secret key
        /// </summary>
        /// <typeparam name="Byte">The key.</typeparam>
        /// <returns></returns>
        internal static AesGcm GetAesGcmDecryptor(byte[] key) 
        => 
        new AesGcm(key);

        /// <summary>
        /// Character mappings for Base64Url strings
        /// </summary>
        internal static Dictionary<char, char> UrlCharMappings = new Dictionary<char, char>()
        {
            { '+', '-' }, // Replace all '+' signs with '-'s
            { '/', '_' }  // Replace all '/' signs with '_'s
        };
    }
}
