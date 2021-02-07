namespace JWTLib
{
    // Required namespaces
    using System;
    using System.Collections;
    using System.Collections.Generic;
    using System.Security.Cryptography;

    /// <summary>
    /// Contains helper data
    /// </summary>
    internal static class Data
    {
        /// <summary>
        /// array that contain functions for creating hashes
        /// </summary>
        internal static HashAlgorithm[] Hashers =
        {
            SHA256.Create(), // SHA256 hasher
            SHA384.Create(), // SHA386 hasher
            SHA512.Create()  // SHA512 hasher
        };

        /// <summary>
        /// Creates and returns a new encryptor
        /// </summary>
        /// <param name="type">The type.</param>
        /// <returns></returns>
        internal static SymmetricAlgorithm GetEncryptor(EncryptionTypes type)
        {
            // Declare a symetric alhorithm
            SymmetricAlgorithm alg;
            // Check what encryptor to return
            switch (type)
            {
                case EncryptionTypes.AES128: // Aes with a key size of 128 bits
                    // Create AES encryptor and set the key size
                    alg = Aes.Create(); alg.KeySize = 128;
                    // return the encryptor
                    return alg;
                case EncryptionTypes.AES192: // Aes with a key size of 192 bits
                    // Create AES encryptor and set the key size
                    alg = Aes.Create(); alg.KeySize = 192;
                    // return the encryptor
                    return alg;
                case EncryptionTypes.AES256: // Aes with a key size of 256 bits
                    // Create AES encryptor and set the key size
                    alg = Aes.Create(); alg.KeySize = 256;
                    // return the encryptor
                    return alg;
                    
                default: return null; // If invalid option was passed
            }
        }

        /// <summary>
        /// The URL character mappings for safe Base64 strings
        /// </summary>
        internal static Dictionary<char, char> UrlCharMappings = new Dictionary<char, char>()
        {
            { '+', '-' }, // Replace all '+' signs with '-'s
            { '/', '_' }, // Replace all '/' signs with '_'s
            { '=', '~' }, // Replace all '=' signs with '~'s
        };
    }
}
