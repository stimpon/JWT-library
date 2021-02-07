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
