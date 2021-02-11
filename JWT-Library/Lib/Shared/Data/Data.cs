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
        /// Character mappings for Base64Url strings
        /// </summary>
        internal static Dictionary<char, char> UrlCharMappings = new Dictionary<char, char>()
        {
            { '+', '-' }, // Replace all '+' signs with '-'s
            { '/', '_' }  // Replace all '/' signs with '_'s
        };
    }
}
