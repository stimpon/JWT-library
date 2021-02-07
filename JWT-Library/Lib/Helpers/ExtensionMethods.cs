namespace JWTLib
{
    // Required namespaces
    using System;
    using System.Text;

    /// <summary>
    /// Contains converter functions
    /// </summary>
    public static class ExtensionMethods
    {
        #region Convert to Base64Url

        /// <summary>
        /// Converts to bas64url.
        /// </summary>
        /// <param name="S">The string.</param>
        /// <returns></returns>
        public static string ToBase64Url(this string S)
        {
            // Convert string to a normal Base64 string
            string Base64String = Convert.ToBase64String(Encoding.Default.GetBytes(S));

            // Go through all forbidden characters in the dictionary
            foreach (var p in Data.UrlCharMappings)
                S = Base64String.Replace(p.Key, p.Value); // Replace the forbidden character with the valid character

            // Return the string
            return S;
        }
        /// <summary>
        /// Converts to bas64url.
        /// </summary>
        /// <param name="S">The string.</param>
        /// <returns></returns>
        public static string ToBase64Url(this byte[] B)
        {
            // Convert string to a normal Base64 string
            string Base64String = Convert.ToBase64String(B);

            // Go through all forbidden characters in the dictionary
            foreach (var p in Data.UrlCharMappings)
                Base64String = Base64String.Replace(p.Key, p.Value); // Replace the forbidden character with the valid character

            // Return the string
            return Base64String;
        }

        #endregion

        #region Convert to Base64Url

        /// <summary>
        /// Converts to bas64url.
        /// </summary>
        /// <param name="S">The string.</param>
        /// <returns></returns>
        public static byte[] FromBase64Url(this string S)
        {
            // Go through all character mappings in the dictionary
            foreach (var p in Data.UrlCharMappings)
                S = S.Replace(p.Value, p.Key); // Replace the URL safe character with the actual base64 character

            // Return the string
            return Convert.FromBase64String(S);
        }

        /// <summary>
        /// Converts a Base64Url to a standard Base64.
        /// </summary>
        /// <param name="s">The s.</param>
        /// <returns></returns>
        public static byte[] ToStandardBase64(this string S)
        {
            // Go through all character mappings in the dictionary
            foreach (var p in Data.UrlCharMappings)
                S = S.Replace(p.Value, p.Key); // Repalce Url safe characters with original Base64 characters

            // Return the converted byte array
            return Encoding.Default.GetBytes(S);
        }

        #endregion
    }
}
