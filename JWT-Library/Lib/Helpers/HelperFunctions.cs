/// <summary>
/// Root namespace
/// </summary>
namespace JWTLib
{
    // Required namespaces
    using System.Text;
    using System.Security.Cryptography;

    /// <summary>
    /// Class that contain helper functions
    /// </summary>
    internal static class HelperFunctions
    {
        /// <summary>
        /// Generates the random secret key.
        /// </summary>
        /// <returns></returns>
        internal static byte[] HashHMACSecret(string key)
        {
            // Placeholder for the bytes
            var bytes = new byte[32];
            // Create a new hasher
            using (var hasher = SHA256.Create())
            {
                // Hash the string
                bytes = hasher.ComputeHash(Encoding.Default.GetBytes(key));
            }
            // Return the hashed key
            return bytes;
        }
    }
}
