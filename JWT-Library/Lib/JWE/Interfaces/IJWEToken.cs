/// <summary>
/// Root namespce
/// </summary>
namespace JWTLib
{
    /// <summary>
    /// Interface that describes a JWT token using JWE
    /// </summary>
    public interface IJWEToken
    {
        /// <summary>
        /// Gets or sets the protected header.
        /// </summary>
        public string ProtectedHeader { get; set; }

        /// <summary>
        /// Gets or sets the encrypted key.
        /// </summary>       
        public string EncryptedKey { get; set; }

        /// <summary>
        /// Gets or sets the iv.
        /// </summary>
        public string IV { get; set; }

        /// <summary>
        /// Gets or sets the ciphertext.
        /// </summary>
        public string Ciphertext { get; set; }

        /// <summary>
        /// Gets or sets the tag.
        /// </summary>
        public string Tag { get; set; }
    }
}
