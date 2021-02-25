/// <summary>
/// Root namespace
/// </summary>
namespace JWTLib
{
    /// <summary>
    /// Defines the default properties of a JWT using JWE protected header
    /// </summary>
    public interface IJWEProtectedHeader
    {
        /// <summary>
        /// <see cref="IJWEHeader.typ"/>
        /// </summary>
        public TokenTypes Type { get; set; }

        /// <summary>
        /// <see cref="IJWEHeader.alg"/>
        /// </summary>
        public JWEAlgorithms Algorithm { get; set; }

        /// <summary>
        /// <see cref="IJWEHeader.enc"/>
        /// </summary>
        public JWEEncryptionModes EncryptionMode { get; set; }
    }
}
