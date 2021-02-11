namespace JWTLib
{
    /// <summary>
    /// Interface for a JWT token using JWE with RSA
    /// </summary>
    /// <seealso cref="JWTLib.IHeader" />
    public interface IJWEHeader: IHeader
    {
        /// <summary>
        /// Gets or sets the encryption type.
        /// </summary>
        abstract string enc { get; set; }
    }
}
