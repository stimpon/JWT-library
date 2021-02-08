namespace JWTLib
{
    /// <summary>
    /// Header for a JWT token using JWE with RSA, can be expanded with more attributes
    /// </summary>
    /// <seealso cref="JWTLib.IJWEHeader" />
    public partial class JWERSAHeader : IJWEHeader
    {
        /// <summary>
        /// <see cref="IJWEHeader.typ"/>
        /// </summary>
        public string typ { get; set; }
        /// <summary>
        /// <see cref="IJWEHeader.alg"/>
        /// </summary>
        public string alg { get; set; }
        /// <summary>
        /// <see cref="IJWEHeader.enc"/>
        /// </summary>
        public string enc { get; set; }
    }
}
