namespace JWTLib
{
    /// <summary>
    /// Header for a JWT token using JWE with RSA
    /// </summary>
    /// <seealso cref="JWTLib.IJWEHeader" />
    public class JWEHeader : IJWEHeader
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
