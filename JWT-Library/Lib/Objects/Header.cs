namespace JWTLib
{
    /// <summary>
    /// Header object
    /// </summary>
    public class JWSHeader
    {
        /// <summary>
        /// Gets or sets the type.
        /// </summary>
        public string typ { get; set; }

        /// <summary>
        /// Gets or sets the cryptographic algorithm.
        /// </summary>
        public string alg { get; set; }
    }
}
