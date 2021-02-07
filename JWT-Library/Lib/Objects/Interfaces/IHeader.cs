namespace JWTLib
{
    public interface IHeader
    {
        /// <summary>
        /// Gets or sets the type.
        /// </summary>
        abstract string typ { get; set; }

        /// <summary>
        /// Gets or sets the cryptographic algorithm.
        /// </summary>
        abstract string alg { get; set; }
    }
}
