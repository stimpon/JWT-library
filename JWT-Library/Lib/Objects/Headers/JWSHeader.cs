namespace JWTLib
{
    /// <summary>
    /// Header object
    /// </summary>
    public class JWSHeader: IHeader
    {
        /// <summary>
        /// <see cref="IHeader.typ"/>
        /// </summary>
        public string typ { get; set; }

        /// <summary>
        /// <see cref="IHeader.alg"/>
        /// </summary>
        public string alg { get; set; }
    }
}
