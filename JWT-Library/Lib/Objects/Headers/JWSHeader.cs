namespace JWTLib
{
    /// <summary>
    /// Header object, can be expanded with more attributes
    /// </summary>
    public partial class JWSHeader: IHeader
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
