/// <summary>
/// Root namespace
/// </summary>
namespace JWTLib
{
    /// <summary>
    /// Interface that contains properties that must exist in a JWS header
    /// </summary>
    public interface IJWSHeader
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
