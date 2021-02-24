/// <summary>
/// Root namespace
/// </summary>
namespace JWTLib
{
    /// <summary>
    /// Interface that descbribes all the required parts of a JWT using JWS
    /// </summary>
    public interface IJWSHeader
    {
        /// <summary>
        /// The token type
        /// </summary>
        public TokenTypes Type { get; set; }

        /// <summary>
        /// The algorithm
        /// </summary>
        public JWSAlgorithms Algorithm { get; set; }
    }
}
