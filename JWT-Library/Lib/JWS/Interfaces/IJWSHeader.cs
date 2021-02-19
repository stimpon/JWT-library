/// <summary>
/// Root namespace
/// </summary>
namespace JWTLib
{
    // Required namespace
    using System;

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

        /// <summary>
        /// Gets or sets the algorithm.
        /// </summary>
        public JWSAlgorithms Algorithm { get {
                // Return the Algorithm as the correct enum, if invalid, return null
                try { return (JWSAlgorithms)Enum.Parse(typeof(JWSAlgorithms), this.alg); } catch { return (JWSAlgorithms)(-100); }
            }
        }

    }
}
