﻿/// <summary>
/// Root namespace
/// </summary>
namespace JWTLib
{
    // Required namespaces
    using System;
    using System.Text.Json.Serialization;

    /// <summary>
    /// Header object, can be expanded with more attributes
    /// </summary>
    public partial class JWSHeader : IJWSHeader
    {
        /// <summary>
        /// <see cref="IHeader.typ"/>
        /// </summary>
        [JsonPropertyName("typ")]
        public string typ { get; set; }

        /// <summary>
        /// <see cref="IHeader.alg"/>
        /// </summary>
        [JsonPropertyName("alg")]
        public string alg { get; set; }

        /// <summary>
        /// Gets or sets the algorithm.
        /// </summary>
        [JsonIgnore]
        public JWSAlgorithms Algorithm { get { 
                // Return the Algorithm as the correct enum, if invalid, return null
                try { return (JWSAlgorithms)Enum.Parse(typeof(JWSAlgorithms), this.alg); } catch { return (JWSAlgorithms)(-100); } } }
    }
}
