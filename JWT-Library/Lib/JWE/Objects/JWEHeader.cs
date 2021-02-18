namespace JWTLib
{
    // Required namespaces
    using System.Text.Json.Serialization;

    /// <summary>
    /// Header for a JWT token using JWE with RSA, can be expanded with more attributes
    /// </summary>
    /// <seealso cref="JWTLib.IJWEHeader" />
    public partial class JWEHeader
    {
        /// <summary>
        /// <see cref="IJWEHeader.typ"/>
        /// </summary>
        [JsonPropertyName("typ")]
        public string typ { get; set; }

        /// <summary>
        /// <see cref="IJWEHeader.alg"/>
        /// </summary>
        [JsonIgnore]
        public JWEAlgorithms alg { get; set; }
        /// <summary>
        /// <see cref="IJWEHeader.enc"/>
        /// </summary>
        [JsonIgnore]
        public JWEEncryptionModes enc { get; set; }

        #region Hidden Json properties

        /// <summary>
        /// Gets the alg string that should be used when serializing <see cref="alg"/>
        /// </summary>
        [JsonPropertyName("alg")]
        public string _alg { get => alg.ToString().Replace('_', '-'); }

        /// <summary>
        /// Gets the alg string that should be used when serializing <see cref="enc"/>
        /// </summary>
        [JsonPropertyName("enc")]
        public string _enc { get => enc.ToString(); }

        #endregion
    }
}
