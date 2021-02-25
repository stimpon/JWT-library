namespace JWTLib
{
    // Required namespaces
    using Newtonsoft.Json;
    using Newtonsoft.Json.Converters;

    /// <summary>
    /// A default implementation of the <see cref="IJWEProtectedHeader"/>
    /// </summary>
    /// <seealso cref="JWTLib.IJWEHeader" />
    public partial class JWEProtectedHeader : IJWEProtectedHeader
    {
        /// <summary>
        /// <see cref="IJWEHeader.typ"/>
        /// </summary>
        [JsonProperty(PropertyName = "typ")]
        [JsonConverter(typeof(StringEnumConverter))]
        public TokenTypes Type { get; set; }

        /// <summary>
        /// <see cref="IJWEHeader.alg"/>
        /// </summary>
        [JsonProperty(PropertyName = "alg")]
        [JsonConverter(typeof(StringEnumConverter))]
        public JWEAlgorithms Algorithm { get; set; }
        /// <summary>
        /// <see cref="IJWEHeader.enc"/>
        /// </summary>
        [JsonProperty(PropertyName = "enc")]
        [JsonConverter(typeof(StringEnumConverter))]
        public JWEEncryptionModes EncryptionMode { get; set; }
    }
}
