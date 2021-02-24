/// <summary>
/// Root namespace
/// </summary>
namespace JWTLib
{
    // Required namespaces
    using Newtonsoft.Json;
    using Newtonsoft.Json.Converters;

    /// <summary>
    /// A default implementation of the <see cref="IJWSHeader"/> interface
    /// </summary>
    public partial class JWSHeader : IJWSHeader
    {
        #region Json properties

        /// <summary>
        /// <see cref="IHeader.typ"/>
        /// </summary>
        [JsonProperty(PropertyName = "typ")]
        [JsonConverter(typeof(StringEnumConverter))]
        public TokenTypes Type { get; set; }

        /// <summary>
        /// <see cref="IHeader.alg"/>
        /// </summary>
        [JsonProperty(PropertyName = "alg")]
        [JsonConverter(typeof(StringEnumConverter))]
        public JWSAlgorithms Algorithm { get; set; }

        #endregion

    }
}
