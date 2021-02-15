/// <summary>
/// Root namespace
/// </summary>
namespace JWTLib
{
    // Requiren namespaces
    using Newtonsoft.Json;

    /// <summary>
    /// Object that will be returned when a JWT is created
    /// </summary>
    public class JWSToken
    {
        #region Json properties

        /// <summary>
        /// Gets or sets the header.
        /// </summary>
        [JsonProperty("header")]
        public string Header { get; set; }

        /// <summary>
        /// Gets or sets the payload.
        /// </summary>
        [JsonProperty("payload")]
        public string Payload { get; set; }

        /// <summary>
        /// Gets or sets the signature.
        /// </summary>
        [JsonProperty("signature")]
        public string Signature { get; set; }

        #endregion

        /// <summary>
        /// Returns the JWT token in it's correct string format
        /// </summary>
        [JsonIgnore]
        public string JWT { get => $"{Header}.{Payload}.{Signature}"; }

        /// <summary>
        /// Returns the JWT in a Json representation<br/>
        /// This will retutn null if JWT could not be serialized
        /// </summary>
        [JsonIgnore]
        public string Json { get { try { return JsonConvert.SerializeObject(this); } catch { return null; } } }
    }
}
