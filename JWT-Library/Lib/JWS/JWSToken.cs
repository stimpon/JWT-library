/// <summary>
/// Root namespace
/// </summary>
namespace JWTLib
{
    // Requiren namespaces
    using System.Text.Json;
    using System.Text.Json.Serialization;

    /// <summary>
    /// Object that will be returned when a JWT is created
    /// </summary>
    public class JWSToken
    {
        #region Json properties

        /// <summary>
        /// Gets or sets the header.
        /// </summary>
        [JsonPropertyName("header")]
        public string Header { get; set; }

        /// <summary>
        /// Gets or sets the payload.
        /// </summary>
        [JsonPropertyName("payload")]
        public string Payload { get; set; }

        /// <summary>
        /// Gets or sets the signature.
        /// </summary>
        [JsonPropertyName("signature")]
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
        public string Json { get { try { return JsonSerializer.Serialize(this); } catch { return null; } } }
    }
}
