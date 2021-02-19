/// <summary>
/// Root namespace
/// </summary>
namespace JWTLib
{
    // Requiren namespaces
    using System.Text.Json.Serialization;

    /// <summary>
    /// Object that will be returned when a JWT is created
    /// </summary>
    public class JWSToken<H, P> : IJWSToken where P : class, new()
                                            where H : IJWSHeader
    {
        #region Consumer properties

        /// <summary>
        /// Gets the decoded header.
        /// </summary>
        [JsonIgnore]
        public H Header { get => JWSTokenHandler.ResolveHeader<H>(this._header); }

        /// <summary>
        /// Gets the decoded payload.
        /// </summary>
        [JsonIgnore]
        public P Payload { get => JWSTokenHandler.ResolvePayload<P>(this._payload); }

        #endregion

        #region Json properties

        /// <summary>
        /// Gets or sets the header.
        /// </summary>
        public string _header { get; set; }

        /// <summary>
        /// Gets or sets the payload.
        /// </summary>
        public string _payload { get; set; }

        /// <summary>
        /// Gets or sets the signature.
        /// </summary>
        public string _signature { get; set; }

        #endregion

        #region Getters

        /// <summary>
        /// Returns the JWT token in it's correct string format
        /// </summary>
        public string JWT => $"{_header}.{_payload}.{_signature}";

        #endregion
    }
}
