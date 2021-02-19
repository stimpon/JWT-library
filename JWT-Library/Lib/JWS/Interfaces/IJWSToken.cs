namespace JWTLib
{
    // Requried namespaces
    using System.Text.Json.Serialization;

    /// <summary>
    /// Standard layout for a JWT token
    /// </summary>
    /// <typeparam name="H">Header type</typeparam>
    /// <typeparam name="P">Payload type</typeparam>
    public interface IJWSToken
    {
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
        [JsonIgnore]
        public string JWT => $"{_header}.{_payload}.{_signature}";

        #endregion

    }
}
