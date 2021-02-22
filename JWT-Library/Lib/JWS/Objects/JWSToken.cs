/// <summary>
/// Root namespace
/// </summary>
namespace JWTLib
{
    // Requiren namespaces
    using System.Text.Json.Serialization;

    /// <summary>
    /// This is an implementation of the <see cref="IJWSToken"/> interface, that makes is easy for the<br/>
    /// developer to work with the JWT.
    /// </summary>
    public class JWSToken<H, P> : IJWSToken where P : class, new()
                                            where H : IJWSHeader
    {
        #region Consumer properties

        /// <summary>
        /// Gets the decoded header.
        /// </summary>
        [JsonIgnore]
        public H Header { get => JWSTokenHandler.ResolveHeader<H>(this.header); }

        /// <summary>
        /// Gets the decoded payload.
        /// </summary>
        [JsonIgnore]
        public P Payload { get => JWSTokenHandler.ResolvePayload<P>(this.payload); }

        #endregion

        #region Json properties

        /// <summary>
        /// Gets or sets the header.
        /// </summary>
        public string header { get; set; }

        /// <summary>
        /// Gets or sets the payload.
        /// </summary>
        public string payload { get; set; }

        /// <summary>
        /// Gets or sets the signature.
        /// </summary>
        public string signature { get; set; }

        #endregion

        #region Getters

        /// <summary>
        /// Returns the JWT token in it's correct string format (header.payload.signature)
        /// </summary>
        [JsonIgnore]
        public string JWT => $"{header}.{payload}.{signature}";

        #endregion
    }
}
