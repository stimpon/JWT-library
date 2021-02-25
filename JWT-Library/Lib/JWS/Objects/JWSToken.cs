/// <summary>
/// Root namespace
/// </summary>
namespace JWTLib
{
    // Requiren namespaces
    using Newtonsoft.Json;

    /// <summary>
    /// This is a standard implementation of the <see cref="IJWSToken"/>
    /// </summary>
    /// <typeparam name="H">The header type, default header: <see cref="JWSHeader"/> should be used</typeparam>
    /// <typeparam name="P">The payload type</typeparam>
    /// <seealso cref="JWTLib.IJWSToken" />
    public class JWSToken<H, P> : IJWSToken where H : IJWSHeader 
                                            where P : class, new()                                           
    {
        #region Non Json properties

        /// <summary>
        /// Returns the <see cref="IJWSToken.RawHeader"/> as the correct object
        /// </summary>
        [JsonIgnore]
        public H Header 
            // Resolve the header into the correct object
            => JWSTokenHandler.ResolveHeader<H>(this.RawHeader);

        /// <summary>
        /// Returns the <see cref="IJWSToken.RawPayload"/> as the correct object
        /// </summary>
        [JsonIgnore]
        public P Payload
            // Resolve the payload into the correct object
            => JWSTokenHandler.ResolvePayload<P>(this.RawPayload);

        /// <summary>
        /// Returns the JWT token in it's correct string format (header.payload.signature)
        /// </summary>
        [JsonIgnore]
        public string JWT => $"{RawHeader}.{RawPayload}.{RawSignature}";

        /// <summary>
        /// Returns this instance as a json object
        /// </summary>
        [JsonIgnore]
        public string Json => JsonConvert.SerializeObject(this);

        #endregion

        #region Json properties

        /// <summary>
        /// The base64url encoded header.
        /// </summary>
        [JsonProperty(PropertyName = "header")]
        public string RawHeader { get; set; }

        /// <summary>
        /// The base64url encoded payload.
        /// </summary>
        [JsonProperty(PropertyName = "payload")]
        public string RawPayload { get; set; }

        /// <summary>
        /// The base64url encoded signature
        /// </summary>
        [JsonProperty(PropertyName = "signature")]
        public string RawSignature { get; set; }

        #endregion
    }
}
