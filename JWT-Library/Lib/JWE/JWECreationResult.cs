namespace JWTLib
{
    // Required namespaces
    using Newtonsoft.Json; 

    /// <summary>
    /// This gets returned when a JWT is created with JWE
    /// </summary>
    public class JWECreationResult
    {
        /// <summary>
        /// Gets or sets the protected header.
        /// </summary>
        [JsonProperty("protected")]
        public string ProtectedHeader { get; set; }
        /// <summary>
        /// Gets or sets the encrypted key.
        /// </summary>
        [JsonProperty("encrypted_key")]
        public string EncryptedKey    { get; set; }
        /// <summary>
        /// Gets or sets the iv.
        /// </summary>
        [JsonProperty("iv")]
        public string IV              { get; set; }
        /// <summary>
        /// Gets or sets the ciphertext.
        /// </summary>
        [JsonProperty("ciphertext")]
        public string Ciphertext      { get; set; }
        /// <summary>
        /// Gets or sets the tag.
        /// </summary>
        [JsonProperty("tag")]
        public string Tag             { get; set; }

        /// <summary>
        /// Gets or sets the jwe.
        /// </summary>
        [JsonIgnore] // This should be ignored if converted to JSON
        public string JWE { get => $"{ProtectedHeader}.{EncryptedKey}.{IV}.{Ciphertext}.{Tag}"; }

        /// <summary>
        /// Gets the json representation.
        /// </summary>
        /// <returns></returns>
        [JsonIgnore]
        public string GetJsonRepresentation { get => JsonConvert.SerializeObject(this); }
        

        /// <summary>
        /// Gets or sets the result.
        /// </summary>
        [JsonIgnore] // This should be ignored if converted to JSON
        public Results Result { get; set; }
    }
}
