/// <summary>
/// Root namespce
/// </summary>
namespace JWTLib
{
    // Required namespaces
    using System.Text.Json;
    using System.Text.Json.Serialization;

    /// <summary>
    /// This gets returned when a JWT is created with JWE
    /// </summary>
    public class JWEToken
    {
        /// <summary>
        /// Gets or sets the protected header.
        /// </summary>
        [JsonPropertyName("protected")]
        public string ProtectedHeader { get; set; }
        /// <summary>
        /// Gets or sets the encrypted key.
        /// </summary>
        [JsonPropertyName("encrypted_key")]
        public string EncryptedKey { get; set; }
        /// <summary>
        /// Gets or sets the iv.
        /// </summary>
        [JsonPropertyName("iv")]
        public string IV { get; set; }
        /// <summary>
        /// Gets or sets the ciphertext.
        /// </summary>
        [JsonPropertyName("ciphertext")]
        public string Ciphertext { get; set; }
        /// <summary>
        /// Gets or sets the tag.
        /// </summary>
        [JsonPropertyName("tag")]
        public string Tag { get; set; }

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
        public string Json { get { try { return JsonSerializer.Serialize(this); } catch { return null; } }}
    }
}
