namespace JWTLib
{
    /// <summary>
    /// This object will be returned when decoding a JWS
    /// </summary>
    public class JWSDecodedResult
    {
        /// <summary>
        /// Gets or sets the header.
        /// </summary>
        public JWSHeader Header { get; set; }

        /// <summary>
        /// Gets or sets the payload.
        /// </summary>
        public string Payload   { get; set; }

        /// <summary>
        /// Gets or sets the signature.
        /// </summary> 
        public string Signature { get; set; }

        /// <summary>
        /// Gets or sets the result.
        /// </summary>
        public Results Result   { get; set; }
    }
}
