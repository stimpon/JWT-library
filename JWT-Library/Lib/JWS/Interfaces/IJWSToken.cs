namespace JWTLib
{
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
    }
}
