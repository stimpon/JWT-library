/// <summary>
/// Root namespace
/// </summary>
namespace JWTLib
{
    /// <summary>
    /// Describes all the required parts of a JWT using JWS
    /// </summary>
    public interface IJWSToken
    {
        #region Json properties

        /// <summary>
        /// The base64url encoded header.
        /// </summary>
        public string RawHeader { get; set; }

        /// <summary>
        /// The base64url encoded payload.
        /// </summary>
        public string RawPayload { get; set; }

        /// <summary>
        /// The base64url encoded signature
        /// </summary>
        public string RawSignature { get; set; }

        #endregion
    }
}
