namespace JWTLib
{
    // Required namespaces
    using System.ComponentModel;
    using System.Security.Cryptography;

    /// <summary>
    /// Header Parameter Values for JWS
    /// </summary>
    public enum JWSAlgorithms
    {
        #region RSA

        /// <summary>
        /// RSASSA-PKCS1-v1_5 using SHA256 (RECOMENDED)
        /// </summary>
        RS256 = 0,
        /// <summary>
        /// RSASSA-PKCS1-v1_5 using SHA384
        /// </summary>
        RS384 = 1,
        /// <summary>
        /// RSASSA-PKCS1-v1_5 using SHA512
        /// </summary>
        RS512 = 2,

        #endregion

        #region HMAC     

        /// <summary>
        /// HMAC using SHA-256
        /// </summary>
        [Description("HMACSHA256")]
        HS256 = 3,
        /// <summary>
        /// HMAC using SHA-384
        /// </summary>
        [Description("HMACSHA384")]
        HS384 = 4,
        /// <summary>
        /// HMAC using SHA-512
        /// </summary>
        [Description("HMACSHA512")]
        HS512 = 5,

        #endregion
    }

    /// <summary>
    /// Contains 
    /// </summary>
    public enum JWERSAAlgorithmTypes
    {
        /// <summary>
        /// The RSA oaep
        /// </summary>
        [Description("A256GCM")] // Describes what encryption algorithm to use with this type
        RSA_OAEP = 0,
    }

    /// <summary>
    /// Contains results for JWT verifications
    /// </summary>
    public enum Results
    {
        /// <summary>
        /// Gets returned if JWT could be verified
        /// </summary>
        OK,
        /// <summary>
        /// Gets returned if the JWT could not be verified
        /// </summary>
        Failed,
        /// <summary>
        /// Gets returned if the JWT is invalid
        /// </summary>
        InvalidJWT,
        /// <summary>
        /// Gets returned if the payload is empty or null
        /// </summary>
        EmptyPayload,

        /// <summary>
        /// Gets returned if verification failed due to missing private key
        /// </summary>
        MissingPrivateKey,
        /// <summary>
        /// Gets returned if HMAC secret key is missing
        /// </summary>
        MissingHMACSecretKey,

        /// <summary>
        /// Gets returned if a mode that is not supported yet is used
        /// </summary>
        ModeNotSupported
    }

    /// <summary>
    /// Contains results returned when verifying a JWT
    /// </summary>
    public enum VerifyResults 
    {
        /// <summary>
        /// The JWT is valid
        /// </summary>
        Valid,
        /// <summary>
        /// The JWT is invalid
        /// </summary>
        Invalid,
        /// <summary>
        /// JWT has expired
        /// </summary>
        Expired,

        /// <summary>
        /// Error occurred while verifying JWT
        /// </summary>
        Error
    }
}
