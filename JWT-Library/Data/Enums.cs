namespace JWTLib
{
    // Required namespaces
    using System.ComponentModel;

    /// <summary>
    /// Contains all RSA algorithms for JWS
    /// </summary>
    public enum JWSRSAAlgorithmTypes
    {
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
        RS512 = 2
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
        /// Gets returned if the JWT is invalid
        /// </summary>
        InvalidJWT,
        /// <summary>
        /// Gets returned if verification failed due to missing private key
        /// </summary>
        MissingPrivateKey,
        /// <summary>
        /// Gets returned if the JWT could not be verified
        /// </summary>
        Failed
    }
}
