﻿/// <summary>
/// Root namespace
/// </summary>
namespace JWTLib
{
    // Required namespaces
    using System.ComponentModel;

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
    public enum JWEAlgorithms
    {
        /// <summary>
        /// The RSA oaep
        /// </summary>
        [Description("0")] // Describes the default encryption type to use with this alhorithm
        RSA_OAEP = 0,
    }

    /// <summary>
    /// Contains 
    /// </summary>
    public enum JWEEncryptionModes
    {
        /// <summary>
        /// Advanced Encryption Standard (AES) using 128 bit keys in Galois/Counter Mode
        /// </summary>
        [Description("16")]
        A128GCM = 0,

        /// <summary>
        /// Advanced Encryption Standard (AES) using 256 bit keys in Galois/Counter Mode
        /// </summary>
        [Description("32")]
        A256GCM = 1
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
