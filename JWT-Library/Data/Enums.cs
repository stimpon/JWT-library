namespace JWTLib
{
    /// <summary>
    /// Contains all RSA algorithms for JWS
    /// </summary>
    public enum RSATypes
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
    /// Contains all available types for JWE
    /// </summary>
    public enum EncryptionTypes
    {
        /// <summary>
        /// No encryption
        /// </summary>
        None = 99,

        /// <summary>
        /// Aes encryptor with a key size of 123 bits
        /// </summary>
        AES128 = 0,
        /// <summary>
        /// Aes encryptor with a key size of 192 bits
        /// </summary>
        AES192 = 1,
        /// <summary>
        /// Aes encryptor with a key size of 256 bits
        /// </summary>
        AES256 = 2
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
