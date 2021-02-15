/// <summary>
/// Root namespaces
/// </summary>
namespace JWTLib
{
    // Required namespaces
    using System;
    using System.Text;
    using Newtonsoft.Json;
    using System.Security.Cryptography;

    /// <summary>
    /// Contains functions for processing JWTs using JWS
    /// </summary>
    public static class JWSTokenHandler
    {

        #region Public functions

        /// <summary>
        /// Resolves the payload into the specified object.
        /// </summary>
        /// <param name="token">The JWT token.</param>
        /// <typeparam name="T">Object to resolve the payload into</typeparam>
        /// <returns>
        ///     Complete instance of the resolved object 
        /// </returns>
        public static T ResolvePayload<T>(JWSToken token) where T: class, new()
        {
            // Try to resolve the payload...
            try
            {
                // Convert payload from base64url and remove newlines
                var obj = Encoding.Default.GetString(token.Payload.FromBase64Url());

                // Resolve and return the token payload
                return JsonConvert.DeserializeObject<T>(obj);
            }
            // If payload could not be verified...
            catch { return null; } // return null object
        }

        /// <summary>
        /// Verifies the specified JWT.
        /// </summary>
        /// <param name="JWT">The JWT.</param>
        /// <param name="param">
        ///     If RSA was used for signing- set key to the RSA public key<br/>
        ///     If HMAC was used for signing- set key to the secret key <see cref="byte[]"/>
        /// </param>
        /// <returns>
        ///     <see cref="Results.OK"/>: If JWT could be verified<br/>
        ///     <see cref="Results.Failed"/>: If JWT could not be verified<br/>
        ///     <see cref="Results.Expired"/>: If JWT has expired
        /// </returns>
        public static VerifyResults Verify(JWSToken token, object key)
        {
            // If not all parts exist
            if (token == null || token.JWT.Split('.').Length != 3) return VerifyResults.Invalid; // The JWT is invalid

            // Get the algorithm type from the header
            var algType = (JWSAlgorithms)Enum.Parse(typeof(JWSAlgorithms),
                                                JsonConvert.DeserializeObject<JWSHeader>(
                                                Encoding.Default.GetString(token.Header.FromBase64Url())).alg);

            // Check algorithm...
            if ((int)algType >= (int)JWSAlgorithms.RS256 && (int)algType <= (int)JWSAlgorithms.RS512) // RSA Mode
            {
                // If the token is expired
                if (IsExpired(token)) return VerifyResults.Expired;

                // Try verifying the JWT...
                    try
                {
                    // Create the RSA crypto service provider
                    using (var provider = new RSACryptoServiceProvider())
                    {
                        // Load the RSA parameters
                        provider.ImportParameters((RSAParameters)key);

                        // Verify the JWT
                        bool result = provider.VerifyData(
                            Encoding.Default.GetBytes($"{token.Header}.{token.Payload}"),
                            Data.Hashers[(int)algType],
                            token.Signature.FromBase64Url());

                        // If JWT could be verified...
                        if (result) return VerifyResults.Valid; // Return OK result
                        // If JWT could not be verified...
                        else return VerifyResults.Invalid; // return Fail result
                    }
                }
                // If errors occurred when verifying JWT...
                catch { return VerifyResults.Error; } // JWT is invalid               
            }
            else // HMAC Mode
            {
                // If the token is expired
                if (IsExpired(token)) return VerifyResults.Expired;

                // Create hasher
                using (var hmac = Data.Hashers[(int)algType])
                {
                    // Set the provided key
                    (hmac as HMAC).Key = (byte[])key;

                    // Get bytes from header . payload
                    var compareTo = Encoding.Default.GetBytes($"{token.Header}.{token.Payload}");

                    // Compute the hash and compare to signature in JWT
                    // If the same signature was generated...
                    if (token.Signature.CompareTo(hmac.ComputeHash(compareTo).ToBase64Url()) == 0)
                        // JWT verified
                        return VerifyResults.Valid;
                    // Else...
                    else
                        // Signature could not be verified
                        return VerifyResults.Invalid;
                }
            }
        }

        /// <summary>
        /// Convert a string JWT into a <see cref="JWSToken"/>
        /// </summary>
        /// <param name="JWT">The string JWT</param>
        /// <returns>
        ///     New <see cref="JWSToken"/> if convertsion was successful<br/>
        ///     nulll if convertsion failed
        /// </returns>
        public static JWSToken ToToken(string JWT)
        {
            // Create the token and assign it to null
            JWSToken token = null;

            // JWT must contain 3 parts seperated by a dot
            if(JWT.Split('.').Length == 3)
                // Create the token
                token = new JWSToken()
                {
                    Header    = JWT.Split('.')[0], // Pull the header from the JWT
                    Payload   = JWT.Split('.')[1], // Pull the payload from the payload from the JWT
                    Signature = JWT.Split('.')[2]  // Pull the signature from the JWT
                };

            // Return the token
            return token;
        }

        #endregion

        #region Private functions

        /// <summary>
        /// Determines whether this token is expired.
        /// </summary>
        /// <returns>
        ///   <c>true</c> if this token is expired; otherwise, <c>false</c>.
        /// </returns>
        private static bool IsExpired(JWSToken token)
        {
            // This can fail if the exp claim has been modified
            try
            {
                // If the token has a expiration date claim...
                if (JsonConvert.DeserializeObject<dynamic>(Encoding.Default.GetString(token.Payload.FromBase64Url())).exp != null)
                {
                    // Get expiration date from JWT
                    var exp = JsonConvert.DeserializeObject<dynamic>(
                        Encoding.Default.GetString(token.Payload.FromBase64Url())).exp;

                    // If expired...
                    if (NumericDate.Today() > Convert.ToInt64(exp)) return true; // Return true result
                }

                // Token has no expiration claim or is not expired
                return false;
            }
            // Return true result because the claim is unreadable
            catch { return true; }
        }

        #endregion
    }
}
