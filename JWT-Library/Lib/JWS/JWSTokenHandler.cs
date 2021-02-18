﻿/// <summary>
/// Root namespaces
/// </summary>
namespace JWTLib
{
    // Required namespaces
    using System;
    using System.Text;
    using System.Text.Json;
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
                return JsonSerializer.Deserialize<T>(obj);
            }
            // If payload could not be verified...
            catch { return null; } // return null object
        }

        /// <summary>
        /// Verifies the specified JWT. <br/>
        /// This function will also search for the existence of default claims
        /// </summary>
        /// <param name="token">The token to verify.</param>
        /// <param name="key">
        ///     If RSA was used for signing- set key to the RSA public key<br/>
        ///     If HMAC was used for signing- set key to the secret key <see cref="byte[]"/>
        /// </param>
        /// <param name="optUniqueIdentifier">Verification will fail if the jti in the token is equal to this identifier</param>
        /// <returns>
        ///     <see cref="Results.OK"/>: If JWT could be verified<br/>
        ///     <see cref="Results.Failed"/>: If JWT could not be verified<br/>
        ///     <see cref="Results.Expired"/>: If JWT has the 'exp' claim and the token has expired<br/>
        ///     <see cref="Results.NotValidYet"/>: If the JWT has the 'nbf' claim and the token is not yet valid
        /// </returns>
        public static VerifyResults Verify(JWSToken token, object key, string 
            // Optional parameters
            optUniqueIdentifier = null)
        {
            // If not all parts exist
            if (token == null || token.JWT.Split('.').Length != 3) return VerifyResults.Invalid; // The JWT is invalid

            // Get the algorithm type from the header
            var algType = (JWSAlgorithms)Enum.Parse(typeof(JWSAlgorithms),
                                                JsonSerializer.Deserialize<JWSHeader>(
                                                Encoding.Default.GetString(token.Header.FromBase64Url())).alg);

            // Check algorithm...
            if ((int)algType >= (int)JWSAlgorithms.RS256 && (int)algType <= (int)JWSAlgorithms.RS512) // RSA Mode
            {
                // If the token is expired...
                if (IsExpired(token)) return VerifyResults.Expired;
                // If the token is not yet valid...
                if (IsNotValidYet(token)) return VerifyResults.NotValidYet;
                // If the token has a uniqye identifier...
                if (!String.IsNullOrEmpty(optUniqueIdentifier)) throw new NotImplementedException("functionality not implemented");

                // Try verifying the JWT...
                try
                {
                    // Create the RSA crypto service provider
                    using (var provider = new RSACryptoServiceProvider())
                    {
                        // Load the RSA parameters
                        provider.ImportParameters((RSAParameters)key);

                        // Encode the payload
                        var encodedPayload = Encoding.Default.GetBytes($"{token.Header}.{token.Payload}");

                        // Verify the JWT
                        bool result = provider.VerifyData(
                            // Load the encoded payload
                            encodedPayload, 0, encodedPayload.Length,
                            // Load the signature
                            token.Signature.FromBase64Url(),
                            // Get the correct hasher
                            (HashAlgorithmName)Data.Hashers[(int)algType],
                            // Define padding
                            RSASignaturePadding.Pkcs1);

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
                using (var hmac = (HMAC)Data.Hashers[(int)algType])
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
        /// Converts the base64 payload into a dynamic object (Used for cheking the existence of claims)
        /// </summary>
        /// <param name="token">The token.</param>
        /// <returns>The dynamix payload</returns>
        private static dynamic GetDynamicPayload(JWSToken token)
        {
            // Convert and return the payload as a dynamic
            return JsonSerializer.Deserialize<dynamic>(Encoding.Default.GetString(token.Payload.FromBase64Url()));
        }

        // Private claim checking functions >>
        #region Claim checking
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
                // Get the dynamic payload
                var payload = GetDynamicPayload(token);
                // If the token has a exp claim...
                if (payload.exp > 0)
                    // If expired...
                    if (NumericDate.Now() > Convert.ToInt64(payload.exp)) return true; // JWT is expired

                // Token has no expiration claim or is not expired
                return false;
            }
            // Claim is unreadable so skip it, verification will fail if this has been altered...
            catch { return false; }
        }

        /// <summary>
        /// Compares the current time agains the 
        /// </summary>
        /// <param name="token">The token.</param>
        /// <returns>
        ///   <c>true</c> if the specified token is valid; otherwise, <c>false</c>.
        /// </returns>
        private static bool IsNotValidYet(JWSToken token)
        {
            // This can fail if the exp claim has been modified
            try
            {
                // Get the dynamic payload
                var payload = GetDynamicPayload(token);
                // If the token has a nbf claim...
                if (payload.nbf > 0)
                    // If expired...
                    if (Convert.ToInt64(payload.nbf) > NumericDate.Now()) return true; // JWT is not valid yet 

                // Token has no expiration claim or is not expired
                return false;
            }
            // Claim is unreadable so skip it, verification will fail if this has been altered...
            catch { return false; }
        }

        /// <summary>
        /// Compares the jti in the token to the provided jti
        /// </summary>
        /// <param name="token">The token.</param>
        /// <returns>
        ///   <c>true</c> if equal; otherwise, <c>false</c>.
        /// </returns>
        private static bool IsJTIEqual(JWSToken token, string jti)
        {
            // This can fail if the exp claim has been modified
            try
            {
                // Get the dynamic payload
                var payload = GetDynamicPayload(token);
                // If the token has a nbf claim...
                if (payload.jti > 0)
                    // If expired...
                    if (jti.CompareTo(payload.jti)) return true; // jti match

                // Token has no expiration claim or is not expired
                return false;
            }
            // Claim is unreadable so skip it, verification will fail if this has been altered...
            catch { return false; }
        }
        #endregion

        #endregion
    }
}
