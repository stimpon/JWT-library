/// <summary>
/// Root library namespace
/// </summary>
namespace JWTLib
{
    // Required namespaces
    using System.Text;
    using System.Security.Cryptography;
    using Newtonsoft.Json;
    using System;

    /// <summary>
    /// Functions for creating, reading and verifying JWTs with JWS
    /// </summary>
    public static class JWS
    {
        /// <summary>
        /// Creates the token using RSA.
        /// </summary>
        /// <param name="payload">The JWT body, the object that is passed will be converted into JSON by standard.</param>
        /// <param name="param">The RSA parameters to use.</param>
        /// <param name="algType">the algorithm type to use.</param>
        /// <param name="useEncryption">Determines if the JWT should be encrypted (If true, the token will be encrypted and then signed)</param>
        /// <returns></returns>
        public static JWTResult CreateUsingRSA(object payload, RSAParameters param, RSATypes algType)
        {
            // Create header for JWS
            JWSHeader header = new JWSHeader()
            {
                typ = "JWT",
                alg = algType.ToString()
            };

            // Create the unsigned JWT
            var unsignedJWT =
                JsonConvert.SerializeObject(header).ToBase64Url()   +
                "."                                                 +
                JsonConvert.SerializeObject(payload).ToBase64Url();

            // Declare the signature variable
            string signature;
            string signedJWT;

            // Create a new RSA crypto service provider
            using (var provider = new RSACryptoServiceProvider())
            {
                // Import the given RSA parameters
                provider.ImportParameters(param);

                // If only private key is present
                if (provider.PublicOnly) return new JWTResult(null, Results.MissingPrivateKey); // Return error result

                // Create the signature and create hash
                signature = provider.SignData(Encoding.Default.GetBytes(unsignedJWT), Data.Hashers[(int)algType]).ToBase64Url();

                // Create the signed JWT
                signedJWT = $"{unsignedJWT}.{signature}";
            }

            // Returned the creation result
            return new JWTResult(signedJWT, Results.OK);
        }

        /// <summary>
        /// Verifies the specified JWT.
        /// </summary>
        /// <param name="JWT">The JWT.</param>
        /// <param name="param">The RSA public</param>
        /// <returns></returns>
        public static Results Verify(string JWT, RSAParameters param, RSATypes algType)
        {
            // If not all parts exist
            if (JWT.Split('.').Length != 3) return Results.InvalidJWT; // The JWT is invalid

            // Try verifying the JWT...
            try
            {
                // Create the RSA crypto service provider
                using (var provider = new RSACryptoServiceProvider())
                {
                    // Load the RSA parameters
                    provider.ImportParameters(param);

                    // Verify the JWT
                    bool result = provider.VerifyData(
                        Encoding.Default.GetBytes(JWT.Remove(JWT.LastIndexOf('.'))), 
                        Data.Hashers[(int)algType],
                        JWT.Split('.')[2].FromBase64Url());

                    // If JWT could be verified...
                    if (result) return Results.OK; // Return OK result
                    // If JWT could not be verified...
                    else return Results.Failed; // return Fail result
                }
            }
            // If errors occurred when verifying JWT...
            catch { return Results.Failed; } // JWT is invalid
        }
    }
}
