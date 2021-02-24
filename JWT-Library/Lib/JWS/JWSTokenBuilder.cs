/// <summary>
/// Root library namespace
/// </summary>
namespace JWTLib
{
    // Required namespaces
    using System;
    using System.Text;
    using Newtonsoft.Json;
    using System.Security.Cryptography;

    /// <summary>
    /// Builder for creating JWT tokens using JWS
    /// </summary>
    public static class JWSTokenBuilder
    {

        #region Public functions

        /// <summary>
        /// Builds the token.
        /// </summary>
        /// <typeparam name="Token">The type of the oken.</typeparam>
        /// <param name="mode">The algorithm to use for signing the token</param>
        /// <param name="payload">The payload object</param>
        /// <param name="key">The key<br/>
        ///     <see cref="RSAParameters"/><br/>
        ///     <see cref="String"/> HMAC secret key
        /// </param>
        /// <returns>The created <see cref="JWSA"/></returns>
        public static Token BuildToken<Token>(JWSAlgorithms mode, object payload, object key) where Token : IJWSToken, new()
        {
            // If no payload has been set...
            if (payload == null)
                throw new Exception("No payload has been set");
            
            // Creates a default header based on the algorithm to use
            JWSHeader header = new JWSHeader()
            {
                Type = TokenTypes.JWT,
                Algorithm = mode
            };
            
            // Serialize and base64url convert the header and the payload
            var serializedHeader  = JsonConvert.SerializeObject(header).ToBase64Url();
            var serializedPayload = JsonConvert.SerializeObject(payload).ToBase64Url();

            // Check mode
            if ((int)mode >= (int)JWSAlgorithms.RS256 && (int)mode <= (int)JWSAlgorithms.RS512) // RSA Mode
            {
                // If no private key has been set...
                if (key.Equals(default(RSAParameters)))
                    throw new Exception("RSA private key is missing");


                // Declare the signature variable
                string signature;

                // Create a new RSA crypto service provider
                using (var provider = new RSACryptoServiceProvider())
                {
                    // Import the given RSA parameters
                    provider.ImportParameters((RSAParameters)key);
                    // If only private key is present
                    if (provider.PublicOnly) throw new Exception("RSA parameters is missing the private key");

                    var encodedPayload = Encoding.Default.GetBytes($"{serializedHeader}.{serializedPayload}");

                    // Create the signature and hash
                    signature = provider.SignData(
                        // From the Header + Payload
                        encodedPayload,
                        // Cast the hasher into the correct enum
                        (HashAlgorithmName)Data.Hashers((int)mode),
                        // Use PKCS1 v 1.5
                        RSASignaturePadding.Pkcs1).ToBase64Url();
                }

                // Returned the creation result
                return new Token()
                {
                    RawHeader = serializedHeader,
                    RawPayload = serializedPayload,
                    RawSignature = signature,
                };
            }
            // Else...
            else
            {
                // Try computing the signature of the JWT
                try
                {
                    using(var hmac = (HMAC)Data.Hashers((int)mode))
                    {
                        // Set the secret key
                        hmac.Key = HelperFunctions.HashHMACSecret((string)key);

                        // Compute signature hash and convert it to a base64 url
                        var signature = hmac.ComputeHash(
                            Encoding.Default.GetBytes($"{serializedHeader}.{serializedPayload}")).ToBase64Url();

                        // Returned the creation result
                        return new Token()
                        {
                            RawHeader = serializedHeader,
                            RawPayload = serializedPayload,
                            RawSignature = signature,
                        };
                    }
                }
                // Return error result
                catch (Exception ex) { throw new Exception(ex.Message); }
            }

        }

        #endregion
    }
}
