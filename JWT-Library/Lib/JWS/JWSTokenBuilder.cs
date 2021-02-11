﻿/// <summary>
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
    /// Construct and build JWT tokens using JWS
    /// </summary>
    public class JWSTokenBuilder
    {
        #region Private properties

        /// <summary>
        /// This will be the token header
        /// </summary>
        private IHeader Header { get; set; }

        /// <summary>
        /// This will be the token payload
        /// </summary>
        private object Payload { get; set; }

        /// <summary>
        /// This is the algorithm that will be used when building JWTs with this builder
        /// </summary>
        public JWSAlgorithms Mode { get; private set; }

        /// <summary>
        /// This is the hasher that will be used when building JWTs with this builder
        /// </summary>
        public HashAlgorithm Hasher { get; private set; }

        /// <summary>
        /// This key needs to be created or set if using any of the HMAC algorithms.
        /// Create this key by executing this function <see cref="SetSecretKey"/>
        /// </summary>
        public byte[] HMACSecret { get; private set; }

        /// <summary>
        /// RSA private key needs to be created or set if using any of the RSA algorithms
        /// 
        /// </summary>
        public RSAParameters RSAPrivateKey { get; set; }

        #endregion

        #region Constructor

        /// <summary>
        /// Initializes a new instance of the <see cref="JWSTokenBuilder"/> class.
        /// </summary>
        /// <param name="mode">The mode to use with this builder.</param>
        public JWSTokenBuilder(JWSAlgorithms mode)
        {
            // Set the mode
            this.Mode = mode;

            // Get the appropriate hasher
            this.Hasher = Data.Hashers[(int)mode];

            // Create header for JWS
            this.Header = new JWSHeader()
            {
                typ = "JWT",          // Set type to JWT (standard value)
                alg = mode.ToString() // Set the algorithm in the header to the mode
            };
        }

        #endregion

        #region Public functions

        /// <summary>
        /// Sets the secret key, leave '<paramref name="key"/>' empty to generate a random secret.
        /// This secret key will be stored in <see cref="HMACSecret"/>
        /// </summary>
        /// <param name="key">The secret key, the key needs to be 32 bytes long, any excess bytes will be skipped.</param>
        public void SetSecretKey(byte[] key = null)
        {
            // If a key was passed...
            if(key != null)
            {
                // Create a new array for the key
                HMACSecret = new byte[32];
                // Copy over the key into the key holder
                Array.Copy(key, HMACSecret, 32);
            }
            // Else...
            else
            {
                // Create a new array for the key
                this.HMACSecret = new byte[32];

                // Create a new random number generator
                using(var RNG = RandomNumberGenerator.Create())
                {
                    // Fill the array with random bytes
                    RNG.GetBytes(HMACSecret);
                }
            }
        }

        /// <summary>
        /// Sets the RSA private key, the secret key will be stored in <see cref="RSAPrivateKey"/>
        /// </summary>
        /// <param name="privateKey">The private key.</param>
        public void SetRSAPrivateKey(RSAParameters privateKey)
        {
            // Set the privateKey
            this.RSAPrivateKey = privateKey;
        }

        #endregion

        /// <summary>
        /// Creates the payload from the passed object, this will overwrite the existing payload.
        /// The payload will be in Json. <br/>
        /// Your payload object can implement sone of the payload implementations for further functionaliyu <br/>
        /// <see cref="StandardPayload"/>: Will add expiration to the JWT
        /// </summary>
        /// <param name="payload">The payload.</param>
        public void SetPayload(object payload)
        {
            // Serialize the passed object
            this.Payload = payload;
        }

        /// <summary>
        /// Builds the JWT token.<br/>
        /// This token can be verifie it by passing it through the function <see cref="JWSTokenHandler.Verify(JWSToken, RSAParameters)"/>
        /// </summary>
        /// <returns>The token objet</returns>
        public JWSToken BuildToken()
        {
            // If no payload has been set...
            if (this.Payload == null) 
                // Return missing payload error
                return new JWSToken() { Result = Results.EmptyPayload };

            // Create the unsigned JWT
            var serializedHeader  = JsonConvert.SerializeObject( this.Header  ).ToBase64Url();
            var serializedPayload = JsonConvert.SerializeObject( this.Payload ).ToBase64Url();


            // Check mode
            if ((int)this.Mode >= (int)JWSAlgorithms.RS256 && (int)this.Mode <= (int)JWSAlgorithms.RS512) // RSA Mode
            {
                // If no private key has been set...
                if (this.RSAPrivateKey.Equals(default(RSAParameters)))
                    // Return missing private key error
                    return new JWSToken() { Result = Results.MissingPrivateKey };


                // Declare the signature variable
                string signature;

                // Create a new RSA crypto service provider
                using (var provider = new RSACryptoServiceProvider())
                {
                    // Import the given RSA parameters
                    provider.ImportParameters(this.RSAPrivateKey);
                    // If only private key is present
                    if (provider.PublicOnly) return new JWSToken() { Result = Results.MissingPrivateKey }; // Return error result 

                    // Create the signature and hash
                    signature = provider.SignData(
                        // From the Header + Payload
                        Encoding.Default.GetBytes($"{serializedHeader}.{serializedPayload}"),
                        // With the set hasher
                        this.Hasher).ToBase64Url();
                }

                // Returned the creation result
                return new JWSToken()
                {
                    Header = serializedHeader,
                    Payload = serializedPayload,
                    Signature = signature,
                    Result = Results.OK
                };
            }
            // Else...
            else 
            {
                // Try computing the signature of the JWT
                try
                {
                    // If a secret has been set
                    if (this.HMACSecret == null)
                        // Return missing secret key error
                        return new JWSToken() { Result = Results.MissingHMACSecretKey };

                    // Set the secret key
                    (this.Hasher as HMAC).Key = this.HMACSecret;

                    // Compute signature hash and convert it to a base64 url
                    var signature = (this.Hasher as HMAC).ComputeHash(Encoding.Default.GetBytes($"{serializedHeader}.{serializedPayload}")).ToBase64Url();

                    // Returned the creation result
                    return new JWSToken()
                    {
                        Header = serializedHeader,
                        Payload = serializedPayload,
                        Signature = signature,
                        Result = Results.OK
                    };
                }
                // Return error result
                catch { return new JWSToken() { Result = Results.Failed }; }
            }

        }
    }
}