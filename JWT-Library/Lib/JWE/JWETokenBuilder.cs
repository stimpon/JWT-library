/// <summary>
/// Root linrary namespace
/// </summary>
namespace JWTLib
{
    // Required namespaces
    using Newtonsoft.Json;
    using System.Security.Cryptography;
    using System.ComponentModel;
    using System;
    using System.Text;

    /// <summary>
    /// Builder for creating JWE tokens
    /// </summary>
    public class JWETokenBuilder
    {
        #region Private properties

        /// <summary>
        /// Gets or sets the protected header.
        /// </summary>
        private IJWEHeader ProtectedHeader { get; set; }

        /// <summary>
        /// Gets or sets the unprotected header.
        /// </summary>
        private object UnprotectedHeader { get; set; }

        /// <summary>
        /// Gets or sets the unencrypted key.
        /// </summary>
        byte[] UnencryptedKey { get; set; }

        /// <summary>
        /// Gets or sets the payload of the JWE.
        /// </summary>
        private string Payload { get; set; }


        /// <summary>
        /// Gets or sets the RSA provider.
        /// </summary>
        RSACryptoServiceProvider provider { get; set; }
        /// <summary>
        /// Gets or sets a value indicating whether [use RSA oaep].
        /// </summary>
        /// <value>
        ///   <c>true</c> if [use RSA oaep]; otherwise, <c>false</c>.
        /// </value>
        private bool RSA_OAEP_MODE { get; set; }
        /// <summary>
        /// Gets or sets the type.
        /// </summary>
        private JWERSAAlgorithmTypes Type { get; set; }

        #endregion

        #region Constructor

        /// <summary>
        /// Initializes a new instance of the <see cref="JWETokenBuilder"/> class.
        /// </summary>
        public JWETokenBuilder()
        {         
            // Set standard values that must be set by the programmer 
            this.RSA_OAEP_MODE = false;
        }

        #endregion

        #region Private functions

        /// <summary>
        /// Creates and returns a new encryptor based on the algorithm type
        /// </summary>
        /// <param name="type">The type.</param>
        /// <returns></returns>
        private AesGcm GetAesGCMEncryptor(JWERSAAlgorithmTypes type)
        {
            // Declare an AesGCM encryptor
            AesGcm alg;

            // Check what keysize that should be used
            switch (type)
            {
                case JWERSAAlgorithmTypes.RSA_OAEP: // AesGCM with a key size of 256 bits should be used in this case
                    // Create key placeholder of 256 bits
                    this.UnencryptedKey = new byte[32];
                    // Create a random number generator
                    using (var RNG = RandomNumberGenerator.Create())
                    {
                        // Fill byte array with random bytes
                        RNG.GetBytes(this.UnencryptedKey);
                    }
                    break;

                default: return null; // If invalid option was passed
            }

            // Create AES encryptor and set the key size
            alg = new AesGcm(this.UnencryptedKey);

            // Return the encryptor
            return alg;
        }

        #endregion

        #region Public functions

        /// <summary>
        /// Set the payload, this could be another signed JWT or an object containing claims. This will be the ciphertext in the JWT
        /// </summary>
        /// <param name="payload">The payload.</param>
        /// <param name="serialize">If the payload is an object the set serialize to <c>true<c> </param>
        /// <returns>
        ///     True:  Payload was set
        ///     False: Payload could not be set
        /// </returns>
        public bool SetPayload(object payload, bool serialize = false)
        {
            // If object should be serialized...
            if (serialize)
            {
                // Serialize the payload
                var obj = JsonConvert.SerializeObject(payload);
                // Set the payload
                this.Payload = obj;
            }
            // Else just set the payload as is...
            else
            {
                this.Payload = payload.ToString();
            }

            // Payload was set successfuly
            return true;
        }

        /// <summary>
        /// This function will turn on RSA-OAEP mode
        /// </summary>
        /// <param name="type">The type.</param>
        /// <param name="param">The RSA private key</param>
        /// <returns></returns>
        public bool UseRSA_OAEP(JWERSAAlgorithmTypes type, RSAParameters param)
        {
            // Get field
            var field = type.GetType().GetField(type.ToString());
            // Get attributes from field
            var attr = field.GetCustomAttributes(typeof(DescriptionAttribute), true);

            // Create the JWE header
            this.ProtectedHeader = new JWERSAHeader()
            {
                typ = "JWT",
                alg = type.ToString().Replace('_', '-'),
                enc = ((DescriptionAttribute)attr[0]).Description
            };

            // Create the RSA crypto provider
            this.provider = new RSACryptoServiceProvider();
            // Import the parameters
            provider.ImportParameters(param);

            // If only a public key was provided...
            if (provider.PublicOnly) return false; // return false

            // Save alg info
            this.RSA_OAEP_MODE = true;
            this.Type = type;

            // Success
            return true;
        }

        /// <summary>
        /// Builds the JWT token
        /// </summary>
        /// <returns>
        ///     True:  Build was successful
        ///     False: Build was not successful
        /// </returns>
        public JWECreationResult Build()
        {
            // If the payload is empty...
            if (String.IsNullOrEmpty(this.Payload)) return new JWECreationResult() { Result = Results.EmptyPayload }; // Return error

            // Check what algorithm to use...
            if (RSA_OAEP_MODE)
            {
                /// <summary>
                /// RSA with OAEP should be used
                /// </summary>

                // Create an encryptor
                using(var encryptor = GetAesGCMEncryptor(this.Type))
                {
                    // Try to build the compact JWT JWE
                    try
                    {
                        // Create placeholder for the IV/NONCE
                        byte[] NONCE = new byte[12];

                        // Create a random number generator for the NONE/IV
                        using(var RNG = RandomNumberGenerator.Create())
                        {
                            // Fill IV/NONCE array with 12 random bytes
                            RNG.GetBytes(NONCE);
                        }

                        // Arrays to put the ciphertext, tag and protected header in
                        byte[] cipherText = new byte[Payload.Length];
                        byte[] tag = new byte[16];
                        byte[] protected_header = Encoding.Default.GetBytes(JsonConvert.SerializeObject(ProtectedHeader));

                        // Create spans for the encryptor
                        Span<byte> cipherTextSpan = new Span<byte>(cipherText),
                            nonceSpan       = new Span<byte>(NONCE),
                            payloadSpan     = new Span<byte>(Encoding.UTF8.GetBytes(this.Payload)),
                            tagSpan         = new Span<byte>(tag),
                            protectedSpan   = new Span<byte>(protected_header);

                        // Encrypt the payload and get the authentication tag
                        encryptor.Encrypt(nonceSpan, payloadSpan, cipherTextSpan, tagSpan, protectedSpan);

                        // Create JWE Result
                        JWECreationResult JWE = new JWECreationResult
                        {
                            ProtectedHeader = JsonConvert.SerializeObject(ProtectedHeader).ToBase64Url(),
                            EncryptedKey    = provider.Encrypt(UnencryptedKey, true).ToBase64Url(),
                            IV              = nonceSpan.ToBase64Url(),
                            Ciphertext      = cipherText.ToBase64Url(),
                            Tag             = tag.ToBase64Url(),
                            Result          = Results.OK
                        };

                        // Return the JWE
                        return JWE;
                    }
                    // If build failed...
                    catch { return new JWECreationResult() { Result = Results.Failed }; } // Return error
                }
            }

            // Return failed result
            return new JWECreationResult() { Result = Results.Failed };
        }

        #endregion
    }
}
