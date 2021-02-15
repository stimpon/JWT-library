/// <summary>
/// Root library namespace
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
        private JWEHeader ProtectedHeader { get; set; }

        /// <summary>
        /// Gets or sets the unprotected header.
        /// </summary>
        private object UnprotectedHeader { get; set; }

        /// <summary>
        /// Gets or sets the unencrypted key.
        /// </summary>
        //byte[] UnencryptedKey { get; set; }

        /// <summary>
        /// Gets or sets the payload of the JWE.
        /// </summary>
        private string Payload { get; set; }

        /// <summary>
        /// RSA private key needs to be created or set if using any of the RSA algorithms
        /// </summary>
        public RSAParameters RSAPrivateKey { get; set; }

        /// <summary>
        /// Gets or sets the encryption mode
        /// </summary>
        private JWEAlgorithms AlgMode { get; set; }

        /// <summary>
        /// Gets or sets the encryption mode.
        /// </summary>
        private JWEEncryptionModes EncMode { get; set; }

        #endregion

        #region Constructor

        /// <summary>
        /// Initializes a new instance of the <see cref="JWETokenBuilder"/> class.
        /// </summary>
        public JWETokenBuilder(JWEAlgorithms mode)
        {
            // Set the mode
            this.AlgMode = mode;
            
            // Get the encryption mode
            this.EncMode = (JWEEncryptionModes)int.Parse(EnumHelpers.ExtractDescriptor(mode));
        }

        #endregion

        #region Public functions

        /// <summary>
        /// Set the payload, this could be another signed JWT or an object containing claims. This will be the ciphertext in the JWT
        /// </summary>
        /// <param name="payload">The payload.</param>
        /// <param name="serialize">If payload should be serialized, set <c>true<c>, else leave at <c>false<c> </param>
        public void SetPayload(object payload, bool serialize = false)
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
            else this.Payload = payload.ToString();
        }

        /// <summary>
        /// Sets the RSA private key, the secret key will be stored in <see cref="RSAPrivateKey"/>
        /// </summary>
        /// <param name="type">The type.</param>
        /// <param name="param">The RSA private key</param>
        /// <returns></returns>
        public void SetRSAPrivateKey(RSAParameters privateKey)
        {
            // Create the JWE header
            this.ProtectedHeader = new JWEHeader()
            {
                typ = "JWT",
                alg = this.AlgMode,
                enc = this.EncMode
            };

            // Create the RSA crypto provider
            this.RSAPrivateKey = privateKey;
        }

        /// <summary>
        /// Calling this function with a new encryption mode will override the default encryption mode<br/>
        /// used by the algorithm
        /// </summary>
        /// <param name="mode">The mode.</param>
        public void SetEncryptionMode(JWEEncryptionModes mode)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Builds the JWT token
        /// </summary>
        /// <returns>
        ///     True:  Build was successful
        ///     False: Build was not successful
        /// </returns>
        public JWEToken BuildToken()
        {
            // If the payload is empty...
            if (String.IsNullOrEmpty(this.Payload)) throw new Exception("No payload has been set");

            // Check what algorithm to use...
            if (this.AlgMode == 0)
            {
                /// <summary>
                /// RSA with OAEP should be used
                /// </summary>

                // Get a new encryptor and random key
                var encryptorTuple = Data.GetAesGcmEncryptor(int.Parse(EnumHelpers.ExtractDescriptor(this.EncMode)));

                // Create an encryptor
                using (var encryptor = encryptorTuple.aesGcm)
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

                        // Create a new token and assign it null
                        JWEToken token = null;

                        // Create a new provider
                        using (var provider = new RSACryptoServiceProvider())
                        {
                            // Import private key
                            provider.ImportParameters(this.RSAPrivateKey);

                            // Create JWE Result
                            token = new JWEToken
                            {
                                ProtectedHeader = JsonConvert.SerializeObject(ProtectedHeader).ToBase64Url(),
                                EncryptedKey    = provider.Encrypt(encryptorTuple.key, true).ToBase64Url(),
                                IV              = nonceSpan.ToBase64Url(),
                                Ciphertext      = cipherText.ToBase64Url(),
                                Tag             = tag.ToBase64Url(),
                            };
                        }

                        // Return the JWE
                        return token;
                    }
                    // If build failed...
                    catch(Exception ex) { throw new Exception(ex.Message); } // Return error
                }
            }

            throw new Exception();
        }

        #endregion
    }
}
