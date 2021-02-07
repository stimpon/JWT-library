﻿namespace JWTLib
{
    /// <summary>
    /// Object that will be returned when a JWT is created
    /// </summary>
    public class JWTCreationResult
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="JWTCreationResult"/> class.
        /// </summary>
        /// <param name="JWT">The JWT.</param>
        /// <param name="Result">The result.</param>
        public JWTCreationResult(string JWT, Results Result)
        {
            // Set properties
            this.JWT = JWT;
            this.Result = Result;
        }

        /// <summary>
        /// Gets or sets the JWT that was created
        /// </summary>
        public string JWT { get; set; }

        /// <summary>
        /// Gets the result.
        /// </summary>
        public Results Result { get; }
    }
}