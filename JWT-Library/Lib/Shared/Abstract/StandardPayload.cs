/// <summary>
/// Root namespace
/// </summary>
namespace JWTLib
{
    // Required namespaces
    using System;

    /// <summary>
    /// A basic payload template that should be implemented in every payload
    /// </summary>
    public abstract class StandardPayload
    {
        /// <summary>
        /// (issuer) : Issuer of the JWT
        /// </summary>
        public abstract string Iss { get; }

        /// <summary>
        /// (expiration time): Time after which the JWT expires (default time 24hrs from now) in numeric date
        /// </summary>
        public virtual long exp { get => NumericDate.Convert(DateTime.Now.AddHours(24)); }

        /// <summary>
        /// (issued at time): Time at which the JWT was issued; can be used to determine age of the JWT, in numeric date
        /// </summary>
        public virtual long iat { get => NumericDate.Today(); }
    }
}
