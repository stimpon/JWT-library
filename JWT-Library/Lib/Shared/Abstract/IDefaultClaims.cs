/// <summary>
/// Root namespace
/// </summary>
namespace JWTLib
{
    /// <summary>
    /// Defines the default claims: <strong>jti, Iss, sub, exp, iat, nbf</strong><br/>
    /// Apply <see cref="System.Text.Json.Serialization.JsonIgnoreAttribute"/><br/>
    /// in order to exclude any of the claims from the JWT
    /// </summary>
    public interface IDefaultClaims
    {
        /// <summary>
        /// (JWT ID): Unique identifier; can be used to prevent the JWT from being replayed(allows a token to be used only once)
        /// </summary>
        public abstract string jti { get; }

        /// <summary>
        /// (issuer) : Issuer of the JWT
        /// </summary>
        public abstract string iss { get; }

        /// <summary>
        /// (subject) : Subject of the JWT(the user)
        /// </summary>
        public abstract string sub { get; }

        /// <summary>
        /// (expiration time): Time after which the JWT expires (default time 24hrs from now) in numeric date<br/>
        /// Set this by using the <see cref="NumericDate.Convert(System.DateTime)"/> function
        /// </summary>
        public abstract long exp { get;}

        /// <summary>
        /// (issued at time): Time at which the JWT was issued; can be used to determine age of the JWT, in numeric date<br/>
        /// Set this by using the <see cref="NumericDate.Convert(System.DateTime)"/> function
        /// </summary>
        public abstract long iat { get; }

        /// <summary>
        /// (not before time) : Time before which the JWT must not be accepted for processing, in numeric date.<br/>
        /// Set this by using the <see cref="NumericDate.Convert(System.DateTime)"/> function
        /// </summary>
        public abstract long nbf { get; }
    }
}
