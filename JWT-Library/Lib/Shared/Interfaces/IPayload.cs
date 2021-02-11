/// <summary>
/// Root namespace
/// </summary>
namespace JWTLib
{
    /// <summary>
    /// Template interface for a JWT payload. Contains standard claims commonly used in the
    /// payload of JWTs
    /// </summary>
    public interface IPayload
    {
        /// <summary>
        /// (subject) : Subject of the JWT(the user)
        /// </summary>
        abstract string sub { get; set; }

        /// <summary>
        /// (audience) : Recipient for which the JWT is intended
        /// </summary>
        abstract string aud { get; set; }

        /// <summary>
        /// (not before time) : Time before which the JWT must not be accepted for processing
        /// </summary>
        abstract string nbf { get; set; }

        /// <summary>
        /// (JWT ID): Unique identifier; can be used to prevent the JWT from being replayed(allows a token to be used only once)
        /// </summary>
        abstract string jti { get; set; }
    }
}
