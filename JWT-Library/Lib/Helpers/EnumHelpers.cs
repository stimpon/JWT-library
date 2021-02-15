/// <summary>
/// Root namespace
/// </summary>
namespace JWTLib
{
    // Required namespaces
    using System;
    using System.ComponentModel;

    /// <summary>
    /// Helpers for enums
    /// </summary>
    public static class EnumHelpers
    {
        /// <summary>
        /// Extracts the descriptor from the enum.
        /// </summary>
        /// <param name="_enum">The enum with the desciptor.</param>
        /// <returns></returns>
        public static string ExtractDescriptor(Enum _enum)
        {
            // Get field from Mode
            var field = _enum.GetType().GetField(_enum.ToString());
            // Get attributes from field
            var attr = field.GetCustomAttributes(typeof(DescriptionAttribute), true);
            // Return the descriptor
            return ((DescriptionAttribute)attr[0]).Description;
        }
    }
}
