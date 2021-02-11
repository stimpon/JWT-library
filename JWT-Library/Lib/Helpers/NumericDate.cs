﻿/// <summary>
/// Root namespace
/// </summary>
namespace JWTLib
{
    // Required namespace
    using System;

    /// <summary>
    /// Helper functions
    /// </summary>
    public static class NumericDate
    {
        /// <summary>
        /// Gets todays date in numeric value (seconds since epoch)
        /// </summary>
        /// <returns></returns>
        public static double Today()
        {
            // Calculate and return the number of seconds from epoch 
            return Math.Floor((DateTime.Now - DateTimeOffset.UnixEpoch).TotalSeconds);
        }

        /// <summary>
        /// Converts the given date to a numeric date (seconds since epoch)
        /// </summary>
        /// <returns></returns>
        public static double Convert(DateTime date)
        {
            // Calculate and return the number of seconds from epoch since the given date 
            return Math.Floor((date - DateTimeOffset.UnixEpoch).TotalSeconds);
        }
    }
}
