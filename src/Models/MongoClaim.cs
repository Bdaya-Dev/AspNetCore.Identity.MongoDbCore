using MongoDB.Entities;
using System.Collections.Generic;
using System.Security.Claims;

namespace AspNetCore.Identity.MongoDbCore.Models
{
    /// <summary>
    /// A class representing the claims a <see cref="MongoIdentityUser"/> can have.
    /// </summary>
    public class MongoClaim
    {
        public MongoClaim()
        {
            Properties = new Dictionary<string, string>();
        }
        /// <inheritdoc cref="Claim.Type"/>
        public string Type { get; set; }

        /// <inheritdoc cref="Claim.ValueType"/>
        public string ValueType { get; set; }


        /// <inheritdoc cref="Claim.Value"/>
        public string Value { get; set; }

        /// <inheritdoc cref="Claim.Issuer"/>
        public string Issuer { get; set; }

        /// <inheritdoc cref="Claim.OriginalIssuer"/>
        public string OriginalIssuer { get; set; }

        /// <inheritdoc cref="Claim.Properties"/>
        public Dictionary<string, string> Properties { get; }

    }
}
