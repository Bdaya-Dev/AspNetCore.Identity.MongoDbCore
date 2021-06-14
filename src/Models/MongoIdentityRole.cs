using AspNetCore.Identity.MongoDbCore.Interfaces;
using Microsoft.AspNetCore.Identity;
using MongoDB.Bson;
using MongoDB.Entities;
using System;
using System.Collections.Generic;

namespace AspNetCore.Identity.MongoDbCore.Models
{
    /// <summary>
    /// A document representing an <see cref="IdentityRole{TKey}"/> document.
    /// </summary>    
    public class MongoIdentityRole : IdentityRole<string>, IEntity, IClaimHolder
    {
        /// <summary>
        /// The constructor for a <see cref="MongoIdentityRole"/>
        /// </summary>
        public MongoIdentityRole()
        {
            InitializeFields();
        }

        /// <summary>
        /// The constructor for a <see cref="MongoIdentityRole"/>, taking a role name.
        /// </summary>
        /// <param name="roleName">The name of the role.</param>
        public MongoIdentityRole(string roleName)
        {
            Name = roleName;
            InitializeFields();
        }

        /// <summary>
        /// Initialize the field of the MongoIdentityRole
        /// </summary>
        protected virtual void InitializeFields()
        {
            Version = 1;
            Claims = new List<MongoClaim>();
            Id = GenerateNewID();
        }

        /// <inheritdoc/>
        public string GenerateNewID() => ObjectId.GenerateNewId().ToString();

        /// <summary>
        /// The constructor for a <see cref="MongoIdentityRole"/>, taking a role name and a primary key value.
        /// </summary>
        /// <param name="name">The name of the role.</param>
        /// <param name="key">The value of the primary key</param>
        public MongoIdentityRole(string name, string key)
        {
            InitializeFields();
            Id = key;
            Name = name;
        }

        /// <summary>
        /// The version of the role schema
        /// </summary>
        public int Version { get; set; }

        /// <summary>
        /// The claims associated to the role
        /// </summary>
        public List<MongoClaim> Claims { get; set; }

        /// <inheritdoc/>
        public string ID { get => Id; set => Id = value; }
    }
}
