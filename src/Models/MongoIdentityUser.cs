using AspNetCore.Identity.MongoDbCore.Interfaces;
using Microsoft.AspNetCore.Identity;
using MongoDB.Bson;
using MongoDB.Bson.Serialization;
using MongoDB.Bson.Serialization.Attributes;
using MongoDB.Bson.Serialization.IdGenerators;
using MongoDB.Bson.Serialization.Serializers;
using MongoDB.Driver;
using MongoDB.Entities;
using System;
using System.Collections.Generic;
using System.Linq;

namespace AspNetCore.Identity.MongoDbCore.Models
{


    /// <summary>
    /// A document representing an <see cref="IdentityUser{TKey}"/> document.
    /// </summary>
    public class MongoIdentityUser : IdentityUser<string>, IEntity, IClaimHolder
    {
        /// <summary>
        /// The version of the schema do the <see cref="MongoIdentityUser"/> document.
        /// </summary>
        public virtual int Version { get; set; }
        /// <summary>
        /// The date and time at which this user was created, in UTC.
        /// </summary>
        public virtual DateTime CreatedOn { get; private set; }
        /// <summary>
        /// The claims this user has.
        /// </summary>
        public virtual List<MongoClaim> Claims { get; set; }
        /// <summary>
        /// The role Ids of the roles that this user has.
        /// </summary>
        public virtual HashSet<string> Roles { get; set; }
        /// <summary>
        /// The list of <see cref="UserLoginInfo"/>s that this user has.
        /// </summary>
        public virtual List<UserLoginInfo> Logins { get; set; }
        /// <summary>
        /// The list of <see cref="Token"/>s that this user has.
        /// </summary>
        public virtual List<Token> Tokens { get; set; }

        //lock (_lock)
        //    {
        //        if (!BsonClassMap.IsClassMapRegistered(typeof(IdentityUser<string>)))
        //        {
        //            BsonClassMap.RegisterClassMap<IdentityUser<string>>(cm =>
        //            {
        //                cm.AutoMap();
        //                cm.SetIsRootClass(true);
        //                cm.UnmapProperty(nameof(Id));

        //            });
        //        }

        //        if (!BsonClassMap.IsClassMapRegistered(typeof(MongoIdentityUser)))
        //        {
        //            BsonClassMap.RegisterClassMap<MongoIdentityUser>(cm =>
        //            {
        //                cm.AutoMap();
        //                cm.MapIdProperty(nameof(ID))
        //               .SetIdGenerator(StringObjectIdGenerator.Instance)
        //               .SetSerializer(new StringSerializer(BsonType.ObjectId));

        //            });
        //        }
        //    }

        /// <inheritdoc/>
        public string ID { get => Id; set => Id = value; }


        /// <summary>
        /// The constructor for a <see cref="MongoIdentityUser"/>, taking a username and an email address.
        /// </summary>
        public MongoIdentityUser()
        {
            SetVersion(1);
            InitializeFields();
        }

        /// <summary>
        /// The constructor for a <see cref="MongoIdentityUser"/>, taking a username and an email address.
        /// </summary>
        /// <param name="userName">The name of the user.</param>
        /// <param name="email">The email address of the user.</param>
        public MongoIdentityUser(string userName, string email) : this(userName)
        {
            if (email != null)
            {
                Email = email.ToLowerInvariant().Trim();
            }
        }

        /// <summary>
        /// The constructor for a <see cref="MongoIdentityUser"/>, taking a username.
        /// </summary>
        /// <param name="userName">The name of the user.</param>
        public MongoIdentityUser(string userName)
        {
            UserName = userName ?? throw new ArgumentNullException(nameof(userName));
            SetVersion(1);
            InitializeFields();
        }

        /// <summary>
        /// Initialize the field of the MongoIdentityUser
        /// </summary>
        protected virtual void InitializeFields()
        {
            CreatedOn = DateTime.UtcNow;
            Claims = new List<MongoClaim>();
            Logins = new List<UserLoginInfo>();
            Roles = new HashSet<string>();
            Tokens = new List<Token>();
            Id = GenerateNewID();
        }

        /// <summary>
        /// Sets the version of the schema for the <see cref="MongoIdentityUser"/> document.
        /// </summary>
        /// <param name="version"></param>
        /// <returns></returns>
        public virtual MongoIdentityUser SetVersion(int version)
        {
            Version = version;
            return this;
        }

        #region Role Management

        /// <summary>
        /// Removes a role.
        /// </summary>
        /// <param name="roleId">The Id of the role you want to remove.</param>
        /// <returns>True if the removal was successful.</returns>
        public virtual bool RemoveRole(string roleId)
        {
            var roleClaim = Roles.FirstOrDefault(e => e.Equals(roleId));
            if (roleClaim != null && !roleClaim.Equals(default))
            {
                Roles.Remove(roleId);
                return true;
            }
            return false;
        }

        /// <summary>
        /// Add a role to the user.
        /// </summary>
        /// <param name="roleId">The Id of the role you want to add.</param>
        /// <returns>True if the addition was successful.</returns>
        public virtual bool AddRole(string roleId)
        {
            if (roleId == null || roleId.Equals(default))
            {
                throw new ArgumentNullException(nameof(roleId));
            }
            if (!Roles.Contains(roleId))
            {
                Roles.Add(roleId);
                return true;
            }
            return false;
        }

        #endregion

        #region Login Management

        /// <summary>
        /// Adds a user login to the user.
        /// </summary>
        /// <param name="userLoginInfo">The <see cref="UserLoginInfo"/> you want to add.</param>
        /// <returns>True if the addition was successful.</returns>
        public virtual bool AddLogin(UserLoginInfo userLoginInfo)
        {
            if (userLoginInfo == null)
            {
                throw new ArgumentNullException(nameof(userLoginInfo));
            }
            if (HasLogin(userLoginInfo))
            {
                return false;
            }

            Logins.Add(new UserLoginInfo(userLoginInfo.LoginProvider, userLoginInfo.ProviderKey, userLoginInfo.ProviderDisplayName));
            return true;
        }

        /// <summary>
        /// Checks if the user has the given <see cref="UserLoginInfo"/>.
        /// </summary>
        /// <param name="userLoginInfo">The <see cref="UserLoginInfo"/> we are looking for.</param>
        /// <returns>True if the user has the given <see cref="UserLoginInfo"/>.</returns>
        public virtual bool HasLogin(UserLoginInfo userLoginInfo)
        {
            return Logins.Any(e => e.LoginProvider == userLoginInfo.LoginProvider && e.ProviderKey == e.ProviderKey);
        }

        /// <summary>
        /// Removes a <see cref="UserLoginInfo"/> from the user.
        /// </summary>
        /// <param name="userLoginInfo"></param>
        public virtual bool RemoveLogin(UserLoginInfo userLoginInfo)
        {
            if (userLoginInfo == null)
            {
                throw new ArgumentNullException(nameof(userLoginInfo));
            }
            var loginToremove = Logins.FirstOrDefault(e => e.LoginProvider == userLoginInfo.LoginProvider && e.ProviderKey == e.ProviderKey);
            if (loginToremove != null)
            {
                Logins.Remove(loginToremove);
                return true;
            }
            return false;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="loginProvider"></param>
        /// <param name="providerKey"></param>
        /// <returns></returns>
        public virtual IdentityUserLogin<string> GetUserLogin(string loginProvider, string providerKey)
        {

            var login = Logins.FirstOrDefault(e => e.LoginProvider == loginProvider && e.ProviderKey == providerKey);
            if (login != null)
            {
                return new IdentityUserLogin<string>
                {
                    UserId = Id,
                    LoginProvider = login.LoginProvider,
                    ProviderDisplayName = login.ProviderDisplayName,
                    ProviderKey = login.ProviderKey
                };
            }
            return default;
        }

        #endregion

        #region Token Management

        /// <summary>
        /// Sets the token to a new value.
        /// </summary>
        /// <param name="tokenToset">The token you want to set you want to set.</param>
        /// <param name="value">The value you want to set the token to.</param>
        /// <returns>Returns true if the token was successfully set.</returns>
        public bool SetToken(IdentityUserToken<string> tokenToset, string value)
        {
            var token = Tokens.FirstOrDefault(e => e.LoginProvider == tokenToset.LoginProvider && e.Name == tokenToset.Name);
            if (token != null)
            {
                token.Value = value;
                return true;
            }
            return false;
        }

        /// <summary>
        /// Gets a token given the login provider and the name.
        /// </summary>
        /// <param name="loginProvider">The value for the login provider.</param>
        /// <param name="name">The name of the token.</param>
        /// <returns>An <see cref="IdentityUser{TKey}"/> if found, or null.</returns>
        public IdentityUserToken<string> GetToken(string loginProvider, string name)
        {
            var token = Tokens.FirstOrDefault(e => e.LoginProvider == loginProvider && e.Name == name);
            if (token != null)
            {
                return new IdentityUserToken<string>
                {
                    UserId = Id,
                    LoginProvider = token.LoginProvider,
                    Name = token.Name,
                    Value = token.Value
                };
            }
            return default;
        }

        /// <summary>
        /// Checks if a user has the given token.
        /// </summary>
        /// <param name="token">The token you are looking for.</param>
        /// <returns>True if the user has the given token</returns>
        public bool HasToken(IdentityUserToken<string> token)
        {
            return Tokens.Any(e => e.LoginProvider == token.LoginProvider
                                && e.Name == token.Name
                                && e.Value == token.Value);
        }

        /// <summary>
        /// Adds a token to the user.
        /// </summary>
        /// <typeparam name="TUserToken">The type of the token.</typeparam>
        /// <param name="token">The token you want to add.</param>
        /// <returns>True if the addition was successful.</returns>
        public bool AddUserToken<TUserToken>(TUserToken token) where TUserToken : IdentityUserToken<string>
        {
            if (HasToken(token))
            {
                return false;
            }

            Tokens.Add(new Token
            {
                LoginProvider = token.LoginProvider,
                Name = token.Name,
                Value = token.Value
            });
            return true;
        }

        /// <summary>
        /// Removes a token from the user.
        /// </summary>
        /// <typeparam name="TUserToken">The type of the token.</typeparam>
        /// <param name="token">The token you want to remove.</param>
        /// <returns>True if the removal was successful.</returns>
        public bool RemoveUserToken<TUserToken>(TUserToken token) where TUserToken : IdentityUserToken<string>
        {
            var exists = Tokens.FirstOrDefault(e => e.LoginProvider == token.LoginProvider
                                                 && e.Name == token.Name);
            if (exists == null)
            {
                return false;
            }
            Tokens.Remove(exists);
            return true;
        }

        /// <summary>
        /// Generates a new ObjectId
        /// </summary>
        /// <returns></returns>
        public virtual string GenerateNewID() => ObjectId.GenerateNewId().ToString();

        #endregion Token Management

    }
}