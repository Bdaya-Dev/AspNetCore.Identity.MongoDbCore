using System;
using AspNetCore.Identity.MongoDbCore.Infrastructure;
using AspNetCore.Identity.MongoDbCore.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Identity.Core;
using MongoDB.Bson;
using MongoDB.Bson.Serialization;
using MongoDB.Bson.Serialization.IdGenerators;
using MongoDB.Bson.Serialization.Serializers;
using MongoDB.Entities;

namespace AspNetCore.Identity.MongoDbCore.Extensions
{
    /// <summary>
    /// Contains extension methods to <see cref="IServiceCollection"/> for adding mongoDb Identity.
    /// </summary>
    public static class ServiceCollectionExtension
    {
        /// <summary>
        /// Configures the MongoDb Identity store adapters for the types of TUser only from <see cref="MongoIdentityUser{TKey}"/>.
        /// </summary>
        /// <typeparam name="TUser">The type representing a user.</typeparam>
        /// <param name="services">The collection of service descriptors.</param>
        /// <param name="mongoDbIdentityConfiguration">A configuration object of the AspNetCore.Identity.MongoDbCore package.</param>
        public static IdentityBuilder ConfigureMongoDbIdentityUserOnly<TUser>(
            this IServiceCollection services,
            MongoDbIdentityConfiguration mongoDbIdentityConfiguration)
                where TUser : MongoIdentityUser, new()
        {
            ValidateMongoDbSettings(mongoDbIdentityConfiguration.MongoDbSettings);

            return CommonMongoDbSetup<TUser, MongoIdentityRole>(services, mongoDbIdentityConfiguration);
        }


        /// <summary>
        /// Configures the MongoDb Identity store adapters for the types of TUser only inheriting from <see cref="MongoIdentityUser"/>.
        /// </summary>
        /// <typeparam name="TUser">The type representing a user.</typeparam>
        /// <param name="services">The collection of service descriptors.</param>
        /// <param name="mongoDbIdentityConfiguration">A configuration object of the AspNetCore.Identity.MongoDbCore package.</param>
        public static IdentityBuilder ConfigureMongoDbIdentity<TUser>(this IServiceCollection services, MongoDbIdentityConfiguration mongoDbIdentityConfiguration)
                    where TUser : MongoIdentityUser, new()
        {
            ValidateMongoDbSettings(mongoDbIdentityConfiguration.MongoDbSettings);

            return CommonMongoDbSetup<TUser, MongoIdentityRole>(services, mongoDbIdentityConfiguration);
        }
       
        /// <summary>
        /// Validates the MongoDbSettings
        /// </summary>
        /// <param name="mongoDbSettings"></param>
        private static void ValidateMongoDbSettings(MongoDbSettings mongoDbSettings)
        {
            if (mongoDbSettings == null)
            {
                throw new ArgumentNullException(nameof(mongoDbSettings));
            }

            if (string.IsNullOrEmpty(mongoDbSettings.ConnectionString))
            {
                throw new ArgumentNullException(nameof(mongoDbSettings.ConnectionString));
            }

            if (string.IsNullOrEmpty(mongoDbSettings.DatabaseName))
            {
                throw new ArgumentNullException(nameof(mongoDbSettings.DatabaseName));
            }
        }

        /// <summary>
        /// Configures the MongoDb Identity store adapters for the types of TUser and TRole.
        /// </summary>
        /// <typeparam name="TUser">The type representing a user.</typeparam>
        /// <typeparam name="TRole">The type representing a role.</typeparam>
        /// <typeparam name="TKey">The type of the primary key of the identity document.</typeparam>
        /// <param name="services">The collection of service descriptors.</param>
        /// <param name="mongoDbIdentityConfiguration">A configuration object of the AspNetCore.Identity.MongoDbCore package.</param>
        /// <param name="mongoDbContext">An object representing a MongoDb connection.</param>
        public static IdentityBuilder ConfigureMongoDbIdentity<TUser, TRole>(this IServiceCollection services, MongoDbIdentityConfiguration mongoDbIdentityConfiguration,
            DBContext mongoDbContext = null)
                    where TUser : MongoIdentityUser, new()
                    where TRole : MongoIdentityRole, new()
        {
            IdentityBuilder builder;

            ValidateMongoDbSettings(mongoDbIdentityConfiguration.MongoDbSettings);
           

            if (mongoDbContext == null)
            {
                builder = services.AddIdentityCore<TUser>()
                        .AddRoles<TRole>()
                        .AddMongoDbStores<TUser, TRole>(
                            mongoDbIdentityConfiguration.MongoDbSettings.ConnectionString,
                            mongoDbIdentityConfiguration.MongoDbSettings.DatabaseName);
            }
            else
            {
                builder = services.AddIdentityCore<TUser>()
                        .AddRoles<TRole>()
                        .AddMongoDbStores(mongoDbContext);
            }

            if (mongoDbIdentityConfiguration.IdentityOptionsAction != null)
            {
                services.Configure(mongoDbIdentityConfiguration.IdentityOptionsAction);
            }

            return builder;
        }


        private static IdentityBuilder CommonMongoDbSetup<TUser, TRole>(this IServiceCollection services, MongoDbIdentityConfiguration mongoDbIdentityConfiguration)
                    where TUser : MongoIdentityUser, new()
                    where TRole : MongoIdentityRole, new()
        {
            IdentityBuilder builder;

            builder = services.AddIdentityCore<TUser>()
                    .AddRoles<TRole>()
                    .AddMongoDbStores<TUser, TRole>(
                        mongoDbIdentityConfiguration.MongoDbSettings.ConnectionString,
                        mongoDbIdentityConfiguration.MongoDbSettings.DatabaseName);

            if (mongoDbIdentityConfiguration.IdentityOptionsAction != null)
            {
                services.Configure(mongoDbIdentityConfiguration.IdentityOptionsAction);
            }

            return builder;
        }
    }
}

/// <summary>
/// Solves the concurrency issue when mapping classes
/// </summary>
public sealed class BsonClassMapper
{

    private static BsonClassMapper instance = null;

    private static readonly object _lock = new object();

    public static BsonClassMapper Instance
    {
        get
        {
            if (instance == null)
            {
                instance = new BsonClassMapper();
            }
            return instance;
        }
    }

    public BsonClassMapper Register<T>(Action<BsonClassMap<T>> classMapInitializer)
    {
        lock (_lock)
        {
            if (!BsonClassMap.IsClassMapRegistered(typeof(T)))
            {
                BsonClassMap.RegisterClassMap(classMapInitializer);
            }
        }
        return this;
    }
}