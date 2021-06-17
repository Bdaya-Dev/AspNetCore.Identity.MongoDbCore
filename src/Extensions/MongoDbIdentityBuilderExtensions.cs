// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Reflection;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection.Extensions;
using AspNetCore.Identity.MongoDbCore;
using AspNetCore.Identity.MongoDbCore.Models;
using AspNetCore.Identity.MongoDbCore.Infrastructure;
using MongoDB.Entities;
using MongoDB.Driver;
using MongoDB.Bson.Serialization.IdGenerators;
using MongoDB.Bson.Serialization.Serializers;
using MongoDB.Bson;
using MongoDB.Bson.Serialization;

namespace Microsoft.Extensions.DependencyInjection
{
    /// <summary>
    /// Contains extension methods to <see cref="IdentityBuilder"/> for adding MongoDb stores.
    /// </summary>
    public static class MongoDbIdentityBuilderExtensions
    {
        /// <summary>
        /// Adds an MongoDb implementation of identity information stores.
        /// </summary>
        /// <typeparam name="TContext">The MongoDb database context to use.</typeparam>
        /// <param name="builder">The <see cref="IdentityBuilder"/> instance this method extends.</param>
        /// <param name="mongoDbContext">A mongoDbContext</param>
        /// <returns>The <see cref="IdentityBuilder"/> instance this method extends.</returns>
        public static IdentityBuilder AddMongoDbStores<TContext>(this IdentityBuilder builder, TContext mongoDbContext)
            where TContext : DBContext
        {
            if (mongoDbContext == null)
            {
                throw new ArgumentNullException(nameof(mongoDbContext));
            }

            builder.Services.TryAddSingleton(mongoDbContext);

            AddStores(builder.Services, builder.UserType, builder.RoleType, typeof(TContext));
            return builder;
        }

        /// <summary>
        /// Adds an MongoDb implementation of identity information stores.
        /// </summary>
        /// <typeparam name="TUser">The type representing a user.</typeparam>
        /// <typeparam name="TRole">The type representing a role.</typeparam>
        /// <typeparam name="TKey">The type of the primary key of the identity document.</typeparam>
        /// <param name="builder">The <see cref="IdentityBuilder"/> instance this method extends.</param>
        /// <param name="connectionString"></param>
        /// <param name="databaseName"></param>
        public static IdentityBuilder AddMongoDbStores<TUser, TRole>(this IdentityBuilder builder, string connectionString, string databaseName)
                    where TUser : MongoIdentityUser, new()
                    where TRole : MongoIdentityRole, new()
        {
            if (string.IsNullOrEmpty(connectionString))
            {
                throw new ArgumentNullException(nameof(connectionString));
            }

            if (string.IsNullOrEmpty(databaseName))
            {
                throw new ArgumentNullException(nameof(databaseName));
            }
            builder.Services.TryAddSingleton(new MongoDbSettings
            {
                ConnectionString = connectionString,
                DatabaseName = databaseName
            });
            builder.AddMongoDbStores<TUser, TRole>(new DBContext(databaseName, MongoClientSettings.FromConnectionString(connectionString)));
            return builder;
        }
        public static void RegisterClassMaps()
        {

            BsonClassMapper.Instance.Register<IdentityUser<string>>(cm =>
            {
                cm.AutoMap();
                cm.SetIsRootClass(true);
                cm.UnmapProperty(nameof(IdentityUser<string>.Id));

            });


            BsonClassMapper.Instance.Register<MongoIdentityUser>(cm =>
            {
                cm.AutoMap();
                cm.MapIdProperty(nameof(MongoIdentityUser.ID))
               .SetIdGenerator(StringObjectIdGenerator.Instance)
               .SetSerializer(new StringSerializer(BsonType.ObjectId));

            });

        }
        /// <summary>
        /// Adds an MongoDb implementation of identity information stores.
        /// </summary>
        /// <typeparam name="TUser">The type representing a user.</typeparam>
        /// <typeparam name="TRole">The type representing a role.</typeparam>
        /// <param name="builder">The <see cref="IdentityBuilder"/> instance this method extends.</param>
        /// <param name="mongoDbContext"></param>
        public static IdentityBuilder AddMongoDbStores<TUser, TRole>(this IdentityBuilder builder, DBContext mongoDbContext)
                    where TUser : MongoIdentityUser, new()
                    where TRole : MongoIdentityRole, new()
        {
            if (mongoDbContext == null)
            {
                throw new ArgumentNullException(nameof(mongoDbContext));
            }
            RegisterClassMaps();
            builder.Services.TryAddSingleton(mongoDbContext);
            builder.Services.TryAddScoped<IUserStore<TUser>>(provider =>
            {
                return new MongoUserStore<TUser, TRole, DBContext>(provider.GetService<DBContext>());
            });

            builder.Services.TryAddScoped<IRoleStore<TRole>>(provider =>
            {
                return new MongoRoleStore<TRole, DBContext>(provider.GetService<DBContext>());
            });
            return builder;
        }

        private static void AddStores(IServiceCollection services, Type userType, Type roleType, Type contextType)
        {
            RegisterClassMaps();
            var identityUserType = FindGenericBaseType(userType, typeof(MongoIdentityUser));
            if (identityUserType == null)
            {
                throw new InvalidOperationException(Resources.NotIdentityUser);
            }


            if (roleType != null)
            {
                var identityRoleType = FindGenericBaseType(roleType, typeof(MongoIdentityRole));
                if (identityRoleType == null)
                {
                    throw new InvalidOperationException(Resources.NotIdentityRole);
                }

                // If its a custom DbContext, we can only add the default POCOs
                Type userStoreType = typeof(MongoUserStore<,,>).MakeGenericType(userType, roleType, contextType);
                Type roleStoreType = typeof(MongoRoleStore<,>).MakeGenericType(roleType, contextType);

                services.TryAddScoped(typeof(IUserStore<>).MakeGenericType(userType), userStoreType);
                services.TryAddScoped(typeof(IRoleStore<>).MakeGenericType(roleType), roleStoreType);
            }
            else
            {   // No Roles
                // If its a custom DbContext, we can only add the default POCOs
                Type userStoreType = typeof(MongoUserStore<,,>).MakeGenericType(userType, roleType, contextType);
                services.TryAddScoped(typeof(IUserStore<>).MakeGenericType(userType), userStoreType);
            }

        }

        private static TypeInfo FindGenericBaseType(Type currentType, Type genericBaseType)
        {
            return currentType.GetTypeInfo();
            //var type = currentType;
            //while (type != null)
            //{
            //    var typeInfo = type.GetTypeInfo();
            //    var genericType = type.IsGenericType ? type.GetGenericTypeDefinition() : null;
            //    if (genericType != null && genericType == genericBaseType)
            //    {
            //        return typeInfo;
            //    }
            //    type = type.BaseType;
            //}
            //return null;
        }
    }
}