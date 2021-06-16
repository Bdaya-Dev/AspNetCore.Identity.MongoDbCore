// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;

using AspNetCore.Identity.MongoDbCore.IntegrationTests.Infrastructure;
using System.Collections.Concurrent;
using System.Linq;
using MongoDB.Driver;
using MongoDB.Entities;
using AspNetCore.Identity.MongoDbCore.Models;

namespace AspNetCore.Identity.MongoDbCore.Test
{
    public class MongoDatabaseFixture<TUser> : IDisposable
        where TUser : MongoIdentityUser
    {

        public DBContext Context;

        public MongoDatabaseFixture()
        {
            Context = new DBContext(Container.MongoDbIdentityConfiguration.MongoDbSettings.DatabaseName, MongoClientSettings.FromConnectionString(Container.MongoDbIdentityConfiguration.MongoDbSettings.ConnectionString));
            UsersToDelete = new ConcurrentBag<TUser>();
        }
        public ConcurrentBag<TUser> UsersToDelete { get; set; }
        public virtual void Dispose()
        {
            var userIds = UsersToDelete.ToList().Select(e => e.Id);
            if (userIds.Any())
            {
                Context.DeleteAsync<TUser>(userIds).Wait();
            }
        }
    }

    public class MongoDatabaseFixture<TUser, TRole> : MongoDatabaseFixture<TUser>, IDisposable
        where TUser : MongoIdentityUser
        where TRole : MongoIdentityRole
    {

        public MongoDatabaseFixture()
        {
            Context = new DBContext(Container.MongoDbIdentityConfiguration.MongoDbSettings.DatabaseName, MongoClientSettings.FromConnectionString(Container.MongoDbIdentityConfiguration.MongoDbSettings.ConnectionString));
            UsersToDelete = new ConcurrentBag<TUser>();
            RolesToDelete = new ConcurrentBag<TRole>();
        }
        public ConcurrentBag<TRole> RolesToDelete { get; set; }

        public override void Dispose()
        {
            var userIds = UsersToDelete.ToList().Select(e => e.Id);
            if (userIds.Any())
            {
                Context.DeleteAsync<TUser>(userIds).Wait();
            }
            var roleIds = RolesToDelete.ToList().Select(e => e.ID);
            if (roleIds.Any())
            {
                Context.DeleteAsync<TRole>(roleIds).Wait();
            }
        }
    }
}