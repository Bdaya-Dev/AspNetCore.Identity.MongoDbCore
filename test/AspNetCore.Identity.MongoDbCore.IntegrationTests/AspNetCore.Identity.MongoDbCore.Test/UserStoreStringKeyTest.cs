// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using Microsoft.Extensions.DependencyInjection;
using Xunit;
using AspNetCore.Identity.MongoDbCore.Models;

namespace AspNetCore.Identity.MongoDbCore.Test
{
    public class StringUser : MongoIdentityUser
    {
        public StringUser() : base()
        {
        }
    }

    public class StringRole : MongoIdentityRole
    {
        public StringRole() : base()
        {
        }
    }

    public class UserStoreStringKeyTest : MongoDbStoreTestBase<StringUser, StringRole>
    {
        public UserStoreStringKeyTest(MongoDatabaseFixture<StringUser, StringRole> fixture)
            : base(fixture)
        { }

    }
}