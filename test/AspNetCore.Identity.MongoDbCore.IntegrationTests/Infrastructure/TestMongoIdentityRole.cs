using AspNetCore.Identity.MongoDbCore.Models;
using System;

namespace AspNetCore.Identity.MongoDbCore.IntegrationTests.Infrastructure
{
    public class TestMongoIdentityRole : MongoIdentityRole
    {
        public TestMongoIdentityRole() : base()
        {
        }

        public TestMongoIdentityRole(string roleName) : base(roleName)
        {
        }

        public TestMongoIdentityRole(string name, string key) : base(name, key)
        {
        }
    }
}
