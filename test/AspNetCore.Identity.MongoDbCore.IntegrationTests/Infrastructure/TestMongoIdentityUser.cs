using AspNetCore.Identity.MongoDbCore.Models;
using System;

namespace AspNetCore.Identity.MongoDbCore.IntegrationTests.Infrastructure
{
    public class TestMongoIdentityUser : MongoIdentityUser
    {
        public TestMongoIdentityUser() : base()
        {
            Id = GenerateNewID();
        }

        public TestMongoIdentityUser(string userName) : base(userName)
        {
            Id = GenerateNewID();
        }

        public TestMongoIdentityUser(string userName, string email) : base(userName, email)
        {
            Id = GenerateNewID();
        }

        public string CustomContent { get; set; }
    }
}
