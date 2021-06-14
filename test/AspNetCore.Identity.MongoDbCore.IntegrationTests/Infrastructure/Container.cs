using AspNetCore.Identity.MongoDbCore.Extensions;
using AspNetCore.Identity.MongoDbCore.Infrastructure;
using Microsoft.Extensions.Configuration;
using MongoDB.Driver;
using MongoDB.Entities;
using System;

namespace AspNetCore.Identity.MongoDbCore.IntegrationTests.Infrastructure
{
    public static class Locks
    {
        public static object MongoInitLock = new object();
        public static object RolesLock = new object();
    }

    public static class Container
    {
        public static IConfiguration Configuration { get; set; }

        static Container()
        {
            var builder = new ConfigurationBuilder()
                                    .SetBasePath(System.Environment.CurrentDirectory)
                                    .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
                                    //per user config that is not committed to repo, use this to override settings (e.g. connection string) based on your local environment.
                                    .AddJsonFile($"appsettings.local.json", optional: true);

            builder.AddEnvironmentVariables();

            Configuration = builder.Build();

            var databaseSettings = Configuration.Load<MongoDbSettings>("MongoDbSettings");

            MongoDbIdentityConfiguration = new MongoDbIdentityConfiguration()
            {
                MongoDbSettings = databaseSettings,
                IdentityOptionsAction = (options) =>
                {
                    options.Password.RequireDigit = false;
                    options.Password.RequireLowercase = false;
                    options.Password.RequireNonAlphanumeric = false;
                    options.Password.RequireUppercase = false;
                    options.User.AllowedUserNameCharacters = null;
                }
            };

            lock (Locks.MongoInitLock)
            {
                DB.InitAsync(databaseSettings.DatabaseName, MongoClientSettings.FromConnectionString(databaseSettings.ConnectionString));

                _mongoDbRepository = new DBContext();
            }
        }

        public static MongoDbIdentityConfiguration MongoDbIdentityConfiguration { get; set; }

        public static IServiceProvider Instance { get; set; }

        const string connectionString = "mongodb://localhost:27017";
        private static readonly DBContext _mongoDbRepository;

        private static readonly DBContext _mongoDbRepository2;

        public static DBContext MongoContext
        {
            get
            {
                return _mongoDbRepository;
            }
        }
    }

    public static class ConfigurationExtensions
    {
        public static T Load<T>(this IConfiguration configuration, string key) where T : new()
        {
            var instance = new T();
            configuration.GetSection(key).Bind(instance);
            return instance;
        }

        public static T Load<T>(this IConfiguration configuration, string key, T instance) where T : new()
        {
            configuration.GetSection(key).Bind(instance);
            return instance;
        }
    }
}
