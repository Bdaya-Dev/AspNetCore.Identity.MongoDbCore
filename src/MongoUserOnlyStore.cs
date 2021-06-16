// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using MongoDB.Driver;
using AspNetCore.Identity.MongoDbCore.Extensions;
using AspNetCore.Identity.MongoDbCore.Models;
using Microsoft.AspNetCore.Identity;
using MongoDB.Entities;
using System.Linq.Expressions;
using System.Reflection;

namespace AspNetCore.Identity.MongoDbCore
{
    /// <inheritdoc/>
    public class MongoUserOnlyStore : MongoUserOnlyStore<MongoIdentityUser, DBContext>
    {
        /// <inheritdoc/>
        public MongoUserOnlyStore(DBContext context, IdentityErrorDescriber describer = null) : base(context, describer) { }
    }

    /// <inheritdoc/>
    public class MongoUserOnlyStore<TUser> : MongoUserOnlyStore<TUser, DBContext>
        where TUser : MongoIdentityUser, new()
    {
        /// <inheritdoc/>
        public MongoUserOnlyStore(DBContext context, IdentityErrorDescriber describer = null) : base(context, describer) { }
    }

    /// <inheritdoc/>
    public class MongoUserOnlyStore<TUser, TContext> : MongoUserOnlyStore<TUser, TContext, IdentityUserClaim<string>, IdentityUserLogin<string>, IdentityUserToken<string>>
        where TUser : MongoIdentityUser
        where TContext : DBContext
    {
        /// <inheritdoc/>
        public MongoUserOnlyStore(TContext context, IdentityErrorDescriber describer = null) : base(context, describer) { }
    }


    /// <inheritdoc/>
    public class MongoUserOnlyStore<TUser, TContext, TUserClaim, TUserLogin, TUserToken> :
        UserStoreBase<TUser, string, TUserClaim, TUserLogin, TUserToken>,
        IUserAuthenticationTokenStore<TUser>
        where TUser : MongoIdentityUser
        where TContext : DBContext
        where TUserClaim : IdentityUserClaim<string>, new()
        where TUserLogin : IdentityUserLogin<string>, new()
        where TUserToken : IdentityUserToken<string>, new()
    {
        /// <summary>
        /// Creates a new instance of the store.
        /// </summary>
        /// <param name="context">The context used to access the store.</param>
        /// <param name="describer">The <see cref="IdentityErrorDescriber"/> used to describe store errors.</param>
        public MongoUserOnlyStore(TContext context, IdentityErrorDescriber describer = null) : base(describer ?? new IdentityErrorDescriber())
        {
            Context = context ?? throw new ArgumentNullException(nameof(context));
        }

        /// <summary>
        /// Gets the database context for this store.
        /// </summary>
        private static TContext Context { get; set; }


        /// <summary>
        /// Gets or sets a flag indicating if changes should be persisted after CreateAsync, UpdateAsync and DeleteAsync are called.
        /// </summary>
        /// <value>
        /// True if changes should be automatically persisted, otherwise false.
        /// </value>
        public bool AutoSaveChanges { get; set; } = true;

        /// <summary>Saves the current store.</summary>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
        protected Task SaveChanges(CancellationToken cancellationToken)
        {
            return Task.CompletedTask;
        }

        /// <inheritdoc/>
        public async override Task<IdentityResult> CreateAsync(TUser user, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            await Context.SaveAsync(user, cancellationToken);
            await SaveChanges(cancellationToken);
            return IdentityResult.Success;
        }

        /// <inheritdoc/>
        public async override Task<IdentityResult> UpdateAsync(TUser user, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            var oldStamp = user.ConcurrencyStamp;
            user.ConcurrencyStamp = Guid.NewGuid().ToString();
            var updateRes = await Context.Replace<TUser>().MatchID(user.ID).Match(x => x.ConcurrencyStamp.Equals(oldStamp)).WithEntity(user).ExecuteAsync(cancellationToken);

            if (updateRes.ModifiedCount == 0)
            {
                return IdentityResult.Failed(ErrorDescriber.ConcurrencyFailure());
            }

            return IdentityResult.Success;
        }

        /// <inheritdoc/>
        public async override Task<IdentityResult> DeleteAsync(TUser user, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            user.Claims.Clear();
            user.Roles.Clear();
            user.Logins.Clear();
            user.Tokens.Clear();
            var oldStamp = user.ConcurrencyStamp;
            user.ConcurrencyStamp = Guid.NewGuid().ToString();
            var deleteRes = await Context.DeleteAsync<TUser>(x => x.ID.Equals(user.ID)
                                                              && x.ConcurrencyStamp.Equals(oldStamp), cancellationToken);
            if (deleteRes.DeletedCount == 0)
            {
                return IdentityResult.Failed(ErrorDescriber.ConcurrencyFailure());
            }
            return IdentityResult.Success;
        }

        /// <inheritdoc/>
        public override Task<TUser> FindByIdAsync(string userId, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            return Context.Find<TUser>().OneAsync(userId, cancellationToken);
        }

        /// <inheritdoc/>
        public override Task<TUser> FindByNameAsync(string normalizedUserName, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            return Context.Find<TUser>().Match(u => u.NormalizedUserName == normalizedUserName).ExecuteFirstAsync(cancellationToken);
        }

        /// <inheritdoc/>
        public override IQueryable<TUser> Users
        {
            get { return Context.Queryable<TUser>(); }
        }



        /// <inheritdoc/>
        protected override Task<TUser> FindUserAsync(string userId, CancellationToken cancellationToken)
        {
            return Context.Find<TUser>().Match(u => userId).ExecuteFirstAsync(cancellationToken);
        }

        /// <inheritdoc/>
        protected override async Task<TUserLogin> FindUserLoginAsync(string userId, string loginProvider, string providerKey, CancellationToken cancellationToken)
        {
            var user = await Context.Find<TUser>().Match(x => x.Id.Equals(userId) && x.Logins.Any(e => e.LoginProvider == loginProvider && e.ProviderKey == providerKey)).ExecuteFirstAsync(cancellationToken);
            if (user != null)
            {
                return (TUserLogin)user.GetUserLogin(loginProvider, providerKey);
            }
            return default;
        }

        /// <inheritdoc/>
        protected override async Task<TUserLogin> FindUserLoginAsync(string loginProvider, string providerKey, CancellationToken cancellationToken)
        {
            var user = await Context.Find<TUser>().Match(x => x.Logins.Any(e => e.LoginProvider == loginProvider && e.ProviderKey == providerKey)).ExecuteFirstAsync(cancellationToken);
            if (user != null)
            {
                return (TUserLogin)user.GetUserLogin(loginProvider, providerKey);
            }
            return default;
        }






        /// <inheritdoc/>
        public override Task<IList<Claim>> GetClaimsAsync(TUser user, CancellationToken cancellationToken = default)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            return Task.FromResult(user.Claims.Select(e => e.ToClaim()).ToList() as IList<Claim>);
        }

        /// <inheritdoc/>
        public override async Task AddClaimsAsync(TUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken = default)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            if (claims == null)
            {
                throw new ArgumentNullException(nameof(claims));
            }
            var addedSome = false;
            foreach (var claim in claims)
            {
                if (user.AddClaim(claim))
                {
                    addedSome |= true;
                }
            }
            if (addedSome)
            {
                var op = await Context.Update<TUser>().MatchID(user.Id).Modify(p => p.Claims, user.Claims).ExecuteAsync();
                if (!op.IsAcknowledged)
                {
                    throw new Exception($"Failed to add claims to user {user.Id}");
                }
            }
        }

        /// <inheritdoc/>
        public async override Task ReplaceClaimAsync(TUser user, Claim claim, Claim newClaim, CancellationToken cancellationToken = default)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            if (claim == null)
            {
                throw new ArgumentNullException(nameof(claim));
            }
            if (newClaim == null)
            {
                throw new ArgumentNullException(nameof(newClaim));
            }

            if (user.ReplaceClaim(claim, newClaim))
            {
                await Context.Update<TUser>().MatchID(user.Id).Modify(e => e.Claims, user.Claims).ExecuteAsync();
            }
        }

        /// <inheritdoc/>
        public async override Task RemoveClaimsAsync(TUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken = default)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            if (claims == null)
            {
                throw new ArgumentNullException(nameof(claims));
            }
            if (user.RemoveClaims(claims))
            {
                await Context.Update<TUser>().MatchID(user.Id).Modify(e => e.Claims, user.Claims).ExecuteAsync();
            }
        }

        /// <inheritdoc/>
        public override async Task AddLoginAsync(TUser user, UserLoginInfo login, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            if (login == null)
            {
                throw new ArgumentNullException(nameof(login));
            }

            if (user.AddLogin(login))
            {
                await Context.Update<TUser>().MatchID(user.Id).Modify(e => e.Logins, user.Logins).ExecuteAsync();
            }
        }


        /// <inheritdoc/>
        public override Task RemoveLoginAsync(TUser user, string loginProvider, string providerKey, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            var entry = user.Logins.FirstOrDefault(e => e.LoginProvider == loginProvider && e.ProviderKey == providerKey);
            if (entry != null)
            {
                user.RemoveLogin(entry);
            }
            return Task.CompletedTask;
        }

        /// <inheritdoc/>
        public override Task<IList<UserLoginInfo>> GetLoginsAsync(TUser user, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            return Task.FromResult(user.Logins.ToList() as IList<UserLoginInfo>);
        }

        /// <inheritdoc/>
        public async override Task<TUser> FindByLoginAsync(string loginProvider, string providerKey,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            var userLogin = await FindUserLoginAsync(loginProvider, providerKey, cancellationToken);
            if (userLogin != null)
            {
                return await FindUserAsync(userLogin.UserId, cancellationToken);
            }
            return null;
        }

        /// <inheritdoc/>
        public override Task<TUser> FindByEmailAsync(string normalizedEmail, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            return Context.Find<TUser>().Match(u => u.NormalizedEmail == normalizedEmail).ExecuteFirstAsync(cancellationToken);
        }

        /// <inheritdoc/>
        public async override Task<IList<TUser>> GetUsersForClaimAsync(Claim claim, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (claim == null)
            {
                throw new ArgumentNullException(nameof(claim));
            }

            return await Context.Find<TUser>()
                .Match(fb => fb.ElemMatch(x => x.Claims, userClaims => userClaims.Value.Equals(claim.Value) && userClaims.Type.Equals(claim.Type))).ExecuteAsync(cancellationToken);

        }


        #region Token Management

        /// <inheritdoc/>
        protected override Task<TUserToken> FindTokenAsync(TUser user, string loginProvider, string name, CancellationToken cancellationToken)
        {
            return Task.FromResult((TUserToken)user.GetToken(loginProvider, name));
        }

        /// <inheritdoc/>
        protected override async Task AddUserTokenAsync(TUserToken token)
        {
            var user = await Context.Find<TUser>().MatchID(token.UserId).ExecuteFirstAsync();
            if (user != null)
            {
                if (user.AddUserToken(token))
                {
                    await Context.Update<TUser>().MatchID(token.UserId).Modify(e => e.Tokens, user.Tokens).ExecuteAsync();
                }
            }
        }

        /// <inheritdoc/>
        protected override async Task RemoveUserTokenAsync(TUserToken token)
        {
            var user = await Context.Find<TUser>().MatchID(token.UserId).ExecuteFirstAsync();
            if (user != null)
            {
                if (user.RemoveUserToken(token))
                {
                    await Context.Update<TUser>().MatchID(token.UserId).Modify(e => e.Tokens, user.Tokens).ExecuteAsync();
                }
            }
        }

        #endregion Token Management

        #region UserStoreBase overrides
        private async Task<T> SetBase<T>(TUser user, Expression<Func<TUser, T>> expression, T value, CancellationToken cancellationToken = default, bool ignoreCheck = false)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            var compiled = expression.Compile();
            async Task common()
            {
                var memberExpression = (MemberExpression)expression.Body;
                var member = (PropertyInfo)memberExpression.Member;
                member.SetValue(user, value);
                await Context.Update<TUser>().MatchID(user.Id).Modify(expression, value).ExecuteAsync(cancellationToken);
            }
            if (ignoreCheck)
            {
                await common();
            }
            else
            {
                if (!EqualityComparer<T>.Default.Equals(compiled(user), value))
                {
                    await common();
                }
            }
            return value;
        }

        /// <inheritdoc />
        public override Task SetUserNameAsync(TUser user, string userName, CancellationToken cancellationToken = default)
        {
            return SetBase(user, e => e.UserName, userName, cancellationToken);
        }

        /// <inheritdoc />
        public override Task SetNormalizedUserNameAsync(TUser user, string normalizedName, CancellationToken cancellationToken = default)
        {
            return SetBase(user, e => e.NormalizedUserName, normalizedName, cancellationToken);
        }

        /// <inheritdoc />
        public override Task SetPasswordHashAsync(TUser user, string passwordHash, CancellationToken cancellationToken = default)
        {
            return SetBase(user, e => e.PasswordHash, passwordHash, cancellationToken);
        }

        /// <inheritdoc />
        public override Task SetEmailConfirmedAsync(TUser user, bool confirmed, CancellationToken cancellationToken = default)
        {
            return SetBase(user, e => e.EmailConfirmed, confirmed, cancellationToken);
        }

        /// <inheritdoc />
        public override Task SetEmailAsync(TUser user, string email, CancellationToken cancellationToken = default)
        {
            return SetBase(user, e => e.Email, email, cancellationToken);
        }

        /// <inheritdoc />
        public override Task SetNormalizedEmailAsync(TUser user, string normalizedEmail, CancellationToken cancellationToken = default)
        {
            return SetBase(user, e => e.NormalizedEmail, normalizedEmail, cancellationToken);
        }

        /// <inheritdoc />
        public override Task SetLockoutEndDateAsync(TUser user, DateTimeOffset? lockoutEnd, CancellationToken cancellationToken = default)
        {
            return SetBase(user, e => e.LockoutEnd, lockoutEnd, cancellationToken);
        }

        /// <inheritdoc />
        public override Task<int> IncrementAccessFailedCountAsync(TUser user, CancellationToken cancellationToken = default)
        {
            return SetBase(user, e => e.AccessFailedCount, user.AccessFailedCount + 1, cancellationToken);
        }

        /// <inheritdoc />
        public override Task ResetAccessFailedCountAsync(TUser user, CancellationToken cancellationToken = default)
        {
            return SetBase(user, e => e.AccessFailedCount, 0, cancellationToken);
        }

        /// <inheritdoc />
        public override Task SetLockoutEnabledAsync(TUser user, bool enabled, CancellationToken cancellationToken = default)
        {
            return SetBase(user, e => e.LockoutEnabled, enabled, cancellationToken);
        }

        /// <inheritdoc />
        public override Task SetPhoneNumberAsync(TUser user, string phoneNumber, CancellationToken cancellationToken = default)
        {
            return SetBase(user, e => e.PhoneNumber, phoneNumber, cancellationToken);
        }

        /// <inheritdoc />
        public override Task SetPhoneNumberConfirmedAsync(TUser user, bool confirmed, CancellationToken cancellationToken = default)
        {
            return SetBase(user, e => e.PhoneNumberConfirmed, confirmed, cancellationToken);
        }


        /// <inheritdoc />
        public override Task SetSecurityStampAsync(TUser user, string stamp, CancellationToken cancellationToken = default)
        {
            return SetBase(user, e => e.SecurityStamp, stamp, cancellationToken);
        }

        /// <inheritdoc />
        public override Task SetTwoFactorEnabledAsync(TUser user, bool enabled, CancellationToken cancellationToken = default)
        {
            return SetBase(user, e => e.TwoFactorEnabled, enabled, cancellationToken);
        }

        /// <inheritdoc/>
        public override async Task SetTokenAsync(TUser user, string loginProvider, string name, string value, CancellationToken cancellationToken)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            Task common()
            {
                return SetBase(user, e => e.Tokens, user.Tokens, cancellationToken: cancellationToken, ignoreCheck: true);
            }
            var token = await FindTokenAsync(user, loginProvider, name, cancellationToken);
            if (token == null)
            {
                if (user.AddUserToken(CreateUserToken(user, loginProvider, name, value)))
                {
                    await common();
                }
            }
            else
            {
                if (user.SetToken(token, value))
                {
                    await common();
                }
            }
        }

        /// <inheritdoc/>
        public override async Task RemoveTokenAsync(TUser user, string loginProvider, string name, CancellationToken cancellationToken)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            var entry = await FindTokenAsync(user, loginProvider, name, cancellationToken);
            if (entry != null)
            {
                if (user.RemoveUserToken(entry))
                {
                    await SetBase(user, e => e.Tokens, user.Tokens, cancellationToken: cancellationToken, ignoreCheck: true);
                }
            }
        }

        /// <inheritdoc/>       
        public override async Task<string> GetTokenAsync(TUser user, string loginProvider, string name, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            var entry = await FindTokenAsync(user, loginProvider, name, cancellationToken);
            return entry?.Value;
        }

        private const string InternalLoginProvider = "[AspNetUserStore]";
        private const string AuthenticatorKeyTokenName = "AuthenticatorKey";
        private const string RecoveryCodeTokenName = "RecoveryCodes";

        /// <inheritdoc/>       
        public override Task SetAuthenticatorKeyAsync(TUser user, string key, CancellationToken cancellationToken)
            => SetTokenAsync(user, InternalLoginProvider, AuthenticatorKeyTokenName, key, cancellationToken);

        /// <inheritdoc/>       
        public override Task<string> GetAuthenticatorKeyAsync(TUser user, CancellationToken cancellationToken)
            => GetTokenAsync(user, InternalLoginProvider, AuthenticatorKeyTokenName, cancellationToken);

        /// <inheritdoc/>       
        public override async Task<int> CountCodesAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            var mergedCodes = await GetTokenAsync(user, InternalLoginProvider, RecoveryCodeTokenName, cancellationToken) ?? "";
            if (mergedCodes.Length > 0)
            {
                return mergedCodes.Split(';').Length;
            }
            return 0;
        }

        /// <inheritdoc/>       
        public override Task ReplaceCodesAsync(TUser user, IEnumerable<string> recoveryCodes, CancellationToken cancellationToken)
        {
            var mergedCodes = string.Join(";", recoveryCodes);
            return SetTokenAsync(user, InternalLoginProvider, RecoveryCodeTokenName, mergedCodes, cancellationToken);
        }

        /// <inheritdoc/>       
        public override async Task<bool> RedeemCodeAsync(TUser user, string code, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            if (code == null)
            {
                throw new ArgumentNullException(nameof(code));
            }

            var mergedCodes = await GetTokenAsync(user, InternalLoginProvider, RecoveryCodeTokenName, cancellationToken) ?? "";
            var splitCodes = mergedCodes.Split(';');
            if (splitCodes.Contains(code))
            {
                var updatedCodes = new List<string>(splitCodes.Where(s => s != code));
                await ReplaceCodesAsync(user, updatedCodes, cancellationToken);
                return true;
            }
            return false;
        }

        #endregion
    }
}