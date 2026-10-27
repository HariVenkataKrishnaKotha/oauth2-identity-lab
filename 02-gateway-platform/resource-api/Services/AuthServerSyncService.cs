using System.Data;
using Dapper;
using Microsoft.Data.SqlClient;
using Microsoft.Extensions.Options;

namespace ResourceApi.Services;

public class AuthServerSyncService(IConfiguration cfg, ILogger<AuthServerSyncService> log)
{
    private readonly string _cs = cfg.GetConnectionString("AuthServerDb")!;
    private readonly ILogger<AuthServerSyncService> _log = log;

    public async Task<Guid> EnsureOnboardeeAsync(Guid onboardeeId, string userNameLike, string? email, CancellationToken ct)
    {
        using var conn = new SqlConnection(_cs);
        await conn.OpenAsync(ct);

        // 1) Upsert user (no password needed)
        const string upsertUser = @"
IF NOT EXISTS (SELECT 1 FROM [Users] WHERE [Id] = @Id)
BEGIN
    INSERT INTO [Users] ([Id],[UserName],[NormalizedUserName],[Email],[NormalizedEmail],[EmailConfirmed],
                         [PasswordHash],[SecurityStamp],[ConcurrencyStamp],[PhoneNumber],[PhoneNumberConfirmed],
                         [TwoFactorEnabled],[LockoutEnd],[LockoutEnabled],[AccessFailedCount],[OnboardId])
    VALUES (@Id,@UserName,@NormUser,@Email,@NormEmail,0,NULL,NEWID(),NEWID(),NULL,0,0,NULL,0,0,@OnboardId)
END";
        var userParams = new
        {
            Id = onboardeeId,
            UserName = userNameLike,
            NormUser = userNameLike.ToUpperInvariant(),
            Email = email,
            NormEmail = email?.ToUpperInvariant(),
            OnboardId = onboardeeId
        };
        await conn.ExecuteAsync(new CommandDefinition(upsertUser, userParams, commandType: CommandType.Text, cancellationToken: ct));

        // 2) Ensure role "Onboardee"
        var roleId = await conn.ExecuteScalarAsync<Guid?>(new CommandDefinition(
            "SELECT TOP 1 [Id] FROM [Roles] WHERE [Name]='Onboardee'",
            cancellationToken: ct)) ?? Guid.Empty;
        if (roleId == Guid.Empty)
        {
            roleId = Guid.NewGuid();
            await conn.ExecuteAsync(new CommandDefinition(
                "INSERT INTO [Roles] ([Id],[Name],[NormalizedName],[ConcurrencyStamp]) VALUES (@Id,'Onboardee','ONBOARDEE',NEWID())",
                new { Id = roleId }, cancellationToken: ct));
        }

        // 3) Link user to role if not already
        const string link = @"IF NOT EXISTS (SELECT 1 FROM [UserRoles] WHERE [UserId]=@U AND [RoleId]=@R)
                              INSERT INTO [UserRoles] ([UserId],[RoleId]) VALUES (@U,@R)";
        await conn.ExecuteAsync(new CommandDefinition(link, new { U = onboardeeId, R = roleId }, cancellationToken: ct));

        return onboardeeId;
    }

    public async Task<Guid> EnsureManagerAsync(string login, string email, string passwordHash, CancellationToken ct)
    {
        using var conn = new SqlConnection(_cs);
        await conn.OpenAsync(ct);

        // Does a user with this normalized username already exist?
        var existingId = await conn.ExecuteScalarAsync<Guid?>(new CommandDefinition(
            "SELECT [Id] FROM [Users] WHERE [NormalizedUserName]=@U",
            new { U = login.ToUpperInvariant() }, cancellationToken: ct));

        var userId = existingId ?? Guid.NewGuid();

        const string upsert = @"
IF NOT EXISTS (SELECT 1 FROM [Users] WHERE [Id]=@Id)
BEGIN
    INSERT INTO [Users] ([Id],[UserName],[NormalizedUserName],[Email],[NormalizedEmail],[EmailConfirmed],
                         [PasswordHash],[SecurityStamp],[ConcurrencyStamp],[PhoneNumber],[PhoneNumberConfirmed],
                         [TwoFactorEnabled],[LockoutEnd],[LockoutEnabled],[AccessFailedCount],[OnboardId])
    VALUES (@Id,@UserName,@NormUser,@Email,@NormEmail,1,@PasswordHash,NEWID(),NEWID(),NULL,0,0,NULL,0,0,NULL)
END
ELSE
BEGIN
    UPDATE [Users] SET [PasswordHash]=@PasswordHash,[Email]=@Email,[NormalizedEmail]=@NormEmail WHERE [Id]=@Id
END";

        await conn.ExecuteAsync(new CommandDefinition(upsert, new
        {
            Id = userId,
            UserName = login,
            NormUser = login.ToUpperInvariant(),
            Email = email,
            NormEmail = email.ToUpperInvariant(),
            PasswordHash = passwordHash
        }, cancellationToken: ct));

        // Ensure "Manager" role and link
        var roleId = await conn.ExecuteScalarAsync<Guid?>(new CommandDefinition(
            "SELECT TOP 1 [Id] FROM [Roles] WHERE [Name]='Manager'",
            cancellationToken: ct)) ?? Guid.Empty;
        if (roleId == Guid.Empty)
        {
            roleId = Guid.NewGuid();
            await conn.ExecuteAsync(new CommandDefinition(
                "INSERT INTO [Roles] ([Id],[Name],[NormalizedName],[ConcurrencyStamp]) VALUES (@Id,'Manager','MANAGER',NEWID())",
                new { Id = roleId }, cancellationToken: ct));
        }

        await conn.ExecuteAsync(new CommandDefinition(
            @"IF NOT EXISTS (SELECT 1 FROM [UserRoles] WHERE [UserId]=@U AND [RoleId]=@R)
              INSERT INTO [UserRoles] ([UserId],[RoleId]) VALUES (@U,@R)",
            new { U = userId, R = roleId }, cancellationToken: ct));

        return userId;
    }
}
