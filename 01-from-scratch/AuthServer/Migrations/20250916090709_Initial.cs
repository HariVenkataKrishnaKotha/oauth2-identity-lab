using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace AuthServer.Migrations
{
    /// <inheritdoc />
    public partial class Initial : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "AuthorizationCodes",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Code = table.Column<string>(type: "nvarchar(120)", maxLength: 120, nullable: false),
                    ClientDbId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    ClientId = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    ResourceOwnerId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    RedirectUri = table.Column<string>(type: "nvarchar(2000)", maxLength: 2000, nullable: false),
                    ScopeCsv = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    CodeChallenge = table.Column<string>(type: "nvarchar(255)", maxLength: 255, nullable: true),
                    CodeChallengeMethod = table.Column<string>(type: "nvarchar(10)", maxLength: 10, nullable: true),
                    ExpiresUtc = table.Column<DateTime>(type: "datetime2", nullable: false),
                    Used = table.Column<bool>(type: "bit", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AuthorizationCodes", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "OAuthClients",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    ClientId = table.Column<string>(type: "nvarchar(100)", maxLength: 100, nullable: false),
                    ClientSecretHash = table.Column<byte[]>(type: "varbinary(max)", nullable: true),
                    ClientSecretSalt = table.Column<byte[]>(type: "varbinary(max)", nullable: true),
                    IsConfidential = table.Column<bool>(type: "bit", nullable: false),
                    TokenEndpointAuthMethod = table.Column<string>(type: "nvarchar(50)", maxLength: 50, nullable: false),
                    DisplayName = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    RedirectUrisJson = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    AllowedScopesJson = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    CreatedUtc = table.Column<DateTime>(type: "datetime2", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_OAuthClients", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "RefreshTokens",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Handle = table.Column<string>(type: "nvarchar(200)", maxLength: 200, nullable: false),
                    FamilyId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    ClientDbId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    ResourceOwnerId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    ScopeCsv = table.Column<string>(type: "nvarchar(1000)", maxLength: 1000, nullable: false),
                    ExpiresUtc = table.Column<DateTime>(type: "datetime2", nullable: false),
                    Revoked = table.Column<bool>(type: "bit", nullable: false),
                    RotationParent = table.Column<string>(type: "nvarchar(200)", maxLength: 200, nullable: true),
                    ReplacedBy = table.Column<string>(type: "nvarchar(200)", maxLength: 200, nullable: true),
                    CompromisedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_RefreshTokens", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "ResourceOwnerConsents",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    ResourceOwnerId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    ClientDbId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    ScopeCsv = table.Column<string>(type: "nvarchar(1000)", maxLength: 1000, nullable: false),
                    GrantedUtc = table.Column<DateTime>(type: "datetime2", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ResourceOwnerConsents", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "ResourceOwners",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Username = table.Column<string>(type: "nvarchar(200)", maxLength: 200, nullable: false),
                    PasswordHash = table.Column<byte[]>(type: "varbinary(max)", nullable: false),
                    PasswordSalt = table.Column<byte[]>(type: "varbinary(max)", nullable: false),
                    CreatedUtc = table.Column<DateTime>(type: "datetime2", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ResourceOwners", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Scopes",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Name = table.Column<string>(type: "nvarchar(200)", maxLength: 200, nullable: false),
                    DisplayName = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    Description = table.Column<string>(type: "nvarchar(max)", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Scopes", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_AuthorizationCodes_Code",
                table: "AuthorizationCodes",
                column: "Code",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_OAuthClients_ClientId",
                table: "OAuthClients",
                column: "ClientId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_RefreshTokens_Handle",
                table: "RefreshTokens",
                column: "Handle",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_ResourceOwnerConsents_ResourceOwnerId_ClientDbId",
                table: "ResourceOwnerConsents",
                columns: new[] { "ResourceOwnerId", "ClientDbId" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_ResourceOwners_Username",
                table: "ResourceOwners",
                column: "Username",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_Scopes_Name",
                table: "Scopes",
                column: "Name",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "AuthorizationCodes");

            migrationBuilder.DropTable(
                name: "OAuthClients");

            migrationBuilder.DropTable(
                name: "RefreshTokens");

            migrationBuilder.DropTable(
                name: "ResourceOwnerConsents");

            migrationBuilder.DropTable(
                name: "ResourceOwners");

            migrationBuilder.DropTable(
                name: "Scopes");
        }
    }
}
