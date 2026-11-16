using System.Data;
using System.ComponentModel.DataAnnotations;
using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.Data.SqlClient;
using TryBlazor.Security;

namespace TryBlazor.Data;

public sealed class UserService
{
    private const int SaltSize = 16;
    private const int HashSize = 32;
    private const int Pbkdf2Iterations = 600_000;
    private static readonly byte[] DummySalt = new byte[SaltSize];
    private static readonly byte[] DummyHash = new byte[HashSize];
    private readonly string _connectionString;

    public UserService(IConfiguration configuration)
    {
        _connectionString = configuration.GetConnectionString("Users")
            ?? throw new InvalidOperationException("Connection string 'Users' is not configured.");
    }

    public async Task<IReadOnlyList<UserRecord>> GetFirstTenAsync()
    {
        const string query = @"
            SELECT TOP (10) [Id], [FirstName], [LastName], [Email], [Role]
            FROM [TryDbProjects].[dbo].[Users]
            ORDER BY [Id];";
        var users = new List<UserRecord>();

        await using var connection = new SqlConnection(_connectionString);
        await connection.OpenAsync();

        await using var command = new SqlCommand(query, connection);
        await using var reader = await command.ExecuteReaderAsync();

        while (await reader.ReadAsync())
        {
            users.Add(new UserRecord(
                reader.GetGuid(0),
                reader.GetString(1),
                reader.IsDBNull(2) ? null : reader.GetString(2),
                reader.IsDBNull(3) ? null : reader.GetString(3),
                reader.GetInt32(4)));
        }

        return users;
    }

    public async Task<IReadOnlyList<UserRecord>> GetAssignableUsersAsync()
    {
        const string query = @"
            SELECT [Id], [FirstName], [LastName], [Email], [Role]
            FROM [TryDbProjects].[dbo].[Users]
            ORDER BY [FirstName], [LastName], [Id];";
        var users = new List<UserRecord>();

        await using var connection = new SqlConnection(_connectionString);
        await connection.OpenAsync();

        await using var command = new SqlCommand(query, connection);
        await using var reader = await command.ExecuteReaderAsync();

        while (await reader.ReadAsync())
        {
            users.Add(new UserRecord(
                reader.GetGuid(0),
                reader.GetString(1),
                reader.IsDBNull(2) ? null : reader.GetString(2),
                reader.IsDBNull(3) ? null : reader.GetString(3),
                reader.GetInt32(4)));
        }

        return users;
    }

    public async Task<UserRecord?> AuthenticateAsync(string email, string password)
    {
        const string query = @"
            SELECT TOP (2) [Id], [FirstName], [LastName], [Email], [Hash], [Salt], [Role]
            FROM [TryDbProjects].[dbo].[Users]
            WHERE [Email] = @Email
            ORDER BY [Id];";
        var matches = new List<(Guid Id, string FirstName, string? LastName, string? Email, string? Hash, string? Salt, int Role)>(2);

        await using var connection = new SqlConnection(_connectionString);
        await connection.OpenAsync();

        await using var command = new SqlCommand(query, connection);
        command.Parameters.Add("@Email", SqlDbType.NVarChar, 200).Value = email;
        await using var reader = await command.ExecuteReaderAsync();

        while (await reader.ReadAsync())
        {
            matches.Add((
                reader.GetGuid(0),
                reader.GetString(1),
                reader.IsDBNull(2) ? null : reader.GetString(2),
                reader.IsDBNull(3) ? null : reader.GetString(3),
                reader.IsDBNull(4) ? null : reader.GetString(4),
                reader.IsDBNull(5) ? null : reader.GetString(5),
                reader.GetInt32(6)));
        }

        if (matches.Count != 1)
        {
            VerifyPassword(password, DummySalt, DummyHash);
            return null;
        }

        var match = matches[0];
        if (!TryDecodeCredential(match.Hash, match.Salt, out var storedHash, out var salt))
        {
            VerifyPassword(password, DummySalt, DummyHash);
            return null;
        }

        if (!VerifyPassword(password, salt, storedHash))
        {
            return null;
        }

        return new UserRecord(match.Id, match.FirstName, match.LastName, match.Email, match.Role);
    }

    public async Task<UserRecord> CreateAsync(
        string firstName,
        string lastName,
        string email,
        string password,
        int role)
    {
        if (role is < 0 or > 4)
        {
            throw new ArgumentOutOfRangeException(nameof(role), "Roles must be between 0 and 4.");
        }

        var salt = RandomNumberGenerator.GetBytes(SaltSize);
        var passwordHash = Convert.ToBase64String(Rfc2898DeriveBytes.Pbkdf2(
            password,
            salt,
            Pbkdf2Iterations,
            HashAlgorithmName.SHA256,
            HashSize));
        var passwordSalt = Convert.ToBase64String(salt);

        const string query = @"
            INSERT INTO [TryDbProjects].[dbo].[Users]
                ([FirstName], [LastName], [Email], [Hash], [Salt], [Role])
            OUTPUT INSERTED.[Id]
            VALUES (@FirstName, @LastName, @Email, @Hash, @Salt, @Role);";

        await using var connection = new SqlConnection(_connectionString);
        await connection.OpenAsync();

        await using var command = new SqlCommand(query, connection);
        command.Parameters.Add("@FirstName", SqlDbType.NVarChar, 100).Value = firstName;
        command.Parameters.Add("@LastName", SqlDbType.NVarChar, 100).Value = lastName;
        command.Parameters.Add("@Email", SqlDbType.NVarChar, 200).Value = email;
        command.Parameters.Add("@Hash", SqlDbType.NVarChar, 50).Value = passwordHash;
        command.Parameters.Add("@Salt", SqlDbType.NVarChar, 50).Value = passwordSalt;
        command.Parameters.Add("@Role", SqlDbType.Int).Value = role;

        var result = await command.ExecuteScalarAsync();
        if (result is not Guid id)
        {
            throw new InvalidOperationException("The user insert did not return a valid ID.");
        }

        return new UserRecord(id, firstName, lastName, email, role);
    }

    public async Task ResetPasswordAsync(ClaimsPrincipal actor, Guid userId, string newPassword)
    {
        if (actor.Identity?.IsAuthenticated != true || !RolePolicies.HasMinimumRole(actor, 4))
        {
            throw new UnauthorizedAccessException("Only users with role 4 or higher can reset passwords.");
        }

        var salt = RandomNumberGenerator.GetBytes(SaltSize);
        var passwordHash = Convert.ToBase64String(Rfc2898DeriveBytes.Pbkdf2(
            newPassword,
            salt,
            Pbkdf2Iterations,
            HashAlgorithmName.SHA256,
            HashSize));
        var passwordSalt = Convert.ToBase64String(salt);

        const string query = @"
            UPDATE [TryDbProjects].[dbo].[Users]
            SET [Hash] = @Hash, [Salt] = @Salt
            WHERE [Id] = @UserId;";

        await using var connection = new SqlConnection(_connectionString);
        await connection.OpenAsync();

        await using var command = new SqlCommand(query, connection);
        command.Parameters.Add("@UserId", SqlDbType.UniqueIdentifier).Value = userId;
        command.Parameters.Add("@Hash", SqlDbType.NVarChar, 50).Value = passwordHash;
        command.Parameters.Add("@Salt", SqlDbType.NVarChar, 50).Value = passwordSalt;

        if (await command.ExecuteNonQueryAsync() != 1)
        {
            throw new InvalidOperationException($"User {userId} was not found or could not be updated.");
        }
    }

    private static bool TryDecodeCredential(string? encodedHash, string? encodedSalt, out byte[] hash, out byte[] salt)
    {
        hash = Array.Empty<byte>();
        salt = Array.Empty<byte>();

        if (encodedHash is null || encodedSalt is null)
        {
            return false;
        }

        try
        {
            hash = Convert.FromBase64String(encodedHash);
            salt = Convert.FromBase64String(encodedSalt);
            return hash.Length == HashSize && salt.Length == SaltSize;
        }
        catch (FormatException)
        {
            return false;
        }
    }

    private static bool VerifyPassword(string password, byte[] salt, byte[] expectedHash)
    {
        var actualHash = Rfc2898DeriveBytes.Pbkdf2(
            password,
            salt,
            Pbkdf2Iterations,
            HashAlgorithmName.SHA256,
            HashSize);
        return CryptographicOperations.FixedTimeEquals(actualHash, expectedHash);
    }
}

public sealed class UserCreateModel : IValidatableObject
{
    [Required]
    [StringLength(100)]
    public string FirstName { get; set; } = string.Empty;

    [Required]
    [StringLength(100)]
    public string LastName { get; set; } = string.Empty;

    [Required]
    [EmailAddress]
    [StringLength(200)]
    public string Email { get; set; } = string.Empty;

    [Required]
    [StringLength(128, MinimumLength = 12)]
    public string Password { get; set; } = string.Empty;

    [Required]
    [Compare(nameof(Password), ErrorMessage = "The password and confirmation do not match.")]
    public string ConfirmPassword { get; set; } = string.Empty;

    public int Role { get; set; }

    public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
    {
        if (Role is < 0 or > 4)
        {
            yield return new ValidationResult(
                "Choose one of the available roles.",
                new[] { nameof(Role) });
        }
    }
}

public sealed class PasswordResetModel
{
    [Required]
    [StringLength(128, MinimumLength = 12)]
    public string Password { get; set; } = string.Empty;

    [Required]
    [Compare(nameof(Password), ErrorMessage = "The password and confirmation do not match.")]
    public string ConfirmPassword { get; set; } = string.Empty;
}

public sealed record UserRecord(Guid Id, string FirstName, string? LastName, string? Email, int Role);
