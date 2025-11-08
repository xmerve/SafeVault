using Microsoft.Data.Sqlite;

namespace SafeVault.Data;

/// <summary>
/// Provides secure, parameterised access to the user store.
/// </summary>
public class UserRepository
{
    private readonly string _connectionString;

    public UserRepository(string connectionString)
    {
        ArgumentNullException.ThrowIfNull(connectionString);
        _connectionString = connectionString;
    }

    public async Task InitialiseAsync()
    {
        await using var connection = new SqliteConnection(_connectionString);
        await connection.OpenAsync().ConfigureAwait(false);

        var command = connection.CreateCommand();
        command.CommandText = """
            CREATE TABLE IF NOT EXISTS Users (
                UserID INTEGER PRIMARY KEY AUTOINCREMENT,
                Username TEXT NOT NULL UNIQUE,
                Email TEXT NOT NULL,
                PasswordHash TEXT NOT NULL,
                Role TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS IX_Users_Role ON Users(Role);
            """;
        await command.ExecuteNonQueryAsync().ConfigureAwait(false);
    }

    public async Task<int> CreateUserAsync(string username, string email, string passwordHash, string role)
    {
        await using var connection = new SqliteConnection(_connectionString);
        await connection.OpenAsync().ConfigureAwait(false);

        await using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO Users (Username, Email, PasswordHash, Role)
            VALUES ($username, $email, $passwordHash, $role);
            SELECT last_insert_rowid();
            """;

        command.Parameters.AddWithValue("$username", username);
        command.Parameters.AddWithValue("$email", email);
        command.Parameters.AddWithValue("$passwordHash", passwordHash);
        command.Parameters.AddWithValue("$role", role);

        var result = await command.ExecuteScalarAsync().ConfigureAwait(false);
        return Convert.ToInt32(result);
    }

    public async Task<UserRecord?> GetUserByUsernameAsync(string username)
    {
        await using var connection = new SqliteConnection(_connectionString);
        await connection.OpenAsync().ConfigureAwait(false);

        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT UserID, Username, Email, PasswordHash, Role
            FROM Users
            WHERE Username = $username;
            """;
        command.Parameters.AddWithValue("$username", username);

        await using var reader = await command.ExecuteReaderAsync().ConfigureAwait(false);
        if (await reader.ReadAsync().ConfigureAwait(false))
        {
            return new UserRecord(
                reader.GetInt32(0),
                reader.GetString(1),
                reader.GetString(2),
                reader.GetString(3),
                reader.GetString(4));
        }

        return null;
    }

    public async Task<int> GetUserCountByEmailAsync(string email)
    {
        await using var connection = new SqliteConnection(_connectionString);
        await connection.OpenAsync().ConfigureAwait(false);

        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT COUNT(*)
            FROM Users
            WHERE Email = $email;
            """;
        command.Parameters.AddWithValue("$email", email);

        var result = await command.ExecuteScalarAsync().ConfigureAwait(false);
        return Convert.ToInt32(result);
    }

    public async Task<IReadOnlyList<UserSummary>> SearchByUsernameAsync(string partialUsername)
    {
        await using var connection = new SqliteConnection(_connectionString);
        await connection.OpenAsync().ConfigureAwait(false);

        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT Username, Email, Role
            FROM Users
            WHERE Username LIKE $pattern ESCAPE '\';
            """;
        command.Parameters.AddWithValue("$pattern", EscapeLikePattern(partialUsername) + "%");

        var users = new List<UserSummary>();
        await using var reader = await command.ExecuteReaderAsync().ConfigureAwait(false);
        while (await reader.ReadAsync().ConfigureAwait(false))
        {
            users.Add(new UserSummary(reader.GetString(0), reader.GetString(1), reader.GetString(2)));
        }

        return users;
    }

    private static string EscapeLikePattern(string raw)
    {
        if (string.IsNullOrEmpty(raw))
        {
            return string.Empty;
        }

        return raw
            .Replace(@"\", @"\\", StringComparison.Ordinal)
            .Replace("%", @"\%", StringComparison.Ordinal)
            .Replace("_", @"\_", StringComparison.Ordinal);
    }
}

public record UserRecord(int UserId, string Username, string Email, string PasswordHash, string Role);

public record UserSummary(string Username, string Email, string Role);

