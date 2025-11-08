using Microsoft.Data.Sqlite;
using SafeVault.Data;
using SafeVault.Security;

namespace SafeVault.Tests;

public class SecurityTests
{
    private SqliteConnection? _keeperConnection;
    private UserRepository? _repository;
    private UserInputValidator? _validator;
    private AuthenticationService? _authService;

    [SetUp]
    public async Task Setup()
    {
        var connectionString = $"Data Source=file:memdb_{Guid.NewGuid()};Mode=Memory;Cache=Shared;Foreign Keys=True";
        _keeperConnection = new SqliteConnection(connectionString);
        await _keeperConnection.OpenAsync();

        _repository = new UserRepository(connectionString);
        await _repository.InitialiseAsync();
        _validator = new UserInputValidator();
        _authService = new AuthenticationService(_repository, _validator);
    }

    [TearDown]
    public void TearDown()
    {
        _keeperConnection?.Dispose();
    }

    [Test]
    public void SanitizeForHtml_RemovesScriptsAndEncodesHtml()
    {
        const string maliciousInput = " <script>alert('owned');</script><b>Welcome</b> ";

        var sanitized = InputSanitizer.SanitizeForHtml(maliciousInput);

        Assert.That(sanitized, Is.EqualTo("&lt;b&gt;Welcome&lt;/b&gt;"));
        Assert.That(sanitized, Does.Not.Contain("script"));
    }

    [Test]
    public void ValidateRegistration_ReturnsErrorsForInvalidPayload()
    {
        Assert.That(_validator, Is.Not.Null);

        var result = _validator!.ValidateRegistration("!nv@lid<script>", "not-an-email", "weak");

        Assert.Multiple(() =>
        {
            Assert.That(result.IsValid, Is.False);
            Assert.That(result.Errors, Has.Exactly(1).Matches<string>(e => e.Contains("Username")));
            Assert.That(result.Errors, Has.Exactly(1).Matches<string>(e => e.Contains("Email")));
        });
    }

    [Test]
    public async Task RegisterAsync_StoresHashedPasswordWithoutInjection()
    {
        Assert.That(_authService, Is.Not.Null);
        Assert.That(_repository, Is.Not.Null);

        var registration = await _authService!.RegisterAsync("Secure_User", "SECURE@Example.com ", "Str0ngP@ssw0rd!", "admin");
        Assert.That(registration.Succeeded, Is.True, registration.Message);

        var persisted = await _repository!.GetUserByUsernameAsync("Secure_User");
        Assert.That(persisted, Is.Not.Null);
        Assert.That(persisted!.PasswordHash, Does.Not.Contain("Str0ngP@ssw0rd!"));
        Assert.That(persisted.PasswordHash, Does.StartWith("$2")); // bcrypt hash prefix

        var count = await _repository.GetUserCountByEmailAsync(registration.Principal!.Value.Email);
        Assert.That(count, Is.EqualTo(1));
    }

    [Test]
    public async Task SearchByUsernameAsync_ResistsSqlInjection()
    {
        Assert.That(_repository, Is.Not.Null, "Repository should be initialised in SetUp.");

        await _repository!.CreateUserAsync("Alice_User", "alice@example.com", "$2y$dummyhash", "user");

        var results = await _repository.SearchByUsernameAsync("Alice'; DROP TABLE Users;--");

        Assert.That(results, Is.Empty);

        var stillExists = await _repository.GetUserCountByEmailAsync("alice@example.com");
        Assert.That(stillExists, Is.EqualTo(1), "Users table should remain intact after injection attempt.");
    }

    [Test]
    public void SanitizeForHtml_NeutralisesEventHandlers()
    {
        const string payload = "<img src=x onerror=\"alert(1)\">";

        var sanitized = InputSanitizer.SanitizeForHtml(payload);

        Assert.That(sanitized, Does.Not.Contain("onerror"));
        Assert.That(sanitized, Is.EqualTo("&lt;img src=x&gt;"));
    }

    [Test]
    public void SanitizeForHtml_StripsJavascriptProtocols()
    {
        const string payload = "<a href=\"javascript:alert(1)\">click</a>";

        var sanitized = InputSanitizer.SanitizeForHtml(payload);

        Assert.That(sanitized, Does.Not.Contain("javascript"));
        Assert.That(sanitized, Is.EqualTo("&lt;a href=&quot;alert(1)&quot;&gt;click&lt;/a&gt;"));
    }

    [Test]
    public async Task AuthenticateAsync_FailsWithInvalidPassword()
    {
        Assert.That(_authService, Is.Not.Null);

        var registration = await _authService!.RegisterAsync("LoginUser", "login@example.com", "Sup3rS@fePass!", "user");
        Assert.That(registration.Succeeded, Is.True);

        var result = await _authService.AuthenticateAsync("LoginUser", "wrongPassword!");

        Assert.That(result.IsAuthenticated, Is.False);
        Assert.That(result.Message, Does.Contain("Invalid username or password"));
    }

    [Test]
    public async Task AuthorizationService_RestrictsAccessByRole()
    {
        Assert.That(_authService, Is.Not.Null);

        var adminRegistration = await _authService!.RegisterAsync("AdminUser", "admin@example.com", "Adm1n$uperPass!", "admin");
        var userRegistration = await _authService.RegisterAsync("RegularUser", "user@example.com", "User$ecurePass1!", "user");
        Assert.Multiple(() =>
        {
            Assert.That(adminRegistration.Succeeded, Is.True);
            Assert.That(userRegistration.Succeeded, Is.True);
        });

        var adminAuthorized = AuthorizationService.Authorize(adminRegistration.Principal, "admin");
        var userAuthorized = AuthorizationService.Authorize(userRegistration.Principal, "admin");

        Assert.That(adminAuthorized, Is.True, "Admin should access admin resources.");
        Assert.That(userAuthorized, Is.False, "Regular user must not access admin resources.");
    }

    [Test]
    public async Task SearchByUsernameAsync_EscapesWildcards()
    {
        Assert.That(_repository, Is.Not.Null);

        await _repository!.CreateUserAsync("Wildcard_User", "wild@example.com", "$2y$dummyhash", "user");

        var results = await _repository.SearchByUsernameAsync("Wildcard_");

        Assert.That(results, Has.Count.EqualTo(1));
        Assert.That(results[0].Username, Is.EqualTo("Wildcard_User"));
    }
}
