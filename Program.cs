using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using SecureAccountsLab6.Data;
using SecureAccountsLab6.Models;
using SecureAccountsLab6.Services;
using Microsoft.AspNetCore.DataProtection;

var builder = WebApplication.CreateBuilder(args);
var databasePath = Path.Combine(builder.Environment.ContentRootPath, "App_Data");
Directory.CreateDirectory(databasePath);
Directory.CreateDirectory(Path.Combine(databasePath, "keys"));

// Keys persist across restarts (session and token protection remain valid).
builder.Services.AddDataProtection()
    .SetApplicationName("SecureAccountsLab6")
    .PersistKeysToFileSystem(new DirectoryInfo(Path.Combine(databasePath, "keys")));

builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseSqlite(builder.Configuration.GetConnectionString("Default")));

builder.Services.AddIdentity<AppUser, IdentityRole>(options =>
{
    options.Password.RequiredLength = 8;
    options.Password.RequireUppercase = true;
    options.Password.RequireLowercase = true;
    options.Password.RequireDigit = true;
    options.Password.RequireNonAlphanumeric = true;
    options.Password.RequiredUniqueChars = 4;
    options.User.RequireUniqueEmail = true;
    options.SignIn.RequireConfirmedEmail = true;
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
    options.Lockout.MaxFailedAccessAttempts = 5;
    options.Lockout.AllowedForNewUsers = true;
    options.Tokens.AuthenticatorTokenProvider = TokenOptions.DefaultAuthenticatorProvider;
})
.AddEntityFrameworkStores<AppDbContext>()
.AddErrorDescriber<UkrainianIdentityErrorDescriber>()
.AddDefaultTokenProviders();

builder.Services.Configure<Microsoft.AspNetCore.Identity.DataProtectionTokenProviderOptions>(options =>
    options.TokenLifespan = TimeSpan.FromHours(1));
builder.Services.Configure<SecurityStampValidatorOptions>(options => options.ValidationInterval = TimeSpan.Zero);
builder.Services.ConfigureApplicationCookie(options =>
{
    options.Cookie.Name = "SecureAccounts.Auth";
    options.Cookie.HttpOnly = true;
    options.Cookie.SameSite = SameSiteMode.Lax;
    options.Cookie.SecurePolicy = builder.Environment.IsDevelopment() ? CookieSecurePolicy.SameAsRequest : CookieSecurePolicy.Always;
    options.ExpireTimeSpan = TimeSpan.FromHours(2);
    options.SlidingExpiration = true;
    options.LoginPath = "/auth/login";
    options.AccessDeniedPath = "/auth/access-denied";
});

var googleId = builder.Configuration["Authentication:Google:ClientId"];
var googleSecret = builder.Configuration["Authentication:Google:ClientSecret"];
var googleReady = !string.IsNullOrWhiteSpace(googleId) && !string.IsNullOrWhiteSpace(googleSecret);
if (googleReady)
{
    builder.Services.AddAuthentication().AddOpenIdConnect("Google", "Google", options =>
    {
        options.Authority = "https://accounts.google.com";
        options.ClientId = googleId!;
        options.ClientSecret = googleSecret!;
        options.ResponseType = "code";
        options.UsePkce = true;
        options.CallbackPath = "/signin-google";
        options.SignInScheme = IdentityConstants.ExternalScheme;
        options.Scope.Add("email");
        options.Scope.Add("profile");
        options.SaveTokens = false;
        options.GetClaimsFromUserInfoEndpoint = false; // email_verified comes from ID token
        options.Events.OnRemoteFailure = context =>
        {
            context.HandleResponse();
            context.Response.Redirect("/auth/login?googleError=1");
            return Task.CompletedTask;
        };
    });
}

builder.Services.AddHttpContextAccessor();
builder.Services.AddScoped<AuditService>();
builder.Services.AddScoped<IAppMailer, AppMailer>();
builder.Services.AddSingleton<CaptchaService>();
builder.Services.AddDistributedMemoryCache();
builder.Services.AddSession(options =>
{
    options.Cookie.Name = "SecureAccounts.CaptchaSession";
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
    options.Cookie.SameSite = SameSiteMode.Lax;
    options.Cookie.SecurePolicy = builder.Environment.IsDevelopment() ? CookieSecurePolicy.SameAsRequest : CookieSecurePolicy.Always;
    options.IdleTimeout = TimeSpan.FromMinutes(15);
});
builder.Services.AddControllersWithViews(options => options.Filters.Add(new AutoValidateAntiforgeryTokenAttribute()));

builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    void AddIpLimit(string name, int count, int minutes) => options.AddPolicy(name, context =>
        RateLimitPartition.GetFixedWindowLimiter(
            context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = count, Window = TimeSpan.FromMinutes(minutes), QueueLimit = 0, AutoReplenishment = true
            }));
    AddIpLimit("login", 30, 5);
    AddIpLimit("register", 15, 10);
    AddIpLimit("recover", 8, 15);
    AddIpLimit("captcha", 50, 5);
    AddIpLimit("twofactor", 20, 5);
});

var app = builder.Build();
if (!app.Environment.IsDevelopment())
{
    if (builder.Configuration["Mail:Mode"] == "Development")
        throw new InvalidOperationException("Development mail mode forbidden in Production; configure SMTP.");
    app.UseExceptionHandler("/home/error");
    app.UseHsts();
    app.UseHttpsRedirection();
}
else
{
    app.UseDeveloperExceptionPage();
}

// Security headers are applied to MVC and static responses.
app.Use(async (ctx, next) =>
{
    ctx.Response.OnStarting(() =>
    {
        ctx.Response.Headers["X-Content-Type-Options"] = "nosniff";
        ctx.Response.Headers["X-Frame-Options"] = "DENY";
        ctx.Response.Headers["Referrer-Policy"] = "strict-origin-when-cross-origin";
        ctx.Response.Headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'";
        return Task.CompletedTask;
    });
    await next();
});
app.UseStaticFiles();
app.UseRouting();
app.UseSession();
app.UseRateLimiter();
app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(name: "default", pattern: "{controller=Home}/{action=Index}/{id?}");

if (app.Environment.IsDevelopment() || args.Contains("--initialize-db"))
    await SeedData.InitializeAsync(app.Services, app.Environment.IsDevelopment(), args.Contains("--reset-demo-admin"));
else
{
    // The sample uses EnsureCreated; production deployment requires operator-approved schema setup.
    using var scope = app.Services.CreateScope();
    var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
    if (!await db.Database.CanConnectAsync())
        throw new InvalidOperationException("Database not initialized. Set up database before Production launch.");
}
app.Run();
