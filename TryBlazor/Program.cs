using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Web;
using TryBlazor.Data;
using TryBlazor.Security;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddRazorPages();
builder.Services.AddServerSideBlazor();
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.LoginPath = "/login";
        options.Cookie.Name = ".AspNetCore.TryBlazor.Auth";
        options.Cookie.HttpOnly = true;
        options.Cookie.SameSite = SameSiteMode.Lax;
        options.ExpireTimeSpan = TimeSpan.FromHours(8);
        options.SlidingExpiration = true;
    });
builder.Services.AddAuthorization(options =>
{
    options.FallbackPolicy = new AuthorizationPolicyBuilder()
        .RequireAuthenticatedUser()
        .Build();
    options.AddPolicy(RolePolicies.BeoAccess, policy =>
        policy.RequireAssertion(context => RolePolicies.HasBeoAccess(context.User)));
    options.AddPolicy(RolePolicies.StandardAccess, policy =>
        policy.RequireAssertion(context => RolePolicies.HasMinimumRole(context.User, 2)));
    options.AddPolicy(RolePolicies.UserManagement, policy =>
        policy.RequireAssertion(context => RolePolicies.HasMinimumRole(context.User, 4)));
});
builder.Services.AddSingleton<WeatherForecastService>();
builder.Services.AddScoped<UserService>();
builder.Services.AddScoped<BeoLineItemService>();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
}


app.UseStaticFiles();

app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();

app.MapRazorPages();
app.MapBlazorHub().RequireAuthorization();
app.MapFallbackToPage("/_Host").RequireAuthorization();

app.Run();
