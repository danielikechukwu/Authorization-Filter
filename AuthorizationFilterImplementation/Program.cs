using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Mvc.Authorization;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Read the JWT secret key from the appsettings.json configuration file.
// This key will be used to sign and validate JWT tokens.
var jwtSecretKey = builder.Configuration.GetSection("JwtSetting");
var secretKey = jwtSecretKey.GetValue<string>("SecretKey") ?? "8b1e5ddde0ad708f55df7a0517128980a21371d6839b87c9001779c6";

// Register MVC controllers with the application.
// Also, configure JSON options to keep property names as defined in the C# models.
builder.Services.AddControllers()
    .AddJsonOptions(options =>
    {
        // Disable camelCase in JSON output, preserve property names as defined in C# classes
        options.JsonSerializerOptions.PropertyNamingPolicy = null; // Keep property names as defined in C# models

        //Apply authorize filter globally
        // options.Filters.Add(new AuthorizeFilter());
    });

// Register Authentication with JWT Bearer scheme
builder.Services.AddAuthentication(options =>
{
    // These two options set JWT Bearer as the default scheme for authentication and challenge.
    // This means the middleware will look for JWT tokens in incoming requests by default.

    // Set the default scheme used for authentication — this means how the app will try to authenticate incoming requests
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;

    // Set the default challenge scheme — this is how the app will challenge unauthorized requests
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
    .AddJwtBearer(options =>
    {
        // Configure parameters for validating incoming JWT tokens
        options.TokenValidationParameters = new TokenValidationParameters
        {

            // Do NOT validate the issuer (the token's "iss" claim)
            ValidateIssuer = false,

            // Do NOT validate the audience (the token's "aud" claim)
            ValidateAudience = false,

            // Ensure the token's signature matches the signing key (to verify token integrity)
            ValidateIssuerSigningKey = true,

            // The key used to sign tokens — must match the key used to generate tokens
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey)) // Use a symmetric key from configuration for token validation.

        };
    });

// Define a policy that requires authenticated users
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("AdminAndManager", policy =>
        policy.RequireRole("Admin")    // must have Admin
              .RequireRole("Manager")  // AND must also have Manager
    );
});

// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo { Title = "Authorization Filter", Version = "v2" });

    // Add Jwt Authentication support
    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Name = "Authorization",
        Type = SecuritySchemeType.ApiKey,
        Scheme = "Bearer",
        BearerFormat = "JWT",
        In = ParameterLocation.Header,
        Description = "Enter 'Bearer' [space] and then your valid token.\n\nExample: \"Bearer eyJhbGciOiJI...\""
    });

    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            new string[] {}
        }
    });

});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

// Add authentication middleware to validate JWT tokens in incoming requests.
app.UseAuthentication();  // MUST come before UseAuthorization

// Add authorization middleware to check user permissions for accessing resources.
app.UseAuthorization();

app.MapControllers();

app.Run();
