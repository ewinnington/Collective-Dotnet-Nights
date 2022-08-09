using GordianKnotification;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;

var builder = WebApplication.CreateBuilder(args);

var app = builder.Build();

/*using (var scope = app.Services.CreateScope())
{
    var sampleService = scope.ServiceProvider.GetRequiredService<JwtTokenGenerator>();
    sampleService.DoSomething();
}*/

var jwtTokenGenerator = new JwtTokenGenerator("- _--_--_sdsd73_-- - _--_ - 23"); 

app.MapGet("/", () => "Hello World!");

//add a post endoint the receives a username and token and responds with a JWT token signed with a public/private key
app.MapPost("/authenticate", (AuthenticateInputDTO auth_input) =>
{
    return jwtTokenGenerator.generateJwtToken(new SystemUser(1, auth_input.username, auth_input.token));
});

// Receive the JWT token in the Authorization header and validate it
app.MapGet("/validate", ([FromHeader(Name = "Authorization")] string BearerJwtToken) =>
{
    if (BearerJwtToken is null)
        return Results.Unauthorized();

    String jwtToken = BearerJwtToken.Split(" ")[1];
    if (jwtTokenGenerator.validateJwtToken(jwtToken))
        return Results.Redirect("/");
    else
        return Results.Unauthorized();
});


app.Run();

record AuthenticateInputDTO(string username, string token);

