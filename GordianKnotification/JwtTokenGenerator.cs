using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace GordianKnotification
{
    public record SystemUser(int Id, string Username, string Token);
    
    public class JwtTokenGenerator
    {
        private string _secret;

        public JwtTokenGenerator(string secret)
        {
            _secret = secret;
        }

        public string generateJwtToken(SystemUser user)
        {
            // generate token that is valid for 7 days
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_secret);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[] { new Claim("id", user.Id.ToString()), new Claim("user", user.Username)}),
                Expires = DateTime.UtcNow.AddDays(7),
                IssuedAt = DateTime.UtcNow.AddMilliseconds(-5.0),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };
            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }

        public bool validateJwtToken(string token)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_secret);
            var principalClaims = tokenHandler.ValidateToken(token, new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(key),
                ValidateIssuer = false,
                ValidateAudience = false
            }, out _);

            if(principalClaims?.Identity?.IsAuthenticated == true)
            {
                return true;
            }
            else
            {
                return false;
            }
        }
    }
}
