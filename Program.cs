using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JWT_ConsoleApp
{
    internal class Program
    {
        private static readonly string secretKey = "my secret key for generate a json web token JWT";
        private static readonly string issuer = "huy";
        private static readonly string audience = "huy's friends";
        private static readonly string name = "huyho";
        private static readonly int expires = 15;
        static void Main(string[] args)
        {
            
            var token = CreateToken();
            Console.WriteLine(token);

            var valid = ValidateToken(token);

            Console.ReadLine();
        }
        
        public static string CreateToken()
        {
            List<Claim> claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name,name),
                new Claim("Platform", ".NET"),
                new Claim("Language", "C#")
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey));

            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);

            var token = new JwtSecurityToken(
                claims: claims,
                issuer: issuer,
                audience: audience,
                expires: DateTime.Now.AddMinutes(expires),
                signingCredentials: creds);

            var jwt = new JwtSecurityTokenHandler().WriteToken(token);

            return jwt;
        }
        public static bool ValidateToken(string token)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(secretKey);
            try
            {
                tokenHandler.ValidateToken(token, new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(key),
                    ValidateIssuer = true,
                    ValidIssuer = issuer,

                    ValidateAudience = true,
                    ValidAudience = audience,
                    // set clockskew to zero so tokens expire exactly at token expiration time (instead of 5 minutes later)
                    ClockSkew = TimeSpan.Zero
                }, out SecurityToken validatedToken);

                var jwtToken = (JwtSecurityToken)validatedToken;
                var payload = jwtToken.Payload;
                foreach (var item in payload)
                {
                    if (!string.IsNullOrEmpty(item.Key))
                    {
                        Console.WriteLine($"\n{item.Key}: {item.Value}");
                    }
                }


                return true;
            }
            catch (Exception ex)
            {
                return false;
            }
        }

    }
}
