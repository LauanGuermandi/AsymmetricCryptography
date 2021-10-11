using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;

namespace Client
{
    class Program
    {
        private static readonly HttpClient _client = new();
        static async Task Main(string[] _)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = await Loadkey();

            // Recomendação no NIS e da Microsoft
            var enc = new EncryptingCredentials(key, SecurityAlgorithms.RsaOAEP, SecurityAlgorithms.Aes128CbcHmacSha256);

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Issuer = "issuer",
                Audience = "audience",
                Subject = new ClaimsIdentity(new Claim[]
                {
                    new Claim("card_number", "4000-0000-0000-0002"),
                }),
                EncryptingCredentials = enc
            };

            var tokenCreated = tokenHandler.CreateToken(tokenDescriptor);
            var tokenJwe = tokenHandler.WriteToken(tokenCreated);
            Console.WriteLine(tokenJwe);
        }

        private static async Task<SecurityKey> Loadkey()
        {
            var publicKey = await _client.GetStringAsync("http://localhost:5000/jwks_e");
            var key = JsonWebKeySet.Create(publicKey);
            return key.Keys.FirstOrDefault();
        }
    }
}
