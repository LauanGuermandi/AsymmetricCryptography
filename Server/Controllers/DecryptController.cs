using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using NetDevPack.Security.Jwt.Interfaces;
using Server.Models;
using System;
using System.Net;
using System.Threading.Tasks;

namespace Server.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class DecryptController : ControllerBase
    {
        private readonly ILogger<DecryptController> _logger;
        private readonly IJsonWebKeySetService _jsonWebKeySetService;

        public DecryptController(ILogger<DecryptController> logger, IJsonWebKeySetService jsonWebKeySetService)
        {
            _logger = logger;
            _jsonWebKeySetService = jsonWebKeySetService;
        }

        [HttpPost]
        public IActionResult GetResultData(EncryptedDataRequestDto encryptedData)
        {
            try
            {
                var handler = new JsonWebTokenHandler();
                var encryptingCredentials = _jsonWebKeySetService.GetCurrentEncryptingCredentials();
                var result = handler.ValidateToken(encryptedData.TokenJwe,
                    new TokenValidationParameters
                    {
                        ValidIssuer = "issuer",
                        ValidAudience = "audience",
                        RequireSignedTokens = false,
                        TokenDecryptionKey = encryptingCredentials.Key,
                    });

                if (!result.IsValid)
                    BadRequest();

                return Ok(result.Claims);
            }
            catch(Exception ex)
            {
                _logger.LogError(ex, "Erro inesperado.");
                return StatusCode((int)HttpStatusCode.InternalServerError, ex.Message);
            }
        }
    }
}
