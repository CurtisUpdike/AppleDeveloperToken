using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;

namespace AppleDeveloperToken;

public class TokenGenerator
{
    private static readonly JwtSecurityTokenHandler _tokenHandler = new();
    private readonly string _privateKey;
    private readonly string _teamId;
    private readonly string _keyId;
    private readonly TimeSpan _timeValid;

    public TokenGenerator(string privateKey, string teamId, string keyId, int secondsValid = 15777000)
    {
        if (secondsValid > 15777000)
        {
            throw new ArgumentException("Must be less than 15777000 seconds (6 months).");
        }

        _privateKey = FormatKey(privateKey);
        _teamId = teamId;
        _keyId = keyId;
        _timeValid = new TimeSpan(secondsValid);
    }

    private string Generate()
    {
        return GenerateToken(_privateKey, _teamId, _keyId, _timeValid);
    }

    public string Generate(TimeSpan timeValid)
    {
        if (timeValid.TotalSeconds > 15777000)
        {
            throw new ArgumentException("TimeSpan must be less than 15777000 seconds (6 months).");
        }

        return GenerateToken(_privateKey, _teamId, _keyId, timeValid);
    }

    private static string GenerateToken(string privateKey, string teamId, string keyId, TimeSpan timeValid)
    {
        var now = DateTime.UtcNow;
        var algorithm = CreateAlgorithm(privateKey);
        var signingCredentials = CreateSigningCredentials(keyId, algorithm);
        var tokenDescriptor = new SecurityTokenDescriptor()
        {
            Issuer = teamId,
            IssuedAt = now,
            NotBefore = now,
            Expires = now.Add(timeValid),
            SigningCredentials = signingCredentials
        };

        var token = _tokenHandler.CreateJwtSecurityToken(tokenDescriptor);
        return _tokenHandler.WriteToken(token);
    }

    private static ECDsa CreateAlgorithm(string key)
    {
        var algorithm = ECDsa.Create();
        algorithm.ImportPkcs8PrivateKey(Convert.FromBase64String(key), out _);
        return algorithm;
    }

    private static SigningCredentials CreateSigningCredentials(string keyId, ECDsa algorithm)
    {
        var key = new ECDsaSecurityKey(algorithm) { KeyId = keyId };
        return new SigningCredentials(key, SecurityAlgorithms.EcdsaSha256);
    }

    private static string FormatKey(string key)
    {
        return key.Replace("-----BEGIN PRIVATE KEY-----", "")
            .Replace("-----END PRIVATE KEY-----", "")
            .Replace("\n", "")
            .Replace("\r", "");
    }
}
