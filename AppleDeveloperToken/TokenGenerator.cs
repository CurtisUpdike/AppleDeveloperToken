using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;

namespace AppleDeveloperToken;

public class TokenGenerator
{
    private static readonly JwtSecurityTokenHandler _tokenHandler = new();
    private readonly AppleAccount _account;
    private int _secondsValid;
    public int SecondsValid
    {
        get { return _secondsValid; }
        set
        {
            ValidateTime(value);
            _secondsValid = value;
        }
    }

    public TokenGenerator(string privateKey, string teamId, string keyId, int secondsValid = 15777000)
    {
        ValidateTime(secondsValid);
        _account = new(teamId, keyId, FormatKey(privateKey));
        _secondsValid = secondsValid;
    }

    public string Generate()
    {
        return GenerateToken(_account, new TimeSpan(SecondsValid));
    }

    public string Generate(int secondsValid)
    {
        ValidateTime(secondsValid);
        return GenerateToken(_account, new TimeSpan(secondsValid));

    }

    public string Generate(TimeSpan timeValid)
    {
        ValidateTime(timeValid.Seconds);
        return GenerateToken(_account, timeValid);
    }

    private static string GenerateToken(AppleAccount account, TimeSpan timeValid)
    {
        var now = DateTime.UtcNow;
        var algorithm = CreateAlgorithm(account.PrivateKey);
        var signingCredentials = CreateSigningCredentials(account.KeyId, algorithm);
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Issuer = account.TeamId,
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

    private static void ValidateTime(int seconds)
    {
        if (seconds > 15777000)
        {
            throw new ArgumentException("Must be less than 15777000 seconds (6 months).");
        }
    }

    private static string FormatKey(string key)
    {
        return key.Replace("-----BEGIN PRIVATE KEY-----", "")
            .Replace("-----END PRIVATE KEY-----", "")
            .Replace("\n", "")
            .Replace("\r", "");
    }
}
