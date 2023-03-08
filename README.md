
Generate a developer token needed to make requests to Apple Music API.

## Getting Started

You will need an [Apple Developer Account](https://developer.apple.com/) to obtain:
- Private Key (from .p8)
- 10-character Team ID
- 10-character Key ID

See [Apple's documentation](https://developer.apple.com/documentation/applemusicapi/generating_developer_tokens) for more info.

## How to Use

```csharp
using AppleDeveloperToken;

var tokenGenerator = new TokenGenerator(privateKey, teamId, keyId);
var timeValid = TimeSpan.FromDays(1);
var token = tokenGenerator.Generate(timeValid);
```
