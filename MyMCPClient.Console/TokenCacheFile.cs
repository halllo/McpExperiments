using System.Text.Json;
using ModelContextProtocol.Authentication;

public class TokenCacheFile : ITokenCache
{
    private string _filePath;

    public TokenCacheFile(string filePath)
    {
        _filePath = filePath;
    }

    public async Task StoreTokenAsync(TokenContainer token, CancellationToken cancellationToken)
    {
        var json = JsonSerializer.Serialize(token);
        await File.WriteAllTextAsync(_filePath, json, cancellationToken);
    }

    public async Task<TokenContainer?> GetTokenAsync(CancellationToken cancellationToken)
    {
        var token = File.Exists(_filePath)
            ? JsonSerializer.Deserialize<TokenContainer>(await File.ReadAllTextAsync(_filePath, cancellationToken))
            : null;

        return token;
    }
}