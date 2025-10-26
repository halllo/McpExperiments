using System.Text.Json;
using ModelContextProtocol.Authentication;

public class TokenCacheFile : ITokenCache
{
    private string _filePath;

    public TokenCacheFile(string filePath)
    {
        _filePath = filePath;
    }

    public async ValueTask StoreTokensAsync(TokenContainer tokens, CancellationToken cancellationToken)
    {
        var json = JsonSerializer.Serialize(tokens);
        await File.WriteAllTextAsync(_filePath, json, cancellationToken);
    }

    public async ValueTask<TokenContainer?> GetTokensAsync(CancellationToken cancellationToken)
    {
        var token = File.Exists(_filePath)
            ? JsonSerializer.Deserialize<TokenContainer>(await File.ReadAllTextAsync(_filePath, cancellationToken))
            : null;

        return token;
    }
}