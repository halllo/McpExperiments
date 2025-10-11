using System.Text.Json;
using ModelContextProtocol.Authentication;

public class TokenCacheFile : ITokenCache
{
    private string _filePath;

    public TokenCacheFile(string filePath)
    {
        _filePath = filePath;
    }

    public async ValueTask StoreTokenAsync(TokenContainerCacheable token, CancellationToken cancellationToken)
    {
        var json = JsonSerializer.Serialize(token);
        await File.WriteAllTextAsync(_filePath, json, cancellationToken);
    }

    public async ValueTask<TokenContainerCacheable?> GetTokenAsync(CancellationToken cancellationToken)
    {
        var token = File.Exists(_filePath)
            ? JsonSerializer.Deserialize<TokenContainerCacheable>(await File.ReadAllTextAsync(_filePath, cancellationToken))
            : null;

        return token;
    }
}