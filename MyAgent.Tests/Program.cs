using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;

namespace MyAgent.Tests;

public static class Program
{
    public static IHost BuildHost() => CreateHostBuilder().Build();

    static IHostBuilder CreateHostBuilder() => Host.CreateDefaultBuilder()
        .ConfigureAppConfiguration(cfg =>
        {
            cfg.AddJsonFile("appsettings.local.json", optional: true);
            cfg.AddUserSecrets(typeof(Program).Assembly);
        })
        .ConfigureLogging(logging =>
        {
        })
        .ConfigureServices((ctx, services) =>
        {
            var config = ctx.Configuration;
        });
}
