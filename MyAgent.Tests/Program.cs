using Amazon.BedrockAgentCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
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
            services.AddSingleton<IAmazonBedrockAgentCore>(sp =>
                new AmazonBedrockAgentCoreClient(
                    awsAccessKeyId: config["AWSBedrockAccessKeyId"],
                    awsSecretAccessKey: config["AWSBedrockSecretAccessKey"],
                    region: Amazon.RegionEndpoint.GetBySystemName(config["AWSBedrockRegion"])));
            services.AddSingleton<CodeInterpreter>();
        });
}
