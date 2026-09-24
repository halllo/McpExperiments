using Amazon.BedrockAgentCore;
using Amazon.BedrockAgentCoreControl;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace MyAgent.Tests;

public static class Program
{
    public static IHost BuildHost() => CreateHostBuilder().Build();

    /// <summary>
    /// Host wired up the same way MyAgent's own Program.cs wires up its workflows, so tests
    /// exercise the real DI registration rather than a hand-built workflow.
    /// </summary>
    public static IHost BuildWorkflowHost()
    {
        var builder = Host.CreateApplicationBuilder();
        builder.Configuration.AddJsonFile("appsettings.local.json", optional: true);
        builder.Configuration.AddUserSecrets(typeof(Program).Assembly);
        builder.AddArchitectureCouncil();
        return builder.Build();
    }

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
            services.AddSingleton<IAmazonBedrockAgentCoreControl>(sp =>
                new AmazonBedrockAgentCoreControlClient(
                    awsAccessKeyId: config["AWSBedrockAccessKeyId"],
                    awsSecretAccessKey: config["AWSBedrockSecretAccessKey"],
                    region: Amazon.RegionEndpoint.GetBySystemName(config["AWSBedrockRegion"])));
            services.AddSingleton<AgentCoreMemory>();
        });
}
