using Amazon.BedrockAgentCore;
using Microsoft.Agents.AI.DevUI;
using Microsoft.Agents.AI.Hosting;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.Extensions.AI;
using MyAgent;
using Scalar.AspNetCore;
using static MyAgent.Factory;

var builder = WebApplication.CreateBuilder(args);

builder.Services.Configure<ForwardedHeadersOptions>(options =>
{
    options.ForwardedHeaders =
      ForwardedHeaders.XForwardedFor |
      ForwardedHeaders.XForwardedHost |
      ForwardedHeaders.XForwardedProto;
    // Optionally clear KnownIPNetworks and KnownProxies to trust all (for cloud/proxy scenarios)
    options.KnownIPNetworks.Clear();
    options.KnownProxies.Clear();
});

builder.Services.AddOpenApi();

builder.Services.AddDevUI();
builder.Services.AddOpenAIResponses();
builder.Services.AddOpenAIConversations();

builder.Services.AddSingleton<IAmazonBedrockAgentCore>(sp =>
{
    var configuration = sp.GetRequiredService<IConfiguration>();
    return new AmazonBedrockAgentCoreClient(
        awsAccessKeyId: configuration["AWSBedrockAccessKeyId"],
        awsSecretAccessKey: configuration["AWSBedrockSecretAccessKey"],
        region: Amazon.RegionEndpoint.GetBySystemName(configuration["AWSBedrockRegion"]));
});

var openai = builder.AddAIAgent("openai", (sp, key) => CreateAgent(
    name: key,
    chatClient: Factory.OpenAI(sp.GetRequiredService<IConfiguration>(), sp),
    tools: GetTools(),
    services: sp));

var amazonbedrock = builder.AddAIAgent("amazonbedrock", (sp, key) => CreateAgent(
    name: key,
    chatClient: AmazonBedrock(sp.GetRequiredService<IConfiguration>(), sp),
    tools: GetTools(),
    services: sp));


var app = builder.Build();

app.UseForwardedHeaders();
app.UsePathBase("/my-agent");

app.MapOpenApi();
app.MapScalarApiReference();
app.MapDevUI();
app.MapOpenAIResponses();
app.MapOpenAIConversations();

app.Run();
