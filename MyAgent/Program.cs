using Amazon.BedrockRuntime;
using Microsoft.Agents.AI;
using Microsoft.Agents.AI.DevUI;
using Microsoft.Agents.AI.Hosting;
using Microsoft.Extensions.AI;
using OpenAI;
using Scalar.AspNetCore;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddOpenApi();

builder.Services.AddDevUI();
builder.Services.AddOpenAIResponses();
builder.Services.AddOpenAIConversations();

var openai = builder.AddAIAgent("openai", (sp , key) => CreateAgent(
    name: key,
    chatClient: OpenAI(sp.GetRequiredService<IConfiguration>(), sp),
    tools: Array.Empty<AIFunction>(),
    services: sp));
    
var amazonbedrock = builder.AddAIAgent("amazonbedrock", (sp , key) => CreateAgent(
    name: key,
    chatClient: AmazonBedrock(sp.GetRequiredService<IConfiguration>(), sp),
    tools: Array.Empty<AIFunction>(),
    services: sp));

var app = builder.Build();

app.MapOpenApi();
app.MapScalarApiReference();
app.MapDevUI();
app.MapOpenAIResponses();
app.MapOpenAIConversations();

app.Run();


static IChatClient OpenAI(IConfiguration configuration, IServiceProvider services)
{
    var applicationName = services.GetRequiredService<IHostEnvironment>().ApplicationName;
    var openaiApiKey = configuration["OPENAI_API_KEY"] ?? throw new InvalidOperationException("OPENAI_API_KEY is not set.");
    return new OpenAIClient(openaiApiKey)
        .GetChatClient("gpt-4o")
        .AsIChatClient()
        .AsBuilder()
        .UseOpenTelemetry(sourceName: applicationName, configure: c => c.EnableSensitiveData = true)
        .Build()
        ;
}

static IChatClient AmazonBedrock(IConfiguration configuration, IServiceProvider services)
{
    var applicationName = services.GetRequiredService<IHostEnvironment>().ApplicationName;
    var runtime = new AmazonBedrockRuntimeClient(
        awsAccessKeyId: configuration["AWSBedrockAccessKeyId"],
        awsSecretAccessKey: configuration["AWSBedrockSecretAccessKey"],
        region: Amazon.RegionEndpoint.GetBySystemName(configuration["AWSBedrockRegion"]));

    return runtime
        .AsIChatClient(defaultModelId:
            "eu.anthropic.claude-sonnet-4-6"
        )
        .AsBuilder()
        .UseOpenTelemetry(sourceName: applicationName, configure: c => c.EnableSensitiveData = true)
        .Build(services)
        ;
}

static AIAgent CreateAgent(string name, IChatClient chatClient, AIFunction[] tools, IServiceProvider services)
{
    var applicationName = services.GetRequiredService<IHostEnvironment>().ApplicationName;
    return chatClient
        .AsAIAgent(
            name: name,
            tools: tools,
            services: services)
        .AsBuilder()
        .UseOpenTelemetry(sourceName: applicationName, configure: c => c.EnableSensitiveData = true)
        .Build(services);
}