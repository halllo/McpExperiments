using Amazon.BedrockAgentCore;
using Amazon.BedrockAgentCore.Model;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Serilog;
using ILogger = Microsoft.Extensions.Logging.ILogger;

var host = CreateHostBuilder().Build();
using (var serviceScope = host.Services.CreateScope())
{
	var serviceProvider = serviceScope.ServiceProvider;
	try
	{
		var logger = serviceProvider.GetRequiredService<ILogger<Program>>();
		logger.LogInformation("Starting Code Interpreter...");

		var agentCore = serviceProvider.GetRequiredService<IAmazonBedrockAgentCore>();
		
		var result = await ExecuteCode(agentCore, logger,
            pythonCode: """
                        import math
                        result = [math.factorial(i) for i in range(10)]
                        print(result)
                        """);
		
		return 0;
	}
	catch (Exception e)
	{
		var logger = serviceProvider.GetRequiredService<ILogger<Program>>();
		logger.LogError(e, "Something went wrong.");
		return 1;
	}
}

static IHostBuilder CreateHostBuilder()
{
	return Host.CreateDefaultBuilder()
		.ConfigureAppConfiguration(cfg =>
		{
            cfg.AddUserSecrets<Program>(optional: true);
			cfg.AddJsonFile("appsettings.local.json", optional: true);
		})
		.UseSerilog((ctx, cfg) =>
		{
			cfg.ReadFrom.Configuration(ctx.Configuration);
		})
		.ConfigureServices((ctx, services) =>
		{
			services.AddSingleton<IAmazonBedrockAgentCore>(sp =>
			{
				var configuration = sp.GetRequiredService<IConfiguration>();
				return new AmazonBedrockAgentCoreClient(
					awsAccessKeyId: configuration["AWSBedrockAccessKeyId"],
					awsSecretAccessKey: configuration["AWSBedrockSecretAccessKey"],
					region: Amazon.RegionEndpoint.GetBySystemName(configuration["AWSBedrockRegion"]));
			});
		});
}





static async Task<string> ExecuteCode(IAmazonBedrockAgentCore agentCore, ILogger logger, string pythonCode)
{
    var codeInterpreterId = "aws.codeinterpreter.v1";
    var session = await agentCore.StartCodeInterpreterSessionAsync(new StartCodeInterpreterSessionRequest
    {
        CodeInterpreterIdentifier = codeInterpreterId,
        Name = "TestSession1",
        SessionTimeoutSeconds = 900 // 15 minutes
    });
    var sessionId = session.SessionId;
    logger.LogInformation("Started code interpreter session with ID: {SessionId}", sessionId);

    try
    {
        var response = await agentCore.InvokeCodeInterpreterAsync(new InvokeCodeInterpreterRequest
        {
            CodeInterpreterIdentifier = codeInterpreterId,
            SessionId = sessionId,
            Name = ToolName.ExecuteCode,
            Arguments = new ToolArguments
            {
                Language = "python",
                Code = pythonCode,
            }
        });

        var result = string.Empty;
        await foreach (var message in response.Stream)
        {
            if (message is CodeInterpreterResult resultMessage)
            {
                logger.LogInformation("Code interpreter result");
                foreach (var content in resultMessage.Content)
                {
                    logger.LogInformation("Output type: {Type}, content: {Content}", content.Type, content.Text);
                    result += content.Text;
                }
            }
            else
            {
                var type = message.GetType().Name;
                logger.LogInformation("Received message from code interpreter: {Content}", type);
            }
        }
        return result;
    }
    catch (Exception ex)
    {
        logger.LogError(ex, "Error invoking code interpreter");
        throw;
    }
    finally
    {
        await agentCore.StopCodeInterpreterSessionAsync(new StopCodeInterpreterSessionRequest
        {
            CodeInterpreterIdentifier = codeInterpreterId,
            SessionId = sessionId
        });
        logger.LogInformation("Ended code interpreter session with ID: {SessionId}", sessionId);
    }
}
