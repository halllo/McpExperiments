using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.AI;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using ModelContextProtocol.Client;
using System.ClientModel;
using System.Net.Http.Headers;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddOpenApi();
builder.Services.AddHttpContextAccessor();

builder.Services.AddTransient<SetAccessToken>();
builder.Services.AddHttpClient("mcp").AddHttpMessageHandler<SetAccessToken>().AddAsKeyed();

builder.Services.AddScoped(sp => new SseClientTransport(new()
{
	Name = "Vibe MCP Server",
	Endpoint = new Uri("https://localhost:7296/"),
	TransportMode = HttpTransportMode.StreamableHttp,
}, sp.GetRequiredKeyedService<HttpClient>("mcp")));

builder.Services.AddScoped<IChatClient>(sp => new FunctionInvokingChatClient(new OpenAI.Chat.ChatClient("gemma-3-27b-it", new ApiKeyCredential("my_key"), new OpenAI.OpenAIClientOptions()
{
	Endpoint = new Uri("http://127.0.0.1:1234/v1"),//lm studio
}).AsIChatClient(), sp.GetRequiredService<ILoggerFactory>(), sp));

builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
	.AddCookie(options =>
	{
		options.Cookie.Name = $"MyMcpClient.Web";
		options.Cookie.SameSite = SameSiteMode.Strict;
		options.ForwardChallenge = OpenIdConnectDefaults.AuthenticationScheme;
		options.Events.OnRedirectToAccessDenied = new Func<RedirectContext<CookieAuthenticationOptions>, Task>(context =>
		{
			context.Response.StatusCode = StatusCodes.Status403Forbidden;
			return context.Response.CompleteAsync();
		});
	})
	.AddOpenIdConnect(OpenIdConnectDefaults.AuthenticationScheme, o =>
	{
		o.Authority = "https://localhost:5001";
		o.ClientId = "mcp_server";
		o.ClientSecret = "secret";
		o.ResponseType = OpenIdConnectResponseType.Code;
		o.Scope.Add("openid");
		o.Scope.Add("profile");
		o.Scope.Add("verification");
		o.Scope.Add("notes");
		o.Scope.Add("admin");
		o.SaveTokens = true;
		o.GetClaimsFromUserInfoEndpoint = true;
	})
	;

builder.Services.AddAuthorization();



var app = builder.Build();
app.MapOpenApi();
app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/account", (HttpContext context) => Results.Ok(context.User.Claims.Select(c => new { c.Type, c.Value }))).RequireAuthorization();

app.MapGet("/tools", async (SseClientTransport sse) =>
{
	await using var mcpClient = await McpClientFactory.CreateAsync(sse);
	var tools = await mcpClient.ListToolsAsync();
	return Results.Ok(tools.Select(t => new { t.Name, t.Description, t.JsonSchema }));
}).RequireAuthorization();

app.MapGet("/invoke", async (SseClientTransport sse, IChatClient chatClient) =>
{
	await using var mcpClient = await McpClientFactory.CreateAsync(sse);
	var tools = await mcpClient.ListToolsAsync();

	IList<ChatMessage> messages =
	[
		new(ChatRole.System, "You are a helpful assistant delivering time and vibes in one short sentence."),
		new(ChatRole.User, "What is the current (CET) time in Karlsruhe, Germany? And what is the vibe there?")
	];

	var response = await chatClient.GetResponseAsync(messages, new ChatOptions { Tools = [.. tools] });
	return Results.Ok(response.Text);
});

app.Run();


public class SetAccessToken : DelegatingHandler
{
	private readonly IHttpContextAccessor httpContextAccessor;

	public SetAccessToken(IHttpContextAccessor httpContextAccessor)
	{
		this.httpContextAccessor = httpContextAccessor;
	}

	protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
	{
		var http = this.httpContextAccessor.HttpContext ?? throw new InvalidOperationException("Authentication needed");
		var accessToken = await http.GetTokenAsync(OpenIdConnectParameterNames.AccessToken);
		request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
		return await base.SendAsync(request, cancellationToken);
	}
}