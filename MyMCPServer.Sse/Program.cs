var builder = WebApplication.CreateBuilder(args);
builder.Services.AddMcpServer().WithToolsFromAssembly();
var app = builder.Build();

app.MapGet("/", () => "Hello World!");
app.MapMcp();

app.Run();
