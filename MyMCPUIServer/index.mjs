import { createMcpExpressApp } from "@modelcontextprotocol/sdk/server/express.js";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import * as z from "zod/v4";

const HOST = process.env.HOST ?? "127.0.0.1";
const PORT = Number.parseInt(process.env.PORT ?? "3000", 10);


const getServer = () => {
    const server = new McpServer({
        name: "my-stateless-streamable-http-server",
        version: "1.0.0"
    });

    server.registerTool("say-hello",
        {
            description: "Says hello to the user.",
            inputSchema: z.object({
                name: z.string().describe("Name of the user to greet").default("World")
            })
        },
        async ({ name }) => {
            return {
                content: [
                    {
                        type: "text",
                        text: `Hello ${name}!`
                    }
                ]
            };
        });

    return server;
};

const app = createMcpExpressApp({ host: HOST });
app
    .route("/mcp")
    .post(async (req, res) => {
        try {
            const server = getServer();
            const transport = new StreamableHTTPServerTransport({
                sessionIdGenerator: undefined
            });
            await server.connect(transport);
            await transport.handleRequest(req, res, req.body);
        } catch (error) {
            console.error("Error handling MCP request:", error);
            if (!res.headersSent) {
                res.status(500).json({
                    jsonrpc: "2.0",
                    error: {
                        code: -32603,
                        message: "Internal server error"
                    },
                    id: null
                });
            }
        }
    })
    .all((_req, res) => {
        res.status(405).json({
            jsonrpc: "2.0",
            error: {
                code: -32000,
                message: "Method not allowed."
            },
            id: null
        });
    });

const httpServer = app.listen(PORT, HOST, error => {
    if (error) {
        console.error("Failed to start server:", error);
        process.exit(1);
    }
    console.log(`MCP Stateless Streamable HTTP Server listening on http://${HOST}:${PORT}`);
});

process.on("SIGINT", async () => {
    console.log("Shutting down server...");
    httpServer.close(() => process.exit(0));
});

process.on("SIGTERM", async () => {
    console.log("Shutting down server...");
    httpServer.close(() => process.exit(0));
});
