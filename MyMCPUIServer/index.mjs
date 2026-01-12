import { createMcpExpressApp } from '@modelcontextprotocol/sdk/server/express.js';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import * as z from 'zod/v4';
import { createUIResource } from '@mcp-ui/server';
import { RESOURCE_URI_META_KEY } from "@modelcontextprotocol/ext-apps";

import fs from 'node:fs';

const HOST = process.env.HOST ?? "127.0.0.1";
const PORT = Number.parseInt(process.env.PORT ?? "3000", 10);

const getServer = () => {
    const server = new McpServer({
        name: 'my-stateless-streamable-http-server',
        version: '1.0.0'
    });


    // MCP-UI embedded resource
    server.registerTool('say-hello',
        {
            description: 'Says hello to the user.',
            inputSchema: z.object({
                name: z.string().describe('Name of the user to greet').default('World')
            })
        },
        async ({ name }) => {
            return {
                content: [
                    {
                        type: 'text',
                        text: `Hello ${name}!`
                    },
                    {
                        type: 'resource',
                        resource: {
                            uri: 'ui://my-tool/dashboard',
                            mimeType: 'text/html',
                            text: `<h1>Hello ${name}</h1>`,
                        }
                    }
                ]
            };
        });


    // MCP Apps with MCP-UI Adapter Example (https://github.com/MCP-UI-Org/mcp-ui/blob/main/examples/mcp-apps-demo/src/index.ts)
    const weatherUiResourceUri = 'ui://weather.html';
    const weatherHtml = fs.readFileSync(new URL('./weather.html', import.meta.url), 'utf8');
    const weatherUiResource = createUIResource({
        uri: weatherUiResourceUri,
        encoding: 'text',
        content: {
            type: 'rawHtml',
            htmlString: weatherHtml,
        },
        adapters: {
            mcpApps: {
                enabled: true,
            },
        },
    });

    server.registerResource(
        weatherUiResource.resource.uri,
        weatherUiResource.resource.uri,
        {},
        async () => ({
            contents: [weatherUiResource.resource],
        }),
    );

    server.registerTool('weather_dashboard',
        {
            description: 'Interactive weather dashboard widget',
            inputSchema: {
                location: z.string().describe('City name'),
            },
            _meta: {
                [RESOURCE_URI_META_KEY]: weatherUiResource.resource.uri,
            },
        },
        async ({ location }) => {
            return {
                content: [{ type: 'text', text: `Weather dashboard for ${location}` }],
            };
        },
    );


    // MCP Apps Example (https://dev.to/bd_perez/create-your-first-mcp-app-2c65)
    const flightUiResourceUri = 'ui://flight.html';
    server.registerResource(
        flightUiResourceUri,
        flightUiResourceUri,
        {},
        async () => {
            const html = fs.readFileSync(new URL('./flight.html', import.meta.url), 'utf8');
            return {
                contents: [
                    {
                        uri: flightUiResourceUri,
                        mimeType: 'text/html;profile=mcp-app',
                        text: html,
                    },
                ],
            };
        }
    );

    server.registerTool('get-flights',
        {
            description: 'retrieves flight arrivals for a given airport code',
            inputSchema: {
                code: z.string().describe("The ICAO airport code, e.g. 'KJFK'"),
            },
            _meta: { [RESOURCE_URI_META_KEY]: flightUiResourceUri },
        },
        async ({ code }) => {
            const mockFlights = [
                { flightNumber: 'AA100', airline: 'American Airlines' },
                { flightNumber: 'DL200', airline: 'Delta Airlines' },
                { flightNumber: 'UA300', airline: 'United Airlines' },
            ];
            return {
                content: [{ type: 'text', text: JSON.stringify(mockFlights, null, 2) }],
                structuredContent: { flights: mockFlights },
            };
        });


    return server;
};


const app = createMcpExpressApp({ host: HOST });

app.get('/healthz', (req, res) => {
    res.status(200).send('ok');
});

app
    .route('/mcp')
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
        console.error('Failed to start server:', error);
        process.exit(1);
    }
    console.log(`MCP Stateless Streamable HTTP Server listening on http://${HOST}:${PORT}`);
});

process.on('SIGINT', async () => {
    console.log('Shutting down server...');
    httpServer.close(() => process.exit(0));
});

process.on('SIGTERM', async () => {
    console.log('Shutting down server...');
    httpServer.close(() => process.exit(0));
});
