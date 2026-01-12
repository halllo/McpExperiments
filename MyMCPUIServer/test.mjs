import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

async function waitForServerReady(url, { timeoutMs = 8000 } = {}) {
	const deadline = Date.now() + timeoutMs;
	while (Date.now() < deadline) {
		try {
			const res = await fetch(url, { method: "GET" });
			if (res.ok) return;
		} catch {
			// ignore connection errors while the server boots
		}
		await sleep(50);
	}
	throw new Error(`Timed out waiting for server readiness at ${url}`);
}

async function withServer(fn) {
	const cwd = __dirname;
	const serverUrl = "http://127.0.0.1:3000/mcp";
	const healthUrl = "http://127.0.0.1:3000/healthz";
	const entrypoint = path.join(__dirname, "index.mjs");
	const proc = spawn(process.execPath, [entrypoint], {
		cwd,
		stdio: ["ignore", "ignore", "pipe"],
		env: { ...process.env }
	});

	let stderr = "";
	proc.stderr?.on("data", chunk => {
		stderr += chunk.toString("utf8");
	});

	try {
		await waitForServerReady(healthUrl);
		return await fn(serverUrl);
	} catch (err) {
		throw new Error(`${err instanceof Error ? err.message : String(err)}\n\nServer stderr:\n${stderr}`);
	} finally {
		proc.kill("SIGINT");
		await new Promise(resolve => proc.once("exit", resolve));
	}
}

test("MCP server accepts StreamableHTTP client and exposes say-hello tool", async () => {
	await withServer(async serverUrl => {
		const client = new Client({ name: "smoke-test-client", version: "1.0.0" }, { capabilities: {} });
		const transport = new StreamableHTTPClientTransport(new URL(serverUrl));

		try {
			await client.connect(transport);

			const tools = await client.listTools();
			assert.ok(Array.isArray(tools.tools));
			assert.ok(tools.tools.some(t => t.name === "say-hello"));

			const toolResult = await client.callTool(
			{
				name: "say-hello",
				arguments: { name: "Manuel" }
			});
			assert.ok(Array.isArray(toolResult.content));
			assert.ok(toolResult.content[0].text.includes("Hello Manuel!"), "Expected say-hello tool to greet provided name");
		} finally {
			await transport.close();
		}
	});
});
