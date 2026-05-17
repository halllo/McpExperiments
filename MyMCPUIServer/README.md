# MCP Apps via AG-UI

## Environment

There is an experimental MCP server running at <http://localhost:3001/mcp>. It hosts the `get_time` MCP App.

There is also an experimental MCP host running at <http://localhost:3000/api/copilotkit> and has connected the experimental MCP server. It uses the AG-UI protocol for communication with the browser frontend. The MCP App can be used through the AG-UI protocol.

## Plan

I plan to replace the experimental MCP host with another MCP host. Both support AG-UI. I want you to explore the behavior of the working MCP host at <http://localhost:3000/api/copilotkit>. I am primarily interested in how it deals with the MCP app via the AG-UI protocol.
Please derive some conformance tests, so that I can make sure another MCP host behaves in the same way and can use the MCP apps via AG-UI in the same way. Run the tests to make sure the tests pass for a working MCP host.

You must only interact with the MCP host. Send it POST requests (the different messages can be read here: <https://docs.ag-ui.com/sdk/js/core/types>) and inspect the SSE response stream (the different response events can be read here: <https://docs.ag-ui.com/sdk/js/core/events>).

---

## Findings

### MCP Server (`http://localhost:3001/mcp`)

The server is treated as a black box for this analysis. From host-observable behavior, it exposes an MCP App tool named `get-time` and an app resource at `ui://get-time/mcp-app.html`.

### MCP Host (`http://localhost:3000/api/copilotkit`)

The host is a CopilotKit-based AG-UI runtime. It connects to the MCP server and exposes the MCP App to browser frontends via the AG-UI SSE protocol.

---

### HTTP Request Format

The endpoint does **not** accept a bare `RunAgentInput` body. It requires a CopilotKit envelope:

```json
{
  "method": "agent/run",
  "params": { "agentId": "default" },
  "body": {
    "threadId": "<uuid>",
    "runId": "<uuid>",
    "messages": [
      { "id": "<uuid>", "role": "user", "content": "What time is it?" }
    ],
    "tools": [],
    "context": [],
    "state": {},
    "forwardedProps": {}
  }
}
```

**Required HTTP headers:**
```
Content-Type: application/json
Accept: text/event-stream
```

Without the `method` field the server responds with:
```json
{"error":"invalid_request","message":"Missing method field"}
```

With an unsupported method value it responds with:
```json
{"error":"invalid_request","message":"Unsupported method '<value>'"}
```

---

### SSE Response Format

Each event is delivered as a line:
```
data: <json>\n\n
```

Events are newline-delimited JSON objects with a `type` discriminator. The stream ends when the TCP connection closes (no explicit `[DONE]` sentinel observed).

---

### Observed Event Sequences

#### Tool invocation (e.g. "What time is it?")

```
RUN_STARTED
TOOL_CALL_START
TOOL_CALL_ARGS
TOOL_CALL_END
TOOL_CALL_RESULT
ACTIVITY_SNAPSHOT
RUN_FINISHED
```

Full example (captured live):

```jsonc
// 1. Run lifecycle opens
{"type":"RUN_STARTED","threadId":"probe-thread-1","runId":"probe-run-1",
 "input":{"threadId":"probe-thread-1","runId":"probe-run-1","state":{},"messages":[...],"tools":[],"context":[],"forwardedProps":{}}}

// 2. Tool call starts — note parentMessageId links to the assistant turn
{"type":"TOOL_CALL_START","parentMessageId":"73bd54d7-...","toolCallId":"call_bCRM...","toolCallName":"get-time"}

// 3. Tool arguments streamed as a JSON delta (empty object for get-time)
{"type":"TOOL_CALL_ARGS","toolCallId":"call_bCRM...","delta":"{}"}

// 4. Argument stream closes
{"type":"TOOL_CALL_END","toolCallId":"call_bCRM..."}

// 5. MCP tool result — content is a plain string (the raw tool output)
{"type":"TOOL_CALL_RESULT","messageId":"b867e073-...","toolCallId":"call_bCRM...","content":"2026-04-09T17:41:37.515Z"}

// 6. MCP App activity snapshot — carries the resource URI and full MCP result
{"type":"ACTIVITY_SNAPSHOT","messageId":"b3e20f20-...","activityType":"mcp-apps",
 "content":{
   "result":{"content":[{"type":"text","text":"2026-04-09T17:41:37.515Z"}]},
   "resourceUri":"ui://get-time/mcp-app.html",
   "serverHash":"2637fef21d2e2f89aa11b1d288fbe14d",
   "serverId":"threejs",
   "toolInput":{}
 },
 "replace":true}

// 7. Run lifecycle closes
{"type":"RUN_FINISHED","threadId":"probe-thread-1","runId":"probe-run-1"}
```

#### Text-only response (e.g. "Say hello briefly.")

```
RUN_STARTED
TEXT_MESSAGE_START
TEXT_MESSAGE_CONTENT  (one per token/chunk, field: "delta")
TEXT_MESSAGE_CONTENT
...
TEXT_MESSAGE_END
RUN_FINISHED
```

Full example (captured live):

```jsonc
{"type":"RUN_STARTED","threadId":"probe-thread-2","runId":"probe-run-2","input":{...}}
{"type":"TEXT_MESSAGE_START","messageId":"msg_0b88a8...","role":"assistant"}
{"type":"TEXT_MESSAGE_CONTENT","messageId":"msg_0b88a8...","delta":"Hello"}
{"type":"TEXT_MESSAGE_CONTENT","messageId":"msg_0b88a8...","delta":"!"}
{"type":"TEXT_MESSAGE_END","messageId":"msg_0b88a8..."}
{"type":"RUN_FINISHED","threadId":"probe-thread-2","runId":"probe-run-2"}
```

---

### Key Event Field Details

#### `RUN_STARTED`
| Field | Type | Notes |
|-------|------|-------|
| `type` | `"RUN_STARTED"` | |
| `threadId` | string | Echoes the request threadId |
| `runId` | string | Echoes the request runId |
| `input` | object | Full RunAgentInput body |

#### `TOOL_CALL_START`
| Field | Type | Notes |
|-------|------|-------|
| `type` | `"TOOL_CALL_START"` | |
| `toolCallId` | string | Unique ID for this call; used to correlate ARGS / END / RESULT |
| `toolCallName` | string | MCP tool name, e.g. `"get-time"` |
| `parentMessageId` | string | ID of the assistant message that triggered the call |

#### `TOOL_CALL_ARGS`
| Field | Type | Notes |
|-------|------|-------|
| `type` | `"TOOL_CALL_ARGS"` | |
| `toolCallId` | string | Matches TOOL_CALL_START |
| `delta` | string | JSON fragment (streamed); concatenate all deltas to get the full args object |

#### `TOOL_CALL_END`
| Field | Type | Notes |
|-------|------|-------|
| `type` | `"TOOL_CALL_END"` | |
| `toolCallId` | string | Matches TOOL_CALL_START |

#### `TOOL_CALL_RESULT`
| Field | Type | Notes |
|-------|------|-------|
| `type` | `"TOOL_CALL_RESULT"` | |
| `toolCallId` | string | Matches TOOL_CALL_START |
| `messageId` | string | ID assigned to the tool result message |
| `content` | **string** | Raw tool output as a plain string (not an array) |

#### `ACTIVITY_SNAPSHOT` (MCP App specific)
| Field | Type | Notes |
|-------|------|-------|
| `type` | `"ACTIVITY_SNAPSHOT"` | |
| `messageId` | string | |
| `activityType` | `"mcp-apps"` | Identifies this as an MCP App activity |
| `replace` | boolean | `true` — replaces any previous snapshot for this message |
| `content.resourceUri` | string | MCP App resource URI, e.g. `"ui://get-time/mcp-app.html"` |
| `content.result` | object | Full MCP tool result: `{ content: [{ type, text }] }` |
| `content.result.content` | array | MCP content items, each with `type` and `text` |
| `content.toolInput` | object | Tool arguments that were passed (empty object for get-time) |
| `content.serverId` | string | ID of the MCP server |
| `content.serverHash` | string | Hash identifying the server version |

#### `TEXT_MESSAGE_START`
| Field | Type | Notes |
|-------|------|-------|
| `type` | `"TEXT_MESSAGE_START"` | |
| `messageId` | string | Unique ID; correlates CONTENT and END events |
| `role` | `"assistant"` | |

#### `TEXT_MESSAGE_CONTENT`
| Field | Type | Notes |
|-------|------|-------|
| `type` | `"TEXT_MESSAGE_CONTENT"` | |
| `messageId` | string | Matches TEXT_MESSAGE_START |
| `delta` | string | Text chunk (one or more tokens) |

#### `TEXT_MESSAGE_END`
| Field | Type | Notes |
|-------|------|-------|
| `type` | `"TEXT_MESSAGE_END"` | |
| `messageId` | string | Matches TEXT_MESSAGE_START |

#### `RUN_FINISHED`
| Field | Type | Notes |
|-------|------|-------|
| `type` | `"RUN_FINISHED"` | |
| `threadId` | string | Echoes the request threadId |
| `runId` | string | Echoes the request runId |

---

### Conformance Tests

The conformance tests are in [mcp-app-ag-ui-host.conformance.mjs](mcp-app-ag-ui-host.conformance.mjs). Run with:

```sh
npm test
# or directly:
node --test mcp-app-ag-ui-host.conformance.mjs
```

Both the MCP server (port 3001) and the AG-UI host (port 3000) must be running.

The 8 test cases cover:

| # | Test | What it verifies |
|---|------|-----------------|
| 1 | Content-Type header | Response has `text/event-stream` |
| 2 | RUN_STARTED is first | Stream opens correctly |
| 3 | RUN_FINISHED is last, no RUN_ERROR | Run completes without error |
| 4 | `get-time` tool is invoked | LLM routes the time query to the MCP App tool |
| 5 | Tool call event sequence | `TOOL_CALL_START → TOOL_CALL_ARGS* → TOOL_CALL_END → TOOL_CALL_RESULT` in order |
| 6 | TOOL_CALL_RESULT is an ISO 8601 UTC timestamp | Tool output format is correct |
| 7 | ACTIVITY_SNAPSHOT carries the MCP App resource | `activityType === "mcp-apps"`, correct `resourceUri`, valid timestamp in result |
| 8 | TEXT_MESSAGE_* events are nested correctly | START/CONTENT/END envelopes are well-formed (vacuously passes if no text events) |
