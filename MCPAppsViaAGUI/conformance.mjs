// AG-UI MCP App Host Conformance Tests
// Verifies that an AG-UI host correctly handles MCP Apps over the AG-UI protocol.
//
// Observed event sequence for a "What time is it?" request:
//   RUN_STARTED → TOOL_CALL_START → TOOL_CALL_ARGS → TOOL_CALL_END
//   → TOOL_CALL_RESULT → ACTIVITY_SNAPSHOT → RUN_FINISHED
//
// Run with: node --test conformance.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/** URL of the AG-UI host under test. Set via the AG_UI_HOST environment variable. */
const AG_UI_HOST = process.env.AG_UI_HOST;

/** Per-test timeout in ms. LLM + MCP tool round-trips can be slow. */
const TEST_TIMEOUT_MS = 60_000;

/** Matches ISO 8601 UTC timestamps as produced by new Date().toISOString(). */
const ISO_8601_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/;

/** MCP App resource URI served by the get-time MCP App. */
const GET_TIME_RESOURCE_URI = 'ui://get-time/mcp-app.html';

// ---------------------------------------------------------------------------
// SSE parsing helper
// ---------------------------------------------------------------------------

/**
 * Reads a fetch() Response body as a streaming SSE source and returns a flat
 * array of parsed JSON event objects. Handles chunk boundaries safely.
 *
 * @param {Response} response
 * @returns {Promise<object[]>}
 */
async function collectSSEEvents(response) {
  const decoder = new TextDecoder();
  const events = [];
  let buffer = '';

  for await (const chunk of response.body) {
    buffer += decoder.decode(chunk, { stream: true });

    // SSE events are separated by blank lines (\n\n)
    const parts = buffer.split('\n\n');
    // The last element may be an incomplete event — keep it buffered
    buffer = parts.pop() ?? '';

    for (const part of parts) {
      for (const line of part.split('\n')) {
        if (line.startsWith('data: ')) {
          const payload = line.slice(6).trim();
          // Skip empty payloads and the [DONE] sentinel some servers emit
          if (payload && payload !== '[DONE]') {
            try { events.push(JSON.parse(payload)); } catch { /* skip non-JSON */ }
          }
        }
      }
    }
  }

  // Flush remaining buffer after stream closes
  const remaining = buffer.trim();
  if (remaining) {
    for (const line of remaining.split('\n')) {
      if (line.startsWith('data: ')) {
        const payload = line.slice(6).trim();
        if (payload && payload !== '[DONE]') {
          try { events.push(JSON.parse(payload)); } catch { /* ignore */ }
        }
      }
    }
  }

  return events;
}

// ---------------------------------------------------------------------------
// Request factory
// ---------------------------------------------------------------------------

/**
 * Sends a request to the AG-UI host using the CopilotKit envelope format
 * (method/params/body) and returns the raw Response plus collected SSE events.
 *
 * Generates fresh threadId / runId for each call so tests are independent.
 *
 * @param {Array<{id: string, role: string, content: string}>} messages
 * @param {object} [opts] Optional overrides merged into the RunAgentInput body
 * @returns {Promise<{response: Response, events: object[]}>}
 */
async function runAgent(messages, opts = {}) {
  const payload = {
    method: 'agent/run',
    params: { agentId: 'default' },
    body: {
      threadId: randomUUID(),
      runId:    randomUUID(),
      messages,
      tools:          [],
      context:        [],
      state:          {},
      forwardedProps: {},
      ...opts,
    },
  };

  const response = await fetch(AG_UI_HOST, {
    method:  'POST',
    headers: {
      'Content-Type': 'application/json',
      'Accept':        'text/event-stream',
    },
    body: JSON.stringify(payload),
  });

  const events = await collectSSEEvents(response);
  return { response, events };
}

/** Builds a minimal user message suitable for the messages array. */
function userMessage(content) {
  return { id: randomUUID(), role: 'user', content };
}

// ---------------------------------------------------------------------------
// Conformance tests
// ---------------------------------------------------------------------------

test('HTTP response has Content-Type: text/event-stream', { timeout: TEST_TIMEOUT_MS }, async () => {
  const { response } = await runAgent([userMessage('ping')]);
  const ct = response.headers.get('content-type') ?? '';
  assert.ok(
    ct.includes('text/event-stream'),
    `Expected Content-Type to include "text/event-stream", got: "${ct}"`
  );
});

test('SSE stream starts with RUN_STARTED event', { timeout: TEST_TIMEOUT_MS }, async () => {
  const { events } = await runAgent([userMessage('ping')]);
  assert.ok(events.length > 0, 'Expected at least one SSE event');
  assert.equal(
    events[0].type, 'RUN_STARTED',
    `First event type was "${events[0].type}", expected "RUN_STARTED"`
  );
});

test('SSE stream ends with RUN_FINISHED and contains no RUN_ERROR', { timeout: TEST_TIMEOUT_MS }, async () => {
  const { events } = await runAgent([userMessage('ping')]);
  assert.ok(events.length > 0, 'Expected at least one SSE event');

  const last = events.at(-1);
  assert.equal(
    last.type, 'RUN_FINISHED',
    `Last event type was "${last.type}", expected "RUN_FINISHED". Full sequence: ${events.map(e => e.type).join(', ')}`
  );
  assert.equal(
    events.filter(e => e.type === 'RUN_ERROR').length,
    0,
    'Stream contained at least one RUN_ERROR event'
  );
});

test('Asking "What time is it?" causes a TOOL_CALL_START for get-time', { timeout: TEST_TIMEOUT_MS }, async () => {
  const { events } = await runAgent([userMessage('What time is it?')]);
  const toolStart = events.find(
    e => e.type === 'TOOL_CALL_START' && e.toolCallName === 'get-time'
  );
  assert.ok(
    toolStart != null,
    `Expected a TOOL_CALL_START with toolCallName "get-time". Full event sequence: ${events.map(e => e.type).join(', ')}`
  );
});

test('Tool call sequence: TOOL_CALL_START → TOOL_CALL_ARGS* → TOOL_CALL_END → TOOL_CALL_RESULT', { timeout: TEST_TIMEOUT_MS }, async () => {
  const { events } = await runAgent([userMessage('What time is it?')]);

  const startEvt = events.find(
    e => e.type === 'TOOL_CALL_START' && e.toolCallName === 'get-time'
  );
  assert.ok(startEvt, 'No TOOL_CALL_START for get-time found');

  const id = startEvt.toolCallId;
  assert.ok(id, 'TOOL_CALL_START must carry a toolCallId');

  const startIdx  = events.indexOf(startEvt);
  const endIdx    = events.findIndex(e => e.type === 'TOOL_CALL_END'    && e.toolCallId === id);
  const resultIdx = events.findIndex(e => e.type === 'TOOL_CALL_RESULT' && e.toolCallId === id);

  assert.ok(endIdx > startIdx,
    `TOOL_CALL_END (index ${endIdx}) must come after TOOL_CALL_START (index ${startIdx})`
  );
  assert.ok(resultIdx > endIdx,
    `TOOL_CALL_RESULT (index ${resultIdx}) must come after TOOL_CALL_END (index ${endIdx})`
  );

  // Every TOOL_CALL_ARGS for this toolCallId must sit between START and END
  const argsEvents = events.filter(e => e.type === 'TOOL_CALL_ARGS' && e.toolCallId === id);
  for (const argEvt of argsEvents) {
    const idx = events.indexOf(argEvt);
    assert.ok(
      idx > startIdx && idx < endIdx,
      `TOOL_CALL_ARGS at index ${idx} is outside [START=${startIdx}, END=${endIdx}]`
    );
  }
});

test('TOOL_CALL_RESULT for get-time contains a valid ISO 8601 UTC timestamp', { timeout: TEST_TIMEOUT_MS }, async () => {
  const { events } = await runAgent([userMessage('What time is it?')]);

  const startEvt = events.find(
    e => e.type === 'TOOL_CALL_START' && e.toolCallName === 'get-time'
  );
  assert.ok(startEvt, 'No TOOL_CALL_START for get-time found');

  const resultEvt = events.find(
    e => e.type === 'TOOL_CALL_RESULT' && e.toolCallId === startEvt.toolCallId
  );
  assert.ok(resultEvt, 'No TOOL_CALL_RESULT for get-time found');

  // content is a plain string — the ISO timestamp returned by the tool
  assert.equal(typeof resultEvt.content, 'string',
    `TOOL_CALL_RESULT.content must be a string, got: ${JSON.stringify(resultEvt.content)}`
  );
  assert.match(
    resultEvt.content,
    ISO_8601_UTC,
    `Expected ISO 8601 UTC timestamp (e.g. 2024-01-15T10:30:00.000Z), got: "${resultEvt.content}"`
  );
});

test('ACTIVITY_SNAPSHOT for get-time appears after TOOL_CALL_RESULT and contains the MCP App resource', { timeout: TEST_TIMEOUT_MS }, async () => {
  const { events } = await runAgent([userMessage('What time is it?')]);

  const startEvt = events.find(
    e => e.type === 'TOOL_CALL_START' && e.toolCallName === 'get-time'
  );
  assert.ok(startEvt, 'No TOOL_CALL_START for get-time found');

  const resultIdx = events.findIndex(
    e => e.type === 'TOOL_CALL_RESULT' && e.toolCallId === startEvt.toolCallId
  );
  assert.ok(resultIdx !== -1, 'No TOOL_CALL_RESULT for get-time found');

  // ACTIVITY_SNAPSHOT must appear after TOOL_CALL_RESULT
  const snapshotEvt = events.find(
    (e, i) => i > resultIdx && e.type === 'ACTIVITY_SNAPSHOT'
  );
  assert.ok(
    snapshotEvt != null,
    `Expected an ACTIVITY_SNAPSHOT after TOOL_CALL_RESULT (index ${resultIdx}). Full sequence: ${events.map(e => e.type).join(', ')}`
  );

  // Must be typed as an MCP App activity
  assert.equal(snapshotEvt.activityType, 'mcp-apps',
    `Expected activityType "mcp-apps", got: "${snapshotEvt.activityType}"`
  );

  // Must carry the MCP App resource URI
  assert.equal(snapshotEvt.content?.resourceUri, GET_TIME_RESOURCE_URI,
    `Expected content.resourceUri "${GET_TIME_RESOURCE_URI}", got: "${snapshotEvt.content?.resourceUri}"`
  );

  // The embedded tool result must contain an ISO 8601 UTC timestamp
  const resultContent = snapshotEvt.content?.result?.content ?? [];
  assert.ok(
    Array.isArray(resultContent) && resultContent.length > 0,
    'ACTIVITY_SNAPSHOT.content.result.content must be a non-empty array'
  );
  const textItem = resultContent.find(c => c.type === 'text');
  assert.ok(textItem, 'ACTIVITY_SNAPSHOT.content.result.content must include a text item');
  assert.match(
    textItem.text,
    ISO_8601_UTC,
    `Expected ISO 8601 UTC timestamp in activity result, got: "${textItem.text}"`
  );
});

test('TEXT_MESSAGE_* events are properly nested when present', { timeout: TEST_TIMEOUT_MS }, async () => {
  // "Say hello" maximises the chance the LLM emits text events, but it is
  // valid for the agent to respond with only tool calls and no text messages.
  const { events } = await runAgent([userMessage('Say hello briefly.')]);

  const startEvents   = events.filter(e => e.type === 'TEXT_MESSAGE_START');
  const contentEvents = events.filter(e => e.type === 'TEXT_MESSAGE_CONTENT');
  const endEvents     = events.filter(e => e.type === 'TEXT_MESSAGE_END');

  // Vacuously satisfied when no text events are present
  if (startEvents.length === 0) return;

  assert.equal(
    startEvents.length, endEvents.length,
    `TEXT_MESSAGE_START count (${startEvents.length}) ≠ TEXT_MESSAGE_END count (${endEvents.length})`
  );

  for (const startEvt of startEvents) {
    const mid    = startEvt.messageId;
    const startI = events.indexOf(startEvt);
    const endI   = events.findIndex(e => e.type === 'TEXT_MESSAGE_END' && e.messageId === mid);

    assert.ok(endI > startI,
      `TEXT_MESSAGE_END for messageId "${mid}" not found after its START`
    );

    // All CONTENT events for this messageId must fall between START and END
    const myContent = events.filter(
      e => e.type === 'TEXT_MESSAGE_CONTENT' && e.messageId === mid
    );
    for (const ce of myContent) {
      const ci = events.indexOf(ce);
      assert.ok(
        ci > startI && ci < endI,
        `TEXT_MESSAGE_CONTENT at index ${ci} is outside START (${startI}) / END (${endI}) for messageId "${mid}"`
      );
    }
  }

  // No CONTENT event should appear without a matching START
  for (const ce of contentEvents) {
    const mid = ce.messageId;
    assert.ok(
      startEvents.some(s => s.messageId === mid),
      `TEXT_MESSAGE_CONTENT for messageId "${mid}" has no corresponding TEXT_MESSAGE_START`
    );
  }
});
