import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import crypto from "crypto";

// ---------------------------------------------------------------------------
// Mock axios at the module level BEFORE any import of index.ts.
// Every test that exercises callApi (through MCP tool invocations) will
// interact with this mock rather than making real HTTP requests.
// ---------------------------------------------------------------------------

vi.mock("axios", async (importOriginal) => {
  const actual = (await importOriginal()) as any;
  return {
    ...actual,
    default: {
      ...actual.default,
      post: vi.fn(),
      isAxiosError: actual.default.isAxiosError,
    },
  };
});

import axios from "axios";
import {
  validateApiUrl,
  createRateLimiter,
  sanitizeResponse,
  sanitizeError,
  createSandboxServer,
} from "./index.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const mockedAxiosPost = axios.post as ReturnType<typeof vi.fn>;

/** Creates an MCP client + server pair connected via in-memory transport. */
async function createConnectedPair(
  serverOverrides?: Parameters<typeof createSandboxServer>[0]
) {
  const server = createSandboxServer({
    publicKey: "test-pub-key",
    privateKey: "test-priv-key",
    apiBase: "https://tradernet.com/api",
    enableRawApi: false,
    ...serverOverrides,
  });

  const client = new Client({ name: "test-client", version: "0.0.1" });
  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();

  await Promise.all([
    server.connect(serverTransport),
    client.connect(clientTransport),
  ]);

  return { server, client, cleanup: () => Promise.all([server.close(), client.close()]) };
}

/** Build a fake AxiosError (matching the shape axios.isAxiosError checks). */
function makeAxiosError(opts: {
  status?: number;
  statusText?: string;
  code?: string;
  data?: unknown;
}) {
  const err: any = new Error("axios error");
  err.isAxiosError = true;
  err.config = {};
  err.toJSON = () => ({});
  if (opts.status) {
    err.response = {
      status: opts.status,
      statusText: opts.statusText ?? "",
      data: opts.data ?? {},
      headers: {},
      config: {},
    };
  }
  if (opts.code) {
    err.code = opts.code;
  }
  return err;
}

// ============================================================================
// 1. STARTUP VALIDATION -- validateApiUrl
// ============================================================================

describe("validateApiUrl", () => {
  it("should accept https://tradernet.com/api", () => {
    expect(validateApiUrl("https://tradernet.com/api")).toBe(
      "https://tradernet.com/api"
    );
  });

  it("should accept https://api.tradernet.com", () => {
    expect(validateApiUrl("https://api.tradernet.com")).toBe(
      "https://api.tradernet.com"
    );
  });

  it("should accept https://tradernet.com/api/ and strip trailing slash", () => {
    expect(validateApiUrl("https://tradernet.com/api/")).toBe(
      "https://tradernet.com/api"
    );
  });

  it("should reject http:// (non-HTTPS)", () => {
    expect(() => validateApiUrl("http://tradernet.com/api")).toThrow(
      "API URL must use HTTPS"
    );
  });

  it("should reject ftp:// protocol", () => {
    expect(() => validateApiUrl("ftp://tradernet.com/api")).toThrow(
      "API URL must use HTTPS"
    );
  });

  it("should reject hosts not in the allowlist", () => {
    expect(() =>
      validateApiUrl("https://evil.example.com/api")
    ).toThrow("API URL host must be one of:");
  });

  it("should reject a subdomain attack like https://fake.tradernet.com", () => {
    expect(() =>
      validateApiUrl("https://fake.tradernet.com/api")
    ).toThrow("API URL host must be one of:");
  });

  it("should throw for a completely invalid URL", () => {
    expect(() => validateApiUrl("not-a-url")).toThrow(
      "Invalid TRADERNET_API_URL:"
    );
  });

  it("should throw for an empty string", () => {
    expect(() => validateApiUrl("")).toThrow("Invalid TRADERNET_API_URL:");
  });
});

// ============================================================================
// 2. RATE LIMITER
// ============================================================================

describe("createRateLimiter", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("should allow calls within the read limit", () => {
    const limiter = createRateLimiter({ read: { maxCalls: 3, windowMs: 1000 } });
    // Each call: check then record
    expect(limiter.check("read")).toBe(true);
    limiter.record("read");
    expect(limiter.check("read")).toBe(true);
    limiter.record("read");
    expect(limiter.check("read")).toBe(true);
    limiter.record("read");
  });

  it("should deny the call that exceeds the read limit", () => {
    const limiter = createRateLimiter({ read: { maxCalls: 2, windowMs: 1000 } });
    expect(limiter.check("read")).toBe(true);
    limiter.record("read");
    expect(limiter.check("read")).toBe(true);
    limiter.record("read");
    // 3rd check should fail -- we already have 2 recorded
    expect(limiter.check("read")).toBe(false);
  });

  it("should allow calls again after the window expires", () => {
    const limiter = createRateLimiter({ read: { maxCalls: 1, windowMs: 1000 } });
    expect(limiter.check("read")).toBe(true);
    limiter.record("read");
    expect(limiter.check("read")).toBe(false);

    // Advance past the window
    vi.advanceTimersByTime(1001);

    expect(limiter.check("read")).toBe(true);
  });

  it("should track read and write limits independently", () => {
    const limiter = createRateLimiter({
      read: { maxCalls: 1, windowMs: 1000 },
      write: { maxCalls: 1, windowMs: 1000 },
    });
    expect(limiter.check("read")).toBe(true);
    limiter.record("read");
    expect(limiter.check("read")).toBe(false);

    // Write should still be available
    expect(limiter.check("write")).toBe(true);
    limiter.record("write");
    expect(limiter.check("write")).toBe(false);
  });

  it("should use default limits (200 read, 50 write) when not overridden", () => {
    const limiter = createRateLimiter();
    // Should allow 200 reads
    for (let i = 0; i < 200; i++) {
      expect(limiter.check("read")).toBe(true);
      limiter.record("read");
    }
    expect(limiter.check("read")).toBe(false);

    // Should allow 50 writes
    for (let i = 0; i < 50; i++) {
      expect(limiter.check("write")).toBe(true);
      limiter.record("write");
    }
    expect(limiter.check("write")).toBe(false);
  });
});

// ============================================================================
// 3. RESPONSE SANITIZATION
// ============================================================================

describe("sanitizeResponse", () => {
  it("should return null unchanged", () => {
    expect(sanitizeResponse(null)).toBeNull();
  });

  it("should return undefined unchanged", () => {
    expect(sanitizeResponse(undefined)).toBeUndefined();
  });

  it("should return primitives unchanged", () => {
    expect(sanitizeResponse(42)).toBe(42);
    expect(sanitizeResponse("hello")).toBe("hello");
    expect(sanitizeResponse(true)).toBe(true);
  });

  it("should redact all known sensitive keys at top level", () => {
    const input = {
      session_id: "abc123",
      sessionId: "def456",
      token: "tok",
      access_token: "at",
      refresh_token: "rt",
      password: "pw",
      secret: "sec",
      api_key: "ak",
      apiKey: "AK",
      private_key: "pk",
      privateKey: "PK",
      ssn: "123-45-6789",
      tax_id: "tid",
      taxId: "TID",
      safe_field: "keep-me",
    };
    const result = sanitizeResponse(input) as Record<string, unknown>;

    // Every sensitive key should be redacted
    for (const key of Object.keys(input)) {
      if (key === "safe_field") {
        expect(result[key]).toBe("keep-me");
      } else {
        expect(result[key]).toBe("[REDACTED]");
      }
    }
  });

  it("should redact sensitive keys in nested objects", () => {
    const input = {
      user: {
        name: "Alice",
        token: "secret-token",
        profile: {
          ssn: "111-22-3333",
          email: "alice@test.com",
        },
      },
    };
    const result = sanitizeResponse(input) as any;
    expect(result.user.name).toBe("Alice");
    expect(result.user.token).toBe("[REDACTED]");
    expect(result.user.profile.ssn).toBe("[REDACTED]");
    expect(result.user.profile.email).toBe("alice@test.com");
  });

  it("should redact sensitive keys inside arrays", () => {
    const input = [
      { id: 1, password: "pw1" },
      { id: 2, password: "pw2" },
    ];
    const result = sanitizeResponse(input) as any[];
    expect(result[0].id).toBe(1);
    expect(result[0].password).toBe("[REDACTED]");
    expect(result[1].id).toBe(2);
    expect(result[1].password).toBe("[REDACTED]");
  });

  it("should handle deeply nested arrays of objects", () => {
    const input = {
      data: [
        { list: [{ token: "deep" }] },
      ],
    };
    const result = sanitizeResponse(input) as any;
    expect(result.data[0].list[0].token).toBe("[REDACTED]");
  });

  it("should pass through an empty object", () => {
    expect(sanitizeResponse({})).toEqual({});
  });

  it("should pass through an empty array", () => {
    expect(sanitizeResponse([])).toEqual([]);
  });
});

// ============================================================================
// 4. ERROR SANITIZATION
// ============================================================================

describe("sanitizeError", () => {
  it("should return status and statusText for Axios errors with response", () => {
    const err = makeAxiosError({ status: 404, statusText: "Not Found" });
    expect(sanitizeError(err)).toBe("API request failed: 404 Not Found");
  });

  it("should include API error message from response body when present", () => {
    const err = makeAxiosError({
      status: 400,
      statusText: "Bad Request",
      data: { error: "Invalid ticker format" },
    });
    const result = sanitizeError(err);
    expect(result).toContain("400");
    expect(result).toContain("Bad Request");
    expect(result).toContain("Invalid ticker format");
  });

  it("should handle Axios error with status but no statusText", () => {
    const err = makeAxiosError({ status: 500 });
    expect(sanitizeError(err)).toMatch(/API request failed: 500/);
  });

  it("should return timeout message for ECONNABORTED", () => {
    const err = makeAxiosError({ code: "ECONNABORTED" });
    expect(sanitizeError(err)).toBe(
      "API request timed out. Please try again."
    );
  });

  it("should return network message for ENOTFOUND", () => {
    const err = makeAxiosError({ code: "ENOTFOUND" });
    expect(sanitizeError(err)).toBe(
      "Could not connect to the Tradernet API. Please check your network."
    );
  });

  it("should return network message for ECONNREFUSED", () => {
    const err = makeAxiosError({ code: "ECONNREFUSED" });
    expect(sanitizeError(err)).toBe(
      "Could not connect to the Tradernet API. Please check your network."
    );
  });

  it("should return generic network error for other Axios errors", () => {
    const err = makeAxiosError({ code: "ESOMETHINGELSE" });
    expect(sanitizeError(err)).toBe(
      "API request failed due to a network error."
    );
  });

  it("should return 'Invalid input format.' for SyntaxError", () => {
    expect(sanitizeError(new SyntaxError("Unexpected token"))).toBe(
      "Invalid input format."
    );
  });

  it("should pass through rate limit error messages", () => {
    const msg =
      "Rate limit exceeded for read operations. Please wait before retrying.";
    expect(sanitizeError(new Error(msg))).toBe(msg);
  });

  it("should return generic message for non-rate-limit Error", () => {
    expect(sanitizeError(new Error("some internal bug"))).toBe(
      "An unexpected error occurred."
    );
  });

  it("should return generic message for non-Error throwables", () => {
    expect(sanitizeError("string error")).toBe(
      "An unexpected error occurred."
    );
    expect(sanitizeError(42)).toBe("An unexpected error occurred.");
    expect(sanitizeError(null)).toBe("An unexpected error occurred.");
    expect(sanitizeError(undefined)).toBe("An unexpected error occurred.");
  });
});

// ============================================================================
// 5. TOOL ANNOTATIONS
// ============================================================================

describe("Tool annotations", () => {
  let client: Client;
  let cleanup: () => Promise<any>;

  beforeEach(async () => {
    const pair = await createConnectedPair();
    client = pair.client;
    cleanup = pair.cleanup;
  });

  afterEach(async () => {
    await cleanup();
  });

  it("should register the expected set of tools (without raw_api_call by default)", async () => {
    const { tools } = await client.listTools();
    const names = tools.map((t) => t.name).sort();

    expect(names).toEqual([
      "add_price_alert",
      "cancel_order",
      "delete_price_alert",
      "get_exchange_rates",
      "get_market_status",
      "get_news",
      "get_order_history",
      "get_orders",
      "get_portfolio",
      "get_price_alerts",
      "get_quote",
      "get_quotes_history",
      "get_security_info",
      "get_security_sessions",
      "get_top_securities",
      "get_trades_history",
      "get_user_data",
      "place_order",
      "search_tickers",
      "set_stop_loss_take_profit",
    ]);
  });

  it("should mark read-only tools with readOnlyHint=true and destructiveHint=false", async () => {
    const { tools } = await client.listTools();

    const readOnlyTools = [
      "get_user_data",
      "get_portfolio",
      "get_security_info",
      "get_quotes_history",
      "search_tickers",
      "get_security_sessions",
      "get_quote",
      "get_orders",
      "get_order_history",
      "get_trades_history",
      "get_price_alerts",
      "get_market_status",
      "get_exchange_rates",
      "get_news",
      "get_top_securities",
    ];

    for (const name of readOnlyTools) {
      const tool = tools.find((t) => t.name === name);
      expect(tool, `Tool ${name} should exist`).toBeDefined();
      expect(tool!.annotations?.readOnlyHint).toBe(true);
      expect(tool!.annotations?.destructiveHint).toBe(false);
    }
  });

  it("should mark destructive tools with destructiveHint=true", async () => {
    const { tools } = await client.listTools();

    const destructiveTools = [
      "place_order",
      "cancel_order",
      "set_stop_loss_take_profit",
      "delete_price_alert",
    ];

    for (const name of destructiveTools) {
      const tool = tools.find((t) => t.name === name);
      expect(tool, `Tool ${name} should exist`).toBeDefined();
      expect(tool!.annotations?.destructiveHint).toBe(true);
    }
  });

  it("should mark place_order as non-idempotent", async () => {
    const { tools } = await client.listTools();
    const tool = tools.find((t) => t.name === "place_order");
    expect(tool!.annotations?.idempotentHint).toBe(false);
  });

  it("should mark cancel_order as idempotent", async () => {
    const { tools } = await client.listTools();
    const tool = tools.find((t) => t.name === "cancel_order");
    expect(tool!.annotations?.idempotentHint).toBe(true);
  });

  it("should mark add_price_alert as non-destructive and non-idempotent", async () => {
    const { tools } = await client.listTools();
    const tool = tools.find((t) => t.name === "add_price_alert");
    expect(tool!.annotations?.destructiveHint).toBe(false);
    expect(tool!.annotations?.idempotentHint).toBe(false);
  });
});

// ============================================================================
// 6. RAW_API_CALL OPT-IN
// ============================================================================

describe("raw_api_call opt-in", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("should NOT register raw_api_call when enableRawApi is false", async () => {
    const { client, cleanup } = await createConnectedPair({
      enableRawApi: false,
    });
    try {
      const { tools } = await client.listTools();
      const names = tools.map((t) => t.name);
      expect(names).not.toContain("raw_api_call");
    } finally {
      await cleanup();
    }
  });

  it("should register raw_api_call when enableRawApi is true", async () => {
    const { client, cleanup } = await createConnectedPair({
      enableRawApi: true,
    });
    try {
      const { tools } = await client.listTools();
      const names = tools.map((t) => t.name);
      expect(names).toContain("raw_api_call");
    } finally {
      await cleanup();
    }
  });

  it("should mark raw_api_call as destructive and non-idempotent", async () => {
    const { client, cleanup } = await createConnectedPair({
      enableRawApi: true,
    });
    try {
      const { tools } = await client.listTools();
      const tool = tools.find((t) => t.name === "raw_api_call");
      expect(tool!.annotations?.destructiveHint).toBe(true);
      expect(tool!.annotations?.idempotentHint).toBe(false);
    } finally {
      await cleanup();
    }
  });
});

// ============================================================================
// 7. API CLIENT -- headers, HMAC signature, timeout (via tool invocations)
// ============================================================================

describe("API client (via tool invocations)", () => {
  let client: Client;
  let cleanup: () => Promise<any>;

  beforeEach(async () => {
    mockedAxiosPost.mockReset();
    const pair = await createConnectedPair();
    client = pair.client;
    cleanup = pair.cleanup;
  });

  afterEach(async () => {
    await cleanup();
  });

  it("should send correct headers including HMAC signature to the API", async () => {
    mockedAxiosPost.mockResolvedValueOnce({ data: { ok: true } });

    await client.callTool({ name: "get_portfolio", arguments: {} });

    expect(mockedAxiosPost).toHaveBeenCalledTimes(1);

    const [url, body, config] = mockedAxiosPost.mock.calls[0];

    // URL
    expect(url).toBe("https://tradernet.com/api/getPositionJson");

    // Body should be JSON string of empty params
    expect(body).toBe("{}");

    // Headers
    expect(config.headers["Content-Type"]).toBe("application/json");
    expect(config.headers["X-NtApi-PublicKey"]).toBe("test-pub-key");
    expect(config.headers["X-NtApi-Timestamp"]).toMatch(/^\d+$/);

    // HMAC signature verification
    const expectedPayload = body + config.headers["X-NtApi-Timestamp"];
    const expectedSig = crypto
      .createHmac("sha256", "test-priv-key")
      .update(expectedPayload)
      .digest("hex");
    expect(config.headers["X-NtApi-Sig"]).toBe(expectedSig);

    // Timeout
    expect(config.timeout).toBe(30_000);
  });

  it("should send correct command URL for different tools", async () => {
    mockedAxiosPost.mockResolvedValue({ data: {} });

    await client.callTool({ name: "get_user_data", arguments: {} });
    expect(mockedAxiosPost.mock.calls[0][0]).toBe(
      "https://tradernet.com/api/getOPQ"
    );

    await client.callTool({
      name: "get_security_info",
      arguments: { ticker: "AAPL.US" },
    });
    expect(mockedAxiosPost.mock.calls[1][0]).toBe(
      "https://tradernet.com/api/getSecurityInfo"
    );
  });

  it("should correctly map place_order parameters", async () => {
    mockedAxiosPost.mockResolvedValueOnce({ data: { order_id: 999 } });

    await client.callTool({
      name: "place_order",
      arguments: {
        instrument: "AAPL.US",
        action: "buy",
        order_type: "limit",
        quantity: 10,
        limit_price: 150.5,
        expiration: "gtc",
      },
    });

    const sentBody = JSON.parse(mockedAxiosPost.mock.calls[0][1]);
    expect(sentBody).toMatchObject({
      instr_name: "AAPL.US",
      action_id: 1,
      order_type_id: 2,
      qty: 10,
      limit_price: 150.5,
      expiration_id: 3,
    });
  });

  it("should correctly map cancel_order parameters", async () => {
    mockedAxiosPost.mockResolvedValueOnce({ data: { ok: true } });

    await client.callTool({
      name: "cancel_order",
      arguments: { order_id: 12345 },
    });

    const sentBody = JSON.parse(mockedAxiosPost.mock.calls[0][1]);
    expect(sentBody).toMatchObject({ order_id: 12345 });
  });

  it("should correctly map search_tickers parameters", async () => {
    mockedAxiosPost.mockResolvedValueOnce({ data: [] });

    await client.callTool({
      name: "search_tickers",
      arguments: { query: "AAPL@FIX" },
    });

    const sentBody = JSON.parse(mockedAxiosPost.mock.calls[0][1]);
    expect(sentBody).toMatchObject({ text: "AAPL@FIX" });
  });

  it("should correctly map add_price_alert parameters", async () => {
    mockedAxiosPost.mockResolvedValueOnce({ data: { alert_id: 42 } });

    await client.callTool({
      name: "add_price_alert",
      arguments: {
        ticker: "AAPL.US",
        price: "150.00",
        trigger_type: "crossing_up",
        quote_type: "ltp",
        notification_type: "push",
        alert_period: "0",
      },
    });

    const sentBody = JSON.parse(mockedAxiosPost.mock.calls[0][1]);
    expect(sentBody).toMatchObject({
      ticker: "AAPL.US",
      price: { price: "150.00" },
      trigger_type: "crossing_up",
      quote_type: "ltp",
      notification_type: "push",
      alert_period: "0",
      expire: 0,
    });
  });

  it("should correctly map delete_price_alert parameters", async () => {
    mockedAxiosPost.mockResolvedValueOnce({ data: { ok: true } });

    await client.callTool({
      name: "delete_price_alert",
      arguments: { alert_id: 42 },
    });

    const sentBody = JSON.parse(mockedAxiosPost.mock.calls[0][1]);
    expect(sentBody).toMatchObject({
      id: 42,
      del: true,
      quote_type: "ltp",
      notification_type: "email",
    });
  });

  it("should correctly map get_quotes_history parameters", async () => {
    mockedAxiosPost.mockResolvedValueOnce({ data: { hloc: [] } });

    await client.callTool({
      name: "get_quotes_history",
      arguments: {
        ticker: "SBER",
        timeframe: "60",
        date_from: "01.01.2025 00:00",
        date_to: "31.01.2025 23:59",
        count: 0,
      },
    });

    const sentBody = JSON.parse(mockedAxiosPost.mock.calls[0][1]);
    expect(sentBody).toMatchObject({
      id: "SBER",
      timeframe: 60,
      date_from: "01.01.2025 00:00",
      date_to: "31.01.2025 23:59",
      count: 0,
      intervalMode: "ClosedRay",
    });
  });

  it("should correctly map set_stop_loss_take_profit parameters", async () => {
    mockedAxiosPost.mockResolvedValueOnce({ data: { ok: true } });

    await client.callTool({
      name: "set_stop_loss_take_profit",
      arguments: {
        instrument: "AAPL.US",
        stop_loss: 140.0,
        take_profit: 180.0,
        trailing_stop_percent: null,
      },
    });

    const sentBody = JSON.parse(mockedAxiosPost.mock.calls[0][1]);
    expect(sentBody).toMatchObject({
      instr_name: "AAPL.US",
      stop_loss: 140.0,
      take_profit: 180.0,
      stoploss_trailing_percent: null,
    });
  });

  it("should correctly map get_quote parameters (split comma-separated tickers)", async () => {
    mockedAxiosPost.mockResolvedValueOnce({ data: [] });

    await client.callTool({
      name: "get_quote",
      arguments: { tickers: "AAPL.US, MSFT.US, GOOG.US" },
    });

    const sentBody = JSON.parse(mockedAxiosPost.mock.calls[0][1]);
    expect(sentBody).toMatchObject({
      tickers: ["AAPL.US", "MSFT.US", "GOOG.US"],
    });
    expect(mockedAxiosPost.mock.calls[0][0]).toBe(
      "https://tradernet.com/api/getStockQuotesJson"
    );
  });

  it("should correctly map get_orders parameters (boolean to 1/0)", async () => {
    mockedAxiosPost.mockResolvedValueOnce({ data: [] });

    await client.callTool({
      name: "get_orders",
      arguments: { active_only: true },
    });

    const sentBody = JSON.parse(mockedAxiosPost.mock.calls[0][1]);
    expect(sentBody).toMatchObject({ active_only: 1 });
    expect(mockedAxiosPost.mock.calls[0][0]).toBe(
      "https://tradernet.com/api/getNotifyOrderJson"
    );
  });

  it("should correctly map get_orders with active_only=false", async () => {
    mockedAxiosPost.mockResolvedValueOnce({ data: [] });

    await client.callTool({
      name: "get_orders",
      arguments: { active_only: false },
    });

    const sentBody = JSON.parse(mockedAxiosPost.mock.calls[0][1]);
    expect(sentBody).toMatchObject({ active_only: 0 });
  });

  it("should correctly map get_order_history parameters", async () => {
    mockedAxiosPost.mockResolvedValueOnce({ data: [] });

    await client.callTool({
      name: "get_order_history",
      arguments: { from: "2025-01-01", till: "2025-01-31" },
    });

    const sentBody = JSON.parse(mockedAxiosPost.mock.calls[0][1]);
    expect(sentBody).toMatchObject({ from: "2025-01-01", till: "2025-01-31" });
    expect(mockedAxiosPost.mock.calls[0][0]).toBe(
      "https://tradernet.com/api/getOrdersHistory"
    );
  });

  it("should correctly map get_trades_history parameters (ticker → nt_ticker)", async () => {
    mockedAxiosPost.mockResolvedValueOnce({ data: [] });

    await client.callTool({
      name: "get_trades_history",
      arguments: {
        beginDate: "2025-01-01",
        endDate: "2025-01-31",
        ticker: "AAPL.US",
        max: 50,
      },
    });

    const sentBody = JSON.parse(mockedAxiosPost.mock.calls[0][1]);
    expect(sentBody).toMatchObject({
      beginDate: "2025-01-01",
      endDate: "2025-01-31",
      nt_ticker: "AAPL.US",
      max: 50,
    });
    expect(sentBody).not.toHaveProperty("ticker");
    expect(mockedAxiosPost.mock.calls[0][0]).toBe(
      "https://tradernet.com/api/getTradesHistory"
    );
  });

  it("should correctly map get_exchange_rates parameters (split currencies)", async () => {
    mockedAxiosPost.mockResolvedValueOnce({ data: {} });

    await client.callTool({
      name: "get_exchange_rates",
      arguments: {
        base_currency: "USD",
        currencies: "EUR, GBP, RUB",
        date: "2025-01-15",
      },
    });

    const sentBody = JSON.parse(mockedAxiosPost.mock.calls[0][1]);
    expect(sentBody).toMatchObject({
      base_currency: "USD",
      currencies: ["EUR", "GBP", "RUB"],
      date: "2025-01-15",
    });
    expect(mockedAxiosPost.mock.calls[0][0]).toBe(
      "https://tradernet.com/api/getCrossRatesForDate"
    );
  });

  it("should correctly map get_news parameters (query → searchFor)", async () => {
    mockedAxiosPost.mockResolvedValueOnce({ data: [] });

    await client.callTool({
      name: "get_news",
      arguments: { ticker: "AAPL.US", query: "earnings", limit: 5 },
    });

    const sentBody = JSON.parse(mockedAxiosPost.mock.calls[0][1]);
    expect(sentBody).toMatchObject({
      ticker: "AAPL.US",
      searchFor: "earnings",
      limit: 5,
    });
    expect(sentBody).not.toHaveProperty("query");
    expect(mockedAxiosPost.mock.calls[0][0]).toBe(
      "https://tradernet.com/api/getNews"
    );
  });

  it("should correctly map get_top_securities parameters (gainers → 1/0)", async () => {
    mockedAxiosPost.mockResolvedValueOnce({ data: [] });

    await client.callTool({
      name: "get_top_securities",
      arguments: {
        type: "stocks",
        exchange: "usa",
        gainers: false,
        limit: 5,
      },
    });

    const sentBody = JSON.parse(mockedAxiosPost.mock.calls[0][1]);
    expect(sentBody).toMatchObject({
      type: "stocks",
      exchange: "usa",
      gainers: 0,
      limit: 5,
    });
    expect(mockedAxiosPost.mock.calls[0][0]).toBe(
      "https://tradernet.com/api/getTopSecurities"
    );
  });
});

// ============================================================================
// 8. RESPONSE SANITIZATION VIA TOOL INVOCATIONS
// ============================================================================

describe("Response sanitization through tool invocations", () => {
  let client: Client;
  let cleanup: () => Promise<any>;

  beforeEach(async () => {
    mockedAxiosPost.mockReset();
    const pair = await createConnectedPair();
    client = pair.client;
    cleanup = pair.cleanup;
  });

  afterEach(async () => {
    await cleanup();
  });

  it("should redact sensitive keys in API response returned to client", async () => {
    mockedAxiosPost.mockResolvedValueOnce({
      data: {
        account_id: "12345",
        session_id: "should-be-hidden",
        token: "also-hidden",
        balance: 1000,
        nested: {
          password: "super-secret",
          name: "visible",
        },
      },
    });

    const result = await client.callTool({
      name: "get_user_data",
      arguments: {},
    });

    const textContent = (result as any).content[0].text;
    const parsed = JSON.parse(textContent);

    expect(parsed.account_id).toBe("12345");
    expect(parsed.balance).toBe(1000);
    expect(parsed.session_id).toBe("[REDACTED]");
    expect(parsed.token).toBe("[REDACTED]");
    expect(parsed.nested.password).toBe("[REDACTED]");
    expect(parsed.nested.name).toBe("visible");
  });

  it("should redact sensitive keys in array responses", async () => {
    mockedAxiosPost.mockResolvedValueOnce({
      data: [
        { ticker: "AAPL", secret: "key1" },
        { ticker: "GOOG", apiKey: "key2" },
      ],
    });

    const result = await client.callTool({
      name: "get_portfolio",
      arguments: {},
    });

    const parsed = JSON.parse((result as any).content[0].text);
    expect(parsed[0].ticker).toBe("AAPL");
    expect(parsed[0].secret).toBe("[REDACTED]");
    expect(parsed[1].ticker).toBe("GOOG");
    expect(parsed[1].apiKey).toBe("[REDACTED]");
  });
});

// ============================================================================
// 9. ERROR SANITIZATION VIA TOOL INVOCATIONS
// ============================================================================

describe("Error sanitization through tool invocations", () => {
  let client: Client;
  let cleanup: () => Promise<any>;

  beforeEach(async () => {
    mockedAxiosPost.mockReset();
    const pair = await createConnectedPair();
    client = pair.client;
    cleanup = pair.cleanup;
  });

  afterEach(async () => {
    await cleanup();
  });

  it("should return sanitized HTTP error to client", async () => {
    mockedAxiosPost.mockRejectedValueOnce(
      makeAxiosError({ status: 403, statusText: "Forbidden" })
    );

    const result = await client.callTool({
      name: "get_portfolio",
      arguments: {},
    });

    expect((result as any).isError).toBe(true);
    const text = (result as any).content[0].text;
    expect(text).toContain("403");
    expect(text).toContain("Forbidden");
    // Should NOT contain any stack trace or internal detail
    expect(text).not.toContain("at ");
    expect(text).toMatch(/^Error: API request failed: 403 Forbidden/);
  });

  it("should return timeout message to client", async () => {
    mockedAxiosPost.mockRejectedValueOnce(
      makeAxiosError({ code: "ECONNABORTED" })
    );

    const result = await client.callTool({
      name: "get_user_data",
      arguments: {},
    });

    expect((result as any).isError).toBe(true);
    expect((result as any).content[0].text).toContain(
      "API request timed out"
    );
  });

  it("should return network error message to client", async () => {
    mockedAxiosPost.mockRejectedValueOnce(
      makeAxiosError({ code: "ENOTFOUND" })
    );

    const result = await client.callTool({
      name: "get_portfolio",
      arguments: {},
    });

    expect((result as any).isError).toBe(true);
    expect((result as any).content[0].text).toContain(
      "Could not connect to the Tradernet API"
    );
  });

  it("should return generic message for unexpected errors", async () => {
    mockedAxiosPost.mockRejectedValueOnce(new Error("something went wrong"));

    const result = await client.callTool({
      name: "get_portfolio",
      arguments: {},
    });

    expect((result as any).isError).toBe(true);
    expect((result as any).content[0].text).toContain(
      "An unexpected error occurred"
    );
  });
});

// ============================================================================
// 10. RAW_API_CALL TOOL BEHAVIOR
// ============================================================================

describe("raw_api_call tool behavior", () => {
  let client: Client;
  let cleanup: () => Promise<any>;

  beforeEach(async () => {
    mockedAxiosPost.mockReset();
    const pair = await createConnectedPair({ enableRawApi: true });
    client = pair.client;
    cleanup = pair.cleanup;
  });

  afterEach(async () => {
    await cleanup();
  });

  it("should make the API call with parsed JSON params", async () => {
    mockedAxiosPost.mockResolvedValueOnce({ data: { result: "ok" } });

    const result = await client.callTool({
      name: "raw_api_call",
      arguments: {
        command: "someCustomCommand",
        params: '{"key": "value"}',
      },
    });

    expect((result as any).isError).toBeUndefined();
    const sentBody = JSON.parse(mockedAxiosPost.mock.calls[0][1]);
    expect(sentBody).toEqual({ key: "value" });
    expect(mockedAxiosPost.mock.calls[0][0]).toBe(
      "https://tradernet.com/api/someCustomCommand"
    );
  });

  it("should return an error for invalid JSON params", async () => {
    const result = await client.callTool({
      name: "raw_api_call",
      arguments: {
        command: "test",
        params: "not valid json{{{",
      },
    });

    expect((result as any).isError).toBe(true);
    expect((result as any).content[0].text).toContain("Invalid input format");
  });

  it("should sanitize the response from raw_api_call", async () => {
    mockedAxiosPost.mockResolvedValueOnce({
      data: { value: 42, token: "leaked-token" },
    });

    const result = await client.callTool({
      name: "raw_api_call",
      arguments: { command: "getData", params: "{}" },
    });

    const parsed = JSON.parse((result as any).content[0].text);
    expect(parsed.value).toBe(42);
    expect(parsed.token).toBe("[REDACTED]");
  });
});

// ============================================================================
// 11. RATE LIMITING VIA TOOL INVOCATIONS
// ============================================================================

describe("Rate limiting through tool invocations", () => {
  let client: Client;
  let cleanup: () => Promise<any>;

  beforeEach(async () => {
    mockedAxiosPost.mockReset();
    mockedAxiosPost.mockResolvedValue({ data: { ok: true } });
    const pair = await createConnectedPair();
    client = pair.client;
    cleanup = pair.cleanup;
  });

  afterEach(async () => {
    await cleanup();
  });

  it("should allow many read calls within limits", async () => {
    // Default limit is 200 reads per minute. Making a few should be fine.
    for (let i = 0; i < 5; i++) {
      const result = await client.callTool({
        name: "get_portfolio",
        arguments: {},
      });
      expect((result as any).isError).toBeUndefined();
    }
  });

  it("should eventually rate-limit write operations", async () => {
    // Default write limit is 50 per minute.
    // We need to make 51 calls to trigger the limit.
    // Note: each callApi checks THEN records, so:
    //   call 1-50: check passes (0-49 recorded), then record
    //   call 51: check fails (50 recorded)
    const results: any[] = [];
    for (let i = 0; i < 52; i++) {
      const result = await client.callTool({
        name: "cancel_order",
        arguments: { order_id: i },
      });
      results.push(result);
    }

    // At least the last call should be rate-limited
    const rateLimited = results.filter(
      (r) => r.isError && r.content[0].text.includes("Rate limit exceeded")
    );
    expect(rateLimited.length).toBeGreaterThanOrEqual(1);
  });
});

// ============================================================================
// 12. EDGE CASES: createSandboxServer configuration
// ============================================================================

describe("createSandboxServer configuration", () => {
  it("should create a server without errors when given valid config", () => {
    expect(() =>
      createSandboxServer({
        publicKey: "pub",
        privateKey: "priv",
        apiBase: "https://tradernet.com/api",
        enableRawApi: false,
      })
    ).not.toThrow();
  });

  it("should create separate independent server instances", async () => {
    // Two servers with different configs should not interfere
    const { client: client1, cleanup: cleanup1 } = await createConnectedPair({
      enableRawApi: false,
    });
    const { client: client2, cleanup: cleanup2 } = await createConnectedPair({
      enableRawApi: true,
    });

    try {
      const tools1 = (await client1.listTools()).tools.map((t) => t.name);
      const tools2 = (await client2.listTools()).tools.map((t) => t.name);

      expect(tools1).not.toContain("raw_api_call");
      expect(tools2).toContain("raw_api_call");
    } finally {
      await Promise.all([cleanup1(), cleanup2()]);
    }
  });
});

// ============================================================================
// 13. TOOL RESULT FORMAT
// ============================================================================

describe("Tool result format", () => {
  let client: Client;
  let cleanup: () => Promise<any>;

  beforeEach(async () => {
    mockedAxiosPost.mockReset();
    const pair = await createConnectedPair();
    client = pair.client;
    cleanup = pair.cleanup;
  });

  afterEach(async () => {
    await cleanup();
  });

  it("should return content as array with a single text item on success", async () => {
    mockedAxiosPost.mockResolvedValueOnce({ data: { foo: "bar" } });

    const result = await client.callTool({
      name: "get_portfolio",
      arguments: {},
    });

    const content = (result as any).content;
    expect(content).toHaveLength(1);
    expect(content[0].type).toBe("text");
    expect(typeof content[0].text).toBe("string");
    // Should be valid JSON
    expect(() => JSON.parse(content[0].text)).not.toThrow();
  });

  it("should return isError=true and error text on failure", async () => {
    mockedAxiosPost.mockRejectedValueOnce(
      makeAxiosError({ status: 500, statusText: "Internal Server Error" })
    );

    const result = await client.callTool({
      name: "get_portfolio",
      arguments: {},
    });

    expect((result as any).isError).toBe(true);
    expect((result as any).content[0].type).toBe("text");
    expect((result as any).content[0].text).toMatch(/^Error:/);
  });

  it("should pretty-print JSON with 2-space indentation", async () => {
    mockedAxiosPost.mockResolvedValueOnce({ data: { a: 1, b: { c: 2 } } });

    const result = await client.callTool({
      name: "get_user_data",
      arguments: {},
    });

    const text = (result as any).content[0].text;
    // Should contain newlines (pretty-printed)
    expect(text).toContain("\n");
    // Verify 2-space indentation
    expect(text).toContain('  "a"');
  });
});
