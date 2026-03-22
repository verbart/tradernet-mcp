#!/usr/bin/env node

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import crypto from "crypto";
import axios from "axios";
import { z } from "zod";

// --- Types ---

type TradernetCommand =
  | "getOPQ"
  | "getPositionJson"
  | "putTradeOrder"
  | "delTradeOrder"
  | "putStopLoss"
  | "getSecurityInfo"
  | "getHloc"
  | "tickerFinder"
  | "togglePriceAlert"
  | "getSecuritySessions"
  | "getStockQuotesJson"
  | "getNotifyOrderJson"
  | "getOrdersHistory"
  | "getTradesHistory"
  | "getAlertsList"
  | "getMarketStatus"
  | "getCrossRatesForDate"
  | "getNews"
  | "getTopSecurities";

interface RateLimit {
  maxCalls: number;
  windowMs: number;
}

interface ServerConfig {
  publicKey: string;
  privateKey: string;
  apiBase: string;
  enableRawApi: boolean;
}

// --- Constants ---

const VERSION = "1.1.2";

const ALLOWED_API_HOSTS = ["tradernet.com", "api.tradernet.com"];

const REQUEST_TIMEOUT_MS = 30_000;

const WRITE_COMMANDS = new Set<string>([
  "putTradeOrder",
  "delTradeOrder",
  "putStopLoss",
  "togglePriceAlert",
]);

const SENSITIVE_KEYS = new Set([
  "session_id",
  "sessionId",
  "token",
  "access_token",
  "refresh_token",
  "password",
  "secret",
  "api_key",
  "apiKey",
  "private_key",
  "privateKey",
  "ssn",
  "tax_id",
  "taxId",
]);

// --- Validation ---

export function validateApiUrl(raw: string): string {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new Error(`Invalid TRADERNET_API_URL: ${raw}`);
  }
  if (url.protocol !== "https:") {
    throw new Error("API URL must use HTTPS");
  }
  if (!ALLOWED_API_HOSTS.includes(url.hostname)) {
    throw new Error(
      `API URL host must be one of: ${ALLOWED_API_HOSTS.join(", ")}`
    );
  }
  return url.toString().replace(/\/$/, "");
}

// --- Rate Limiter ---

export function createRateLimiter(limits?: { read?: RateLimit; write?: RateLimit }) {
  const calls = new Map<string, number[]>();
  const config = {
    read: limits?.read ?? { maxCalls: 200, windowMs: 60_000 },
    write: limits?.write ?? { maxCalls: 50, windowMs: 60_000 },
  };

  return {
    check(category: "read" | "write"): boolean {
      const now = Date.now();
      const { maxCalls, windowMs } = config[category];
      const history = calls.get(category) ?? [];
      const recent = history.filter((t) => now - t < windowMs);
      if (recent.length >= maxCalls) return false;
      calls.set(category, recent);
      return true;
    },
    record(category: "read" | "write"): void {
      const history = calls.get(category) ?? [];
      history.push(Date.now());
      calls.set(category, history);
    },
  };
}

// --- Response Sanitization ---

export function sanitizeResponse(data: unknown): unknown {
  if (data === null || data === undefined) return data;
  if (Array.isArray(data)) return data.map(sanitizeResponse);
  if (typeof data === "object") {
    const result: Record<string, unknown> = Object.create(null);
    for (const [key, value] of Object.entries(data as Record<string, unknown>)) {
      if (SENSITIVE_KEYS.has(key)) {
        result[key] = "[REDACTED]";
      } else {
        result[key] = sanitizeResponse(value);
      }
    }
    return result;
  }
  return data;
}

function formatResult(data: unknown): string {
  return JSON.stringify(sanitizeResponse(data), null, 2);
}

// --- Error Sanitization ---

export function sanitizeError(e: unknown): string {
  if (axios.isAxiosError(e)) {
    const status = e.response?.status;
    const statusText = e.response?.statusText;
    if (status) {
      const body = e.response?.data;
      const apiMessage =
        typeof body === "object" &&
        body !== null &&
        typeof (body as Record<string, unknown>).error === "string"
          ? (body as Record<string, unknown>).error
          : null;
      const base = `API request failed: ${status} ${statusText ?? ""}`.trim();
      return apiMessage ? `${base} — ${apiMessage}` : base;
    }
    if (e.code === "ECONNABORTED") {
      return "API request timed out. Please try again.";
    }
    if (e.code === "ENOTFOUND" || e.code === "ECONNREFUSED") {
      return "Could not connect to the Tradernet API. Please check your network.";
    }
    return "API request failed due to a network error.";
  }
  if (e instanceof SyntaxError) {
    return "Invalid input format.";
  }
  if (e instanceof Error) {
    if (e.message.startsWith("Rate limit exceeded")) {
      return e.message;
    }
  }
  return "An unexpected error occurred.";
}

// --- API Client Factory ---

function createApiClient(config: ServerConfig) {
  const rateLimiter = createRateLimiter();

  function generateSignature(data: string): string {
    return crypto
      .createHmac("sha256", config.privateKey)
      .update(data)
      .digest("hex");
  }

  return async function callApi(
    command: TradernetCommand | (string & {}),
    params: Record<string, unknown> = {}
  ): Promise<unknown> {
    const category = WRITE_COMMANDS.has(command) ? "write" : "read";
    if (!rateLimiter.check(category)) {
      throw new Error(
        `Rate limit exceeded for ${category} operations. Please wait before retrying.`
      );
    }

    const timeStamp = Math.floor(Date.now() / 1000).toString();
    const payload = JSON.stringify(params);

    const headers = {
      "Content-Type": "application/json",
      "X-NtApi-PublicKey": config.publicKey,
      "X-NtApi-Timestamp": timeStamp,
      "X-NtApi-Sig": generateSignature(payload + timeStamp),
    };

    const response = await axios.post(
      `${config.apiBase}/${command}`,
      payload,
      { headers, timeout: REQUEST_TIMEOUT_MS }
    );
    rateLimiter.record(category);
    return response.data;
  };
}

// --- Tool Handler Helper ---

type CallApiFn = ReturnType<typeof createApiClient>;

function toolHandler(
  callApi: CallApiFn,
  command: TradernetCommand | (string & {}),
  mapParams?: (args: any) => Record<string, unknown>
) {
  return async (args: any) => {
    try {
      const data = await callApi(command, mapParams ? mapParams(args) : {});
      return { content: [{ type: "text" as const, text: formatResult(data) }] };
    } catch (e: unknown) {
      return {
        content: [{ type: "text" as const, text: `Error: ${sanitizeError(e)}` }],
        isError: true,
      };
    }
  };
}

// --- Tool Registration ---

function registerTools(server: McpServer, callApi: CallApiFn, config: ServerConfig) {

// ==========================================
// Authentication & User Info
// ==========================================

server.tool(
  "get_user_data",
  "Get initial user data (account info, portfolio summary, open positions). This is the primary command to check your account status.",
  {},
  { readOnlyHint: true, destructiveHint: false, openWorldHint: true },
  toolHandler(callApi, "getOPQ")
);

// ==========================================
// Portfolio
// ==========================================

server.tool(
  "get_portfolio",
  "Get current portfolio positions and account balances. Returns account funds, open positions with P&L, market values, and settlement info.",
  {},
  { readOnlyHint: true, destructiveHint: false, openWorldHint: true },
  toolHandler(callApi, "getPositionJson")
);

// ==========================================
// Orders
// ==========================================

server.tool(
  "place_order",
  "Place a new trading order (buy, sell, short, margin). Returns order_id on success.",
  {
    instrument: z
      .string()
      .max(50)
      .describe('Ticker symbol, e.g. "AAPL.US", "SBER", "SIE.EU"'),
    action: z
      .enum(["buy", "buy_margin", "sell", "sell_short"])
      .describe("Order action"),
    order_type: z
      .enum(["market", "limit", "stop", "stop_limit"])
      .describe("Order type"),
    quantity: z.number().int().positive().describe("Number of shares/lots"),
    limit_price: z.number().optional().describe("Limit price (for limit and stop_limit orders)"),
    stop_price: z.number().optional().describe("Stop price (for stop and stop_limit orders)"),
    expiration: z
      .enum(["day", "day_ext", "gtc"])
      .default("day")
      .describe("Order expiration: day, day+extended, or good-till-cancelled"),
  },
  { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
  toolHandler(callApi, "putTradeOrder", ({ instrument, action, order_type, quantity, limit_price, stop_price, expiration }) => {
    const actionMap: Record<string, number> = { buy: 1, buy_margin: 2, sell: 3, sell_short: 4 };
    const typeMap: Record<string, number> = { market: 1, limit: 2, stop: 3, stop_limit: 4 };
    const expMap: Record<string, number> = { day: 1, day_ext: 2, gtc: 3 };
    return {
      instr_name: instrument,
      action_id: actionMap[action],
      order_type_id: typeMap[order_type],
      qty: quantity,
      ...(limit_price !== undefined && { limit_price }),
      ...(stop_price !== undefined && { stop_price }),
      expiration_id: expMap[expiration],
    };
  })
);

server.tool(
  "cancel_order",
  "Cancel an active order by its ID.",
  {
    order_id: z.number().describe("Order ID to cancel"),
  },
  { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: true },
  toolHandler(callApi, "delTradeOrder", ({ order_id }) => ({ order_id }))
);

server.tool(
  "set_stop_loss_take_profit",
  "Set stop-loss and/or take-profit for a position. Pass null to leave unchanged.",
  {
    instrument: z.string().max(50).describe('Ticker symbol, e.g. "AAPL.US"'),
    stop_loss: z.number().nullable().describe("Stop-loss price, or null to skip"),
    take_profit: z.number().nullable().describe("Take-profit price, or null to skip"),
    trailing_stop_percent: z
      .number()
      .nullable()
      .optional()
      .describe("Trailing stop-loss percentage, or null to skip"),
  },
  { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: true },
  toolHandler(callApi, "putStopLoss", ({ instrument, stop_loss, take_profit, trailing_stop_percent }) => ({
    instr_name: instrument,
    stop_loss,
    take_profit,
    stoploss_trailing_percent: trailing_stop_percent ?? null,
  }))
);

// ==========================================
// Market Data & Quotes
// ==========================================

server.tool(
  "get_security_info",
  "Get detailed information about a security/ticker (name, currency, exchange, min step, etc.)",
  {
    ticker: z.string().max(50).describe('Ticker symbol, e.g. "AAPL.US", "SBER"'),
  },
  { readOnlyHint: true, destructiveHint: false, openWorldHint: true },
  toolHandler(callApi, "getSecurityInfo", ({ ticker }) => ({ ticker, sup: true }))
);

server.tool(
  "get_quotes_history",
  "Get historical candlestick (OHLCV) data for a ticker. Returns arrays of high/low/open/close prices with timestamps.",
  {
    ticker: z.string().max(50).describe('Ticker symbol, e.g. "AAPL.US"'),
    timeframe: z
      .enum(["1", "5", "15", "60", "1440"])
      .describe("Candle interval in minutes: 1, 5, 15, 60 (1h), or 1440 (1d)"),
    date_from: z
      .string()
      .max(100)
      .describe('Start date in format "DD.MM.YYYY hh:mm", e.g. "01.01.2025 00:00"'),
    date_to: z
      .string()
      .max(100)
      .describe('End date in format "DD.MM.YYYY hh:mm", e.g. "31.01.2025 23:59"'),
    count: z
      .number()
      .int()
      .default(0)
      .describe("Extra candlesticks beyond the date range (0 = none)"),
  },
  { readOnlyHint: true, destructiveHint: false, openWorldHint: true },
  toolHandler(callApi, "getHloc", ({ ticker, timeframe, date_from, date_to, count }) => ({
    id: ticker,
    timeframe: parseInt(timeframe),
    date_from,
    date_to,
    count,
    intervalMode: "ClosedRay",
  }))
);

server.tool(
  "search_tickers",
  'Search for securities/tickers by name or symbol. Supports market filter with @ syntax, e.g. "AAPL@FIX" for NYSE/NASDAQ.',
  {
    query: z
      .string()
      .max(200)
      .describe(
        'Search text. Use "TICKER@MARKET" to filter by market. Markets: MCX (MICEX), FORTS (derivatives), FIX (NYSE/NASDAQ), EU (Europe), KASE (Kazakhstan)'
      ),
  },
  { readOnlyHint: true, destructiveHint: false, openWorldHint: true },
  toolHandler(callApi, "tickerFinder", ({ query }) => ({ text: query }))
);

// ==========================================
// Quotes
// ==========================================

server.tool(
  "get_quote",
  "Get current price, bid, ask, volume and other real-time quote data for one or more tickers.",
  {
    tickers: z.string().max(500).describe('Comma-separated tickers, e.g. "AAPL.US,MSFT.US"'),
  },
  { readOnlyHint: true, destructiveHint: false, openWorldHint: true },
  toolHandler(callApi, "getStockQuotesJson", ({ tickers }) => ({
    tickers: tickers.split(",").map((t: string) => t.trim()),
  }))
);

// ==========================================
// Orders & Trades
// ==========================================

server.tool(
  "get_orders",
  "Get current/active orders. Returns order list with status, type, price, quantity.",
  {
    active_only: z.boolean().default(true).describe("Show only active orders"),
  },
  { readOnlyHint: true, destructiveHint: false, openWorldHint: true },
  toolHandler(callApi, "getNotifyOrderJson", ({ active_only }) => ({
    active_only: active_only ? 1 : 0,
  }))
);

server.tool(
  "get_order_history",
  "Get historical orders for a date range.",
  {
    from: z.string().max(100).describe("Start date in ISO 8601 format"),
    till: z.string().max(100).describe("End date in ISO 8601 format"),
  },
  { readOnlyHint: true, destructiveHint: false, openWorldHint: true },
  toolHandler(callApi, "getOrdersHistory", ({ from, till }) => ({ from, till }))
);

server.tool(
  "get_trades_history",
  "Get executed trades for a date range, optionally filtered by ticker.",
  {
    beginDate: z.string().max(100).describe("Start date in ISO 8601 format"),
    endDate: z.string().max(100).describe("End date in ISO 8601 format"),
    ticker: z.string().max(50).optional().describe("Filter by ticker symbol"),
    max: z.number().int().optional().describe("Max number of results"),
  },
  { readOnlyHint: true, destructiveHint: false, openWorldHint: true },
  toolHandler(callApi, "getTradesHistory", ({ beginDate, endDate, ticker, max }) => ({
    beginDate,
    endDate,
    ...(ticker !== undefined && { nt_ticker: ticker }),
    ...(max !== undefined && { max }),
  }))
);

// ==========================================
// Price Alerts
// ==========================================

server.tool(
  "get_price_alerts",
  "List existing price alerts, optionally filtered by ticker.",
  {
    ticker: z.string().max(50).optional().describe("Filter by ticker, or omit for all"),
  },
  { readOnlyHint: true, destructiveHint: false, openWorldHint: true },
  toolHandler(callApi, "getAlertsList", ({ ticker }) => ({
    ...(ticker !== undefined && { ticker }),
  }))
);

// ==========================================
// Price Alerts (Create/Delete)
// ==========================================

server.tool(
  "add_price_alert",
  "Set a price alert for a ticker. You'll be notified when the price condition is met.",
  {
    ticker: z.string().max(50).describe('Ticker symbol in Tradernet format, e.g. "AAPL.US"'),
    price: z.string().max(50).describe("Target price for the alert"),
    trigger_type: z
      .enum([
        "crossing",
        "crossing_down",
        "crossing_up",
        "less_then",
        "greater_then",
        "channel_in",
        "channel_out",
        "moving_down_from_current",
        "moving_up_from_current",
        "moving_down_from_maximum",
        "moving_up_from_minimum",
      ])
      .describe("When to trigger the alert"),
    quote_type: z
      .enum(["ltp", "bap", "bbp", "op", "pp"])
      .default("ltp")
      .describe(
        "Price basis: ltp (last trade), bap (best bid), bbp (best ask), op (open), pp (close)"
      ),
    notification_type: z
      .enum(["email", "sms", "push", "all"])
      .default("push")
      .describe("How to notify: email, sms, push, or all"),
    alert_period: z
      .enum(["0", "60", "300", "900", "3600", "86400"])
      .default("0")
      .describe("Re-alert frequency in seconds (0 = once)"),
  },
  { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
  toolHandler(callApi, "togglePriceAlert", ({ ticker, price, trigger_type, quote_type, notification_type, alert_period }) => ({
    ticker,
    price: { price },
    trigger_type,
    quote_type,
    notification_type,
    alert_period,
    expire: 0,
  }))
);

server.tool(
  "delete_price_alert",
  "Delete an existing price alert by its ID",
  {
    alert_id: z.number().describe("Alert ID to delete"),
  },
  { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: true },
  toolHandler(callApi, "togglePriceAlert", ({ alert_id }) => ({
    id: alert_id,
    del: true,
    quote_type: "ltp",
    notification_type: "email",
  }))
);

// ==========================================
// Market Info
// ==========================================

server.tool(
  "get_market_status",
  'Check if markets are open or closed. Use "*" for all markets.',
  {
    market: z.string().max(50).default("*").describe('Market code, e.g. "FIX" for NYSE/NASDAQ, "*" for all'),
  },
  { readOnlyHint: true, destructiveHint: false, openWorldHint: true },
  toolHandler(callApi, "getMarketStatus", ({ market }) => ({ market }))
);

server.tool(
  "get_exchange_rates",
  "Get currency exchange rates for a base currency against one or more target currencies.",
  {
    base_currency: z.string().max(10).describe('Base currency code, e.g. "USD"'),
    currencies: z.string().max(200).describe('Comma-separated target currency codes, e.g. "EUR,GBP,RUB"'),
    date: z.string().max(20).optional().describe("Date in ISO 8601 format, or omit for latest"),
  },
  { readOnlyHint: true, destructiveHint: false, openWorldHint: true },
  toolHandler(callApi, "getCrossRatesForDate", ({ base_currency, currencies, date }) => ({
    base_currency,
    currencies: currencies.split(",").map((c: string) => c.trim()),
    ...(date !== undefined && { date }),
  }))
);

server.tool(
  "get_news",
  "Get news feed, optionally filtered by ticker or search term.",
  {
    ticker: z.string().max(50).optional().describe("Filter by ticker symbol"),
    query: z.string().max(200).optional().describe("Search term to filter news"),
    limit: z.number().int().default(10).describe("Max number of news items to return"),
  },
  { readOnlyHint: true, destructiveHint: false, openWorldHint: true },
  toolHandler(callApi, "getNews", ({ ticker, query, limit }) => ({
    ...(ticker !== undefined && { ticker }),
    ...(query !== undefined && { searchFor: query }),
    limit,
  }))
);

server.tool(
  "get_top_securities",
  "Get most traded or top gaining/losing securities for a given market.",
  {
    type: z.enum(["stocks", "bonds", "futures", "funds", "indexes"]).describe("Security type"),
    exchange: z.enum(["usa", "europe", "kazakhstan", "currencies"]).describe("Exchange/market"),
    gainers: z.boolean().default(true).describe("true = top gainers, false = top losers"),
    limit: z.number().int().default(10).describe("Max number of results"),
  },
  { readOnlyHint: true, destructiveHint: false, openWorldHint: true },
  toolHandler(callApi, "getTopSecurities", ({ type, exchange, gainers, limit }) => ({
    type,
    exchange,
    gainers: gainers ? 1 : 0,
    limit,
  }))
);

// ==========================================
// Security Sessions
// ==========================================

server.tool(
  "get_security_sessions",
  "Get list of currently open security sessions (for two-factor authentication operations)",
  {},
  { readOnlyHint: true, destructiveHint: false, openWorldHint: true },
  toolHandler(callApi, "getSecuritySessions")
);

// ==========================================
// Raw API Call (opt-in via TRADERNET_ENABLE_RAW_API=true)
// ==========================================

if (config.enableRawApi) {
  server.tool(
    "raw_api_call",
    "Make a raw API call to any Tradernet command. Use this for commands not covered by other tools.",
    {
      command: z
        .string()
        .max(100)
        .regex(/^[a-zA-Z][a-zA-Z0-9_]*$/, "Invalid command name")
        .describe("API command name"),
      params: z
        .string()
        .max(10_000)
        .default("{}")
        .describe("JSON string of parameters"),
    },
    { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
    async ({ command, params }) => {
      try {
        const parsed = JSON.parse(params);
        const data = await callApi(command, parsed);
        return { content: [{ type: "text" as const, text: formatResult(data) }] };
      } catch (e: unknown) {
        return {
          content: [{ type: "text" as const, text: `Error: ${sanitizeError(e)}` }],
          isError: true,
        };
      }
    }
  );
}

} // end registerTools

// --- Server Factory ---

export function createSandboxServer(overrides?: Partial<ServerConfig>) {
  const config: ServerConfig = {
    publicKey: overrides?.publicKey ?? process.env.TRADERNET_PUBLIC_KEY ?? "",
    privateKey: overrides?.privateKey ?? process.env.TRADERNET_PRIVATE_KEY ?? "",
    apiBase: overrides?.apiBase ?? validateApiUrl(process.env.TRADERNET_API_URL ?? "https://tradernet.com/api"),
    enableRawApi: overrides?.enableRawApi ?? process.env.TRADERNET_ENABLE_RAW_API === "true",
  };

  const server = new McpServer({ name: "tradernet", version: VERSION });
  const callApi = createApiClient(config);
  registerTools(server, callApi, config);
  return server;
}

// --- Start Server (only when run directly) ---

async function main() {
  const publicKey = process.env.TRADERNET_PUBLIC_KEY ?? "";
  const privateKey = process.env.TRADERNET_PRIVATE_KEY ?? "";

  if (!publicKey || !privateKey) {
    console.error(
      "FATAL: TRADERNET_PUBLIC_KEY and TRADERNET_PRIVATE_KEY environment variables are required."
    );
    process.exit(1);
  }

  const config: ServerConfig = {
    publicKey,
    privateKey,
    apiBase: validateApiUrl(process.env.TRADERNET_API_URL ?? "https://tradernet.com/api"),
    enableRawApi: process.env.TRADERNET_ENABLE_RAW_API === "true",
  };

  const server = new McpServer({ name: "tradernet", version: VERSION });
  const callApi = createApiClient(config);
  registerTools(server, callApi, config);

  const transport = new StdioServerTransport();
  await server.connect(transport);
}

const isDirectRun =
  process.argv[1] &&
  (process.argv[1].endsWith("/index.js") ||
    process.argv[1].endsWith("/index.ts") ||
    process.argv[1].endsWith("tradernet-mcp"));

if (isDirectRun) {
  main().catch((err) => {
    console.error("Server failed to start:", err);
    process.exit(1);
  });
}
