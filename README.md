<p align="center">
  <img src="logo.jpg" alt="Tradernet" width="120" />
</p>

<h1 align="center">Tradernet MCP Server</h1>

<p align="center">
  <a href="https://www.npmjs.com/package/tradernet-mcp"><img src="https://img.shields.io/npm/v/tradernet-mcp" alt="npm version" /></a>
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT" /></a>
</p>

MCP server for the [Tradernet](https://tradernet.com) / [Freedom24](https://freedom24.com) trading platform API. Manage your portfolio, place orders, get quotes, search tickers, set alerts — all through AI assistants like Claude, ChatGPT, and others.

## Available Tools

| Tool | Description |
|------|-------------|
| `get_user_data` | Account info, portfolio summary, open positions |
| `get_portfolio` | Current positions, balances, P&L |
| `get_quote` | Current price, bid, ask, volume for one or more tickers |
| `place_order` | Place buy/sell/short/margin orders (requires confirmation) |
| `cancel_order` | Cancel an active order (requires confirmation) |
| `get_orders` | Current/active orders |
| `get_order_history` | Past orders for a date range |
| `get_trades_history` | Executed trades for a date range |
| `set_stop_loss_take_profit` | Set SL/TP for a position (requires confirmation) |
| `get_security_info` | Ticker details (currency, exchange, min step) |
| `get_quotes_history` | Historical OHLCV candlestick data |
| `search_tickers` | Search securities by name or symbol |
| `add_price_alert` | Set a price alert with notifications |
| `delete_price_alert` | Remove a price alert |
| `get_price_alerts` | List existing price alerts |
| `get_market_status` | Check if markets are open or closed |
| `get_exchange_rates` | Currency exchange rates |
| `get_news` | News feed for a ticker or search term |
| `get_top_securities` | Most traded / top gaining securities |
| `get_security_sessions` | List open security sessions |
| `raw_api_call` | Call any Tradernet API command directly (opt-in, see below) |

## Setup

### 1. Get API Keys

1. Log in to [Tradernet](https://tradernet.com) or [Freedom24](https://freedom24.com)
2. Go to your profile settings
3. Generate API keys (Public Key and Private Key)

### 2. Configure

#### Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "tradernet": {
      "command": "npx",
      "args": ["-y", "tradernet-mcp@1.1.2"],
      "env": {
        "TRADERNET_PUBLIC_KEY": "your_public_key",
        "TRADERNET_PRIVATE_KEY": "your_private_key"
      }
    }
  }
}
```

#### ChatGPT

ChatGPT only supports remote MCP servers over HTTP. To connect this stdio server, use [supergateway](https://github.com/supercorp-ai/supergateway) as a bridge and [ngrok](https://ngrok.com) to expose it publicly:

> **Security Warning:** This setup exposes your trading API over a public URL. Anyone with the URL can execute trades on your account. Use IP restrictions and keep the URL secret. Consider read-only API keys if available.

1. Start the server with HTTP transport:

```bash
TRADERNET_PUBLIC_KEY=your_public_key \
TRADERNET_PRIVATE_KEY=your_private_key \
npx -y supergateway --stdio "npx -y tradernet-mcp@1.1.2" --outputTransport streamableHttp --port 8000
```

2. Expose it via ngrok with IP restrictions:

```bash
ngrok http 8000 --basic-auth "user:password"
```

3. In ChatGPT: **Settings → Connectors → Add Connector**, enter your ngrok URL with `/mcp` path (e.g. `https://abc123.ngrok-free.app/mcp`)

> Requires ChatGPT Pro, Team, or Enterprise plan with Developer Mode enabled.

## Usage Examples

Once connected, you can ask your AI assistant things like:

- "Show my portfolio"
- "What are my open positions?"
- "Buy 10 shares of AAPL"
- "Set stop-loss for SBER at 250"
- "Search for Tesla stock"
- "Show AAPL price history for the last month"
- "Set an alert when MSFT crosses $400"

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `TRADERNET_PUBLIC_KEY` | Yes | Your Tradernet API public key |
| `TRADERNET_PRIVATE_KEY` | Yes | Your Tradernet API private key |
| `TRADERNET_ENABLE_RAW_API` | No | Set to `true` to enable the `raw_api_call` tool (disabled by default, see warning below) |

### Secrets Management

Avoid storing API keys in plaintext in your config files. Use a secrets manager to inject them at runtime:

#### 1Password CLI

Requires the [1Password desktop app](https://1password.com/downloads) with [CLI integration enabled](https://developer.1password.com/docs/cli/get-started/#sign-in) (Settings → Developer → Integrate with 1Password CLI).

```json
{
  "mcpServers": {
    "tradernet": {
      "command": "sh",
      "args": [
        "-c",
        "TRADERNET_PUBLIC_KEY='op://YOUR_VAULT/YOUR_ITEM/public_key' TRADERNET_PRIVATE_KEY='op://YOUR_VAULT/YOUR_ITEM/private_key' op run -- npx -y tradernet-mcp@1.1.2"
      ]
    }
  }
}
```

Replace `YOUR_VAULT` and `YOUR_ITEM` with your actual 1Password vault and item names (e.g. `op://Personal/Tradernet API Key/public_key`). The `op run` command resolves `op://` references from environment variables and injects the secrets into the child process — your keys never touch disk in plaintext.

#### macOS Keychain

```json
{
  "mcpServers": {
    "tradernet": {
      "command": "sh",
      "args": [
        "-c",
        "TRADERNET_PUBLIC_KEY=$(security find-generic-password -s tradernet-public-key -w) TRADERNET_PRIVATE_KEY=$(security find-generic-password -s tradernet-private-key -w) npx -y tradernet-mcp@1.1.2"
      ]
    }
  }
}
```

Add your keys to the keychain first:

```bash
security add-generic-password -s tradernet-public-key -a tradernet -w "your_public_key"
security add-generic-password -s tradernet-private-key -a tradernet -w "your_private_key"
```

### Raw API Call

The `raw_api_call` tool is **disabled by default** and must be explicitly enabled by setting `TRADERNET_ENABLE_RAW_API=true`. This tool allows the AI assistant to call **any** Tradernet API endpoint with arbitrary parameters, bypassing the controlled surface area of the other tools.

> **Warning:** Enabling this tool significantly increases your risk exposure. An LLM influenced by prompt injection (e.g. from a malicious document or webpage) could use it to execute unintended API calls — including operations not covered by the standard tools. Only enable it if you understand the risks and need access to API commands not otherwise available.

## Development

To run the server from a local clone (useful for testing changes before publishing):

```bash
git clone https://github.com/verbart/tradernet-mcp.git
cd tradernet-mcp
npm install
npm run build
```

Then point your MCP client to the local build:

#### Claude Desktop

```json
{
  "mcpServers": {
    "tradernet": {
      "command": "node",
      "args": ["/absolute/path/to/tradernet-mcp/dist/index.js"],
      "env": {
        "TRADERNET_PUBLIC_KEY": "your_public_key",
        "TRADERNET_PRIVATE_KEY": "your_private_key"
      }
    }
  }
}
```

#### Claude Code

```bash
claude mcp add tradernet -- node /absolute/path/to/tradernet-mcp/dist/index.js
```

Then set environment variables `TRADERNET_PUBLIC_KEY` and `TRADERNET_PRIVATE_KEY`.

### Running Tests

```bash
npm install
npx vitest run
```

## API Documentation

This server implements the [Tradernet API](https://tradernet.com/tradernet-api). For the full API reference, see the [official documentation](https://github.com/tradernet/tn.api).

## License

MIT
