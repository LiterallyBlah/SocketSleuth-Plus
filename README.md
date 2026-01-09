# SocketSleuth+

> Enhanced WebSocket testing for Burp Suite

## About

**SocketSleuth+** is an enhanced fork of [Snyk's SocketSleuth](https://github.com/snyk/socketsleuth), designed to make WebSocket security testing more intuitive and powerful. This extension provides comprehensive WebSocket testing capabilities including a dedicated history tab, match and replace rules, an Intruder-like utility for fuzzing, and an AutoRepeater for authorization testing.

### What's New in SocketSleuth+

This fork introduces significant UI/UX improvements and new features over the original:

**UI/UX Improvements:**
- Message filtering panel with text search, regex support, and direction filtering
- Visual direction arrows (→ outgoing, ← incoming) instead of text labels
- Color-coded connection status indicators (green/red dots)
- Table sorting now enabled across all message tables
- Improved layout with proportional split panes

**New Results Windows (Burp-style):**
- Dedicated WS Intruder attack results window with:
  - Progress bar and cancel button
  - Split view (message table + message editor)
  - Real-time request counter
- Dedicated JSONRPC Discovery results window with:
  - Discovered methods list with request/response viewer
  - All messages tab with filtering

**Improved Attack Execution:**
- Progress tracking during attacks
- Graceful cancellation support
- Better message tracking and display

## Features

- **WebSocket History** - Comprehensive logging of all WebSocket messages
- **WebSocket Intruder** - Fuzz WebSocket messages with payloads
  - JSONRPC method discovery
  - Sniper attack type
    - Simple List payloads
    - Numeric payloads
- **WebSocket AutoRepeater** - Automatically replay messages for AuthZ testing
  - Similar to AutoRepeater and Autorize but for WebSockets
  - Replay source socket messages to a target socket
  - Ideal for testing authorization with two different sessions
- **Interception Rules** - Control which messages are intercepted
- **Match & Replace Rules** - Modify WebSocket messages on the fly
  - Basic string matching
  - Hex encoded string (useful for non-string payloads)
  - Regex patterns

## Build Instructions

### Requirements
- Burp Suite Professional / Community version 2022.9.5 or later
- Maven

### Steps

1. Clone the repository
   ```
   git clone https://github.com/LiterallyBlah/SocketSleuth-Plus.git
   ```
2. Navigate to the project directory
   ```
   cd socketsleuth-plus
   ```
3. Build the project using Maven
   ```
   mvn clean package
   ```
4. Load the generated JAR file (`target/SocketSleuth-[VERSION]-jar-with-dependencies.jar`) into Burp Suite via `Extensions -> Installed -> Add`.

## Known Issues

For an updated list of bugs and issues, see the project issues. Current known limitations:

- Currently only supports text-based WebSockets. Binary message support requires additional refactoring.
- Regular Expression Match & Replace rules can be inconsistent in some edge cases.

## Credits

SocketSleuth+ is built upon the excellent foundation of [SocketSleuth](https://github.com/snyk/socketsleuth) originally developed by [Snyk](https://snyk.io/). We are grateful for their contribution to the security community.

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

## License

SocketSleuth+ is under the Apache 2.0 License. See [LICENSE](LICENSE) for more information.

Original work Copyright 2023 Snyk Ltd. Modifications and enhancements by the SocketSleuth+ contributors.
