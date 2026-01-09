# SocketSleuth+

> Enhanced WebSocket testing for Burp Suite

## About

**SocketSleuth+** is an enhanced fork of [Snyk's SocketSleuth](https://github.com/snyk/socketsleuth), designed to make WebSocket security testing more intuitive and powerful. This extension provides comprehensive WebSocket testing capabilities including a dedicated history tab, match and replace rules, an Intruder-like utility for fuzzing, an AutoRepeater for authorization testing, and an integrated vulnerability scanner with 13 security checks.

### What's New in SocketSleuth+

This fork introduces significant UI/UX improvements and new features over the original:

**UI/UX Improvements:**
- Message filtering panel with text search, regex support, and direction filtering
- "Unique Only" filter to show only the first occurrence of each message per direction
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
- Dedicated WS Scanner results window with:
  - Findings organized by severity
  - Evidence viewer for each finding
  - Message template selection for targeted scanning

**Improved Attack Execution:**
- Progress tracking during attacks
- Graceful cancellation support
- Better message tracking and display

**Burp Integration:**
- Findings automatically reported to Burp's native Issues panel
- Full AuditIssue integration with severity and confidence mapping
- Findings appear in Burp's sitemap for easy reference

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
- **WebSocket Scanner** - Automated vulnerability detection for WebSocket endpoints
  - See [Scanner Checks](#websocket-scanner-checks) below for details
- **Interception Rules** - Control which messages are intercepted
- **Match & Replace Rules** - Modify WebSocket messages on the fly
  - Basic string matching
  - Hex encoded string (useful for non-string payloads)
  - Regex patterns

## WebSocket Scanner Checks

The WebSocket Scanner includes 13 security checks organized into passive and active categories.

### Passive Checks (Safe - No Payloads Sent)

These checks analyze existing WebSocket traffic without sending any additional messages:

| Check | Category | Description |
|-------|----------|-------------|
| **CSWSH Origin Check** | Cross-Site WebSocket Hijacking | Analyzes WebSocket upgrade requests for missing or weak Origin header validation. Detects potential Cross-Site WebSocket Hijacking vulnerabilities. |
| **Encryption Check** | Misconfiguration | Verifies that WebSocket connections use TLS (wss://) and checks for secure transport configurations. |
| **IDOR Pattern Check** | Authorization | Identifies patterns in messages that may indicate Insecure Direct Object Reference vulnerabilities, such as predictable IDs or resource identifiers. |
| **Token in URL Check** | Misconfiguration | Detects sensitive tokens, API keys, or credentials exposed in WebSocket URLs where they may be logged or leaked. |
| **Verbose Error Check** | Misconfiguration | Analyzes error messages for information disclosure, including stack traces, internal paths, database errors, or debug information. |

### Active Checks (Sends Test Payloads)

These checks actively test for vulnerabilities by sending crafted payloads. **Use with caution on production systems.**

| Check | Category | Description |
|-------|----------|-------------|
| **SQL Injection** | Injection | Tests for SQL injection vulnerabilities using error-based, boolean-based, and time-based payloads. |
| **Command Injection** | Injection | Tests for OS command injection using various shell metacharacters and command separators. |
| **NoSQL Injection** | Injection | Tests for NoSQL injection in MongoDB and similar databases using operator injection and JavaScript payloads. |
| **LDAP Injection** | Injection | Tests for LDAP injection vulnerabilities using wildcard and filter injection payloads. |
| **XPath Injection** | Injection | Tests for XPath injection vulnerabilities in XML processing logic. |
| **XSS Injection** | Injection | Tests for Cross-Site Scripting by injecting various HTML and JavaScript payloads. |
| **BOLA/IDOR Check** | Authorization | Tests for Broken Object Level Authorization by manipulating object identifiers in messages. |
| **Auth Bypass Check** | Authorization | Tests authentication mechanisms by removing tokens, modifying JWT signatures, and testing session handling. |

### Scanner Severity Levels

Findings are categorized by severity:
- **Critical** - Immediate action required
- **High** - Significant security risk
- **Medium** - Moderate security concern
- **Low** - Minor security issue
- **Informational** - Security-relevant observation

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
