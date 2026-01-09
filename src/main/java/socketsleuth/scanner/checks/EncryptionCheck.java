package socketsleuth.scanner.checks;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import socketsleuth.scanner.AbstractScannerCheck;
import socketsleuth.scanner.ScanCheckCategory;
import socketsleuth.scanner.ScanContext;
import socketsleuth.scanner.ScanFinding;
import socketsleuth.scanner.ScanSeverity;

import java.util.List;

/**
 * Detects unencrypted WebSocket connections (ws:// instead of wss://).
 */
public class EncryptionCheck extends AbstractScannerCheck {

    private static final String REMEDIATION = 
            "Use secure WebSocket connections (wss://) instead of unencrypted connections (ws://). " +
            "Configure your server to use TLS/SSL for all WebSocket endpoints. " +
            "Ensure proper certificate configuration and consider implementing HSTS " +
            "to prevent protocol downgrade attacks.";

    public EncryptionCheck(MontoyaApi api) {
        super(api);
    }

    @Override
    public String getId() {
        return "encryption";
    }

    @Override
    public String getName() {
        return "WebSocket Encryption Check";
    }

    @Override
    public String getDescription() {
        return "Checks whether WebSocket connections use encrypted (wss://) or " +
               "unencrypted (ws://) protocols.";
    }

    @Override
    public ScanCheckCategory getCategory() {
        return ScanCheckCategory.MISCONFIGURATION;
    }

    @Override
    public boolean isPassive() {
        return true;
    }

    @Override
    public List<ScanFinding> runCheck(ScanContext context) {
        String url = context.getUrl();
        
        if (url == null || url.isEmpty()) {
            return noFindings();
        }

        // Get the upgrade request for inclusion in findings
        HttpRequest upgradeRequest = context.getUpgradeRequest();
        String requestStr = upgradeRequest != null ? upgradeRequest.toString() : null;

        String urlLower = url.toLowerCase();

        // Check for unencrypted WebSocket (ws:// or http://)
        // Burp may display WebSocket URLs with either ws/wss or http/https schemes
        if (urlLower.startsWith("ws://") || urlLower.startsWith("http://")) {
            String protocol = urlLower.startsWith("ws://") ? "ws://" : "http://";
            ScanFinding.Builder builder = createFinding("Unencrypted WebSocket Connection", context)
                    .severity(ScanSeverity.HIGH)
                    .description(
                            "This WebSocket connection uses an unencrypted protocol. " +
                            "All data transmitted over this connection, including authentication " +
                            "tokens, session data, and sensitive information, is sent in plaintext. " +
                            "This exposes the connection to:\n\n" +
                            "- Eavesdropping: Attackers on the network can read all messages\n" +
                            "- Man-in-the-Middle attacks: Attackers can intercept and modify messages\n" +
                            "- Session hijacking: Authentication tokens can be stolen\n" +
                            "- Data tampering: Message integrity cannot be verified")
                    .evidence("URL: " + url + "\nProtocol: " + protocol + " (unencrypted)")
                    .remediation(REMEDIATION);
            if (requestStr != null) {
                builder.request(requestStr);
            }
            return singleFinding(builder.build());
        }

        // Check for encrypted WebSocket (wss:// or https://) - informational
        if (urlLower.startsWith("wss://") || urlLower.startsWith("https://")) {
            String protocol = urlLower.startsWith("wss://") ? "wss://" : "https://";
            ScanFinding.Builder builder = createFinding("Encrypted WebSocket Connection", context)
                    .severity(ScanSeverity.INFO)
                    .description(
                            "This WebSocket connection uses an encrypted protocol. " +
                            "Data transmitted over this connection is protected by TLS/SSL encryption.")
                    .evidence("URL: " + url + "\nProtocol: " + protocol + " (encrypted)")
                    .remediation("No action required. Continue using encrypted connections.");
            if (requestStr != null) {
                builder.request(requestStr);
            }
            return singleFinding(builder.build());
        }

        // Fallback: unknown URL scheme, use isSecure() helper
        if (!context.isSecure()) {
            ScanFinding.Builder builder = createFinding("WebSocket Connection May Be Unencrypted", context)
                    .severity(ScanSeverity.MEDIUM)
                    .description(
                            "The WebSocket connection may not be using TLS encryption. " +
                            "Unable to determine protocol from URL scheme, but security indicators suggest " +
                            "the connection may not be encrypted.")
                    .evidence("URL: " + url + "\nSecure: false")
                    .remediation(REMEDIATION);
            if (requestStr != null) {
                builder.request(requestStr);
            }
            return singleFinding(builder.build());
        }

        return noFindings();
    }
}
