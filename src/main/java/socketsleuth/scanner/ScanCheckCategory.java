package socketsleuth.scanner;

/**
 * Categories of security checks for WebSocket scanning.
 */
public enum ScanCheckCategory {
    CSWSH("Cross-Site WebSocket Hijacking"),
    AUTHORIZATION("Authorization/Authentication"),
    INJECTION("Injection Attacks"),
    MISCONFIGURATION("Misconfiguration"),
    DOS("Denial of Service");

    private final String displayName;

    ScanCheckCategory(String displayName) {
        this.displayName = displayName;
    }

    public String getDisplayName() {
        return displayName;
    }

    @Override
    public String toString() {
        return displayName;
    }
}
