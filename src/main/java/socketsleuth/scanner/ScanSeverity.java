package socketsleuth.scanner;

/**
 * Severity levels for scan findings.
 */
public enum ScanSeverity {
    CRITICAL("Critical", 0),
    HIGH("High", 1),
    MEDIUM("Medium", 2),
    LOW("Low", 3),
    INFO("Informational", 4);

    private final String displayName;
    private final int sortOrder;

    ScanSeverity(String displayName, int sortOrder) {
        this.displayName = displayName;
        this.sortOrder = sortOrder;
    }

    public String getDisplayName() {
        return displayName;
    }

    public int getSortOrder() {
        return sortOrder;
    }

    @Override
    public String toString() {
        return displayName;
    }
}
