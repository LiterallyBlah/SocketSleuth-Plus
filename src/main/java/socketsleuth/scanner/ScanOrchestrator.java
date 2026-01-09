package socketsleuth.scanner;

import burp.api.montoya.MontoyaApi;

import javax.swing.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.BiConsumer;
import java.util.function.Consumer;
import java.util.stream.Collectors;

/**
 * Orchestrates the execution of scanner checks with progress tracking and cancellation support.
 */
public class ScanOrchestrator {

    private final MontoyaApi api;
    private final List<IScannerCheck> registeredChecks;
    private volatile boolean cancelled;
    private volatile boolean running;
    private Thread scanThread;

    // Callbacks
    private Consumer<ScanFinding> findingCallback;
    private BiConsumer<Integer, Integer> progressCallback; // current, total
    private Runnable completionCallback;
    private Consumer<String> statusCallback;
    
    // Burp issue reporter
    private BurpIssueReporter burpIssueReporter;

    public ScanOrchestrator(MontoyaApi api) {
        this.api = api;
        this.registeredChecks = new CopyOnWriteArrayList<>();
        this.cancelled = false;
        this.running = false;
    }

    /**
     * Register a check to be run during scans.
     */
    public void registerCheck(IScannerCheck check) {
        registeredChecks.add(check);
        api.logging().logToOutput("[ScanOrchestrator] Registered check: " + check.getName());
    }

    /**
     * Unregister a check.
     */
    public void unregisterCheck(IScannerCheck check) {
        registeredChecks.remove(check);
    }

    /**
     * Get all registered checks.
     */
    public List<IScannerCheck> getRegisteredChecks() {
        return new ArrayList<>(registeredChecks);
    }

    /**
     * Set callback for when a finding is discovered.
     */
    public void setFindingCallback(Consumer<ScanFinding> callback) {
        this.findingCallback = callback;
    }

    /**
     * Set callback for progress updates.
     */
    public void setProgressCallback(BiConsumer<Integer, Integer> callback) {
        this.progressCallback = callback;
    }

    /**
     * Set callback for scan completion.
     */
    public void setCompletionCallback(Runnable callback) {
        this.completionCallback = callback;
    }

    /**
     * Set callback for status updates.
     */
    public void setStatusCallback(Consumer<String> callback) {
        this.statusCallback = callback;
    }

    /**
     * Set the Burp issue reporter for sending findings to Burp's issue panel.
     */
    public void setBurpIssueReporter(BurpIssueReporter reporter) {
        this.burpIssueReporter = reporter;
    }

    /**
     * Check if a scan is currently running.
     */
    public boolean isRunning() {
        return running;
    }

    /**
     * Cancel the current scan.
     */
    public void cancel() {
        cancelled = true;
        if (scanThread != null) {
            scanThread.interrupt();
        }
        updateStatus("Scan cancelled");
    }

    /**
     * Scan mode enumeration.
     */
    public enum ScanMode {
        PASSIVE_ONLY,
        ACTIVE_ONLY,
        FULL_SCAN
    }

    /**
     * Start a scan with the specified context and enabled categories.
     *
     * @param context           The scan context
     * @param enabledCategories Categories to scan (null or empty means all)
     * @param passiveOnly       If true, only run passive checks (legacy parameter)
     */
    public void startScan(ScanContext context, Set<ScanCheckCategory> enabledCategories, boolean passiveOnly) {
        startScan(context, enabledCategories, passiveOnly ? ScanMode.PASSIVE_ONLY : ScanMode.FULL_SCAN);
    }

    /**
     * Start a scan with the specified context, categories, and scan mode.
     *
     * @param context           The scan context
     * @param enabledCategories Categories to scan (null or empty means all)
     * @param scanMode          The scan mode (PASSIVE_ONLY, ACTIVE_ONLY, or FULL_SCAN)
     */
    public void startScan(ScanContext context, Set<ScanCheckCategory> enabledCategories, ScanMode scanMode) {
        if (running) {
            api.logging().logToOutput("[ScanOrchestrator] Scan already running");
            return;
        }

        cancelled = false;
        running = true;

        // Filter checks based on enabled categories and scan mode
        List<IScannerCheck> checksToRun = registeredChecks.stream()
                .filter(check -> enabledCategories == null || enabledCategories.isEmpty() 
                        || enabledCategories.contains(check.getCategory()))
                .filter(check -> filterByScanMode(check, scanMode))
                .filter(check -> check.isApplicable(context))
                .collect(Collectors.toList());

        api.logging().logToOutput("[ScanOrchestrator] Starting scan in " + scanMode + " mode with " + checksToRun.size() + " checks");

        scanThread = new Thread(() -> {
            try {
                runChecks(context, checksToRun);
            } finally {
                running = false;
                SwingUtilities.invokeLater(() -> {
                    if (completionCallback != null) {
                        completionCallback.run();
                    }
                });
            }
        });

        scanThread.setName("WS-Scanner-Thread");
        scanThread.start();
    }

    private void runChecks(ScanContext context, List<IScannerCheck> checks) {
        int total = checks.size();
        int current = 0;

        for (IScannerCheck check : checks) {
            if (cancelled) {
                api.logging().logToOutput("[ScanOrchestrator] Scan cancelled");
                break;
            }

            current++;
            final int progress = current;
            final String checkName = check.getName();

            updateStatus("Running: " + checkName);
            updateProgress(progress, total);

            try {
                api.logging().logToOutput("[ScanOrchestrator] Running check: " + checkName);
                
                List<ScanFinding> findings = check.runCheck(context);
                
                if (findings != null && !findings.isEmpty()) {
                    api.logging().logToOutput("[ScanOrchestrator] Check '" + checkName 
                            + "' found " + findings.size() + " issue(s)");
                    
                    for (ScanFinding finding : findings) {
                        reportFinding(finding);
                    }
                }
            } catch (Exception e) {
                api.logging().logToError("[ScanOrchestrator] Error running check '" + checkName + "': " + e.getMessage());
            }
        }

        if (!cancelled) {
            updateStatus("Scan complete");
            updateProgress(total, total);
        }
    }

    private void reportFinding(ScanFinding finding) {
        // Report to UI callback
        if (findingCallback != null) {
            SwingUtilities.invokeLater(() -> findingCallback.accept(finding));
        }
        // Also report to Burp's issue panel if enabled
        if (burpIssueReporter != null) {
            burpIssueReporter.reportFinding(finding);
        }
    }

    private void updateProgress(int current, int total) {
        if (progressCallback != null) {
            SwingUtilities.invokeLater(() -> progressCallback.accept(current, total));
        }
    }

    private void updateStatus(String status) {
        api.logging().logToOutput("[ScanOrchestrator] " + status);
        if (statusCallback != null) {
            SwingUtilities.invokeLater(() -> statusCallback.accept(status));
        }
    }

    /**
     * Filters a check based on the scan mode.
     */
    private boolean filterByScanMode(IScannerCheck check, ScanMode scanMode) {
        switch (scanMode) {
            case PASSIVE_ONLY:
                return check.isPassive();
            case ACTIVE_ONLY:
                return !check.isPassive();
            case FULL_SCAN:
            default:
                return true;
        }
    }

    /**
     * Get the number of registered checks.
     */
    public int getCheckCount() {
        return registeredChecks.size();
    }

    /**
     * Get checks by category.
     */
    public List<IScannerCheck> getChecksByCategory(ScanCheckCategory category) {
        return registeredChecks.stream()
                .filter(check -> check.getCategory() == category)
                .collect(Collectors.toList());
    }

    /**
     * Get passive checks only.
     */
    public List<IScannerCheck> getPassiveChecks() {
        return registeredChecks.stream()
                .filter(IScannerCheck::isPassive)
                .collect(Collectors.toList());
    }

    /**
     * Get active checks only.
     */
    public List<IScannerCheck> getActiveChecks() {
        return registeredChecks.stream()
                .filter(check -> !check.isPassive())
                .collect(Collectors.toList());
    }
}
