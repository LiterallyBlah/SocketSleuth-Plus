/*
 * © 2023 Snyk Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package socketsleuth.scanner;

import burp.api.montoya.MontoyaApi;

import java.util.ArrayList;
import java.util.List;

/**
 * Abstract base class for scanner checks providing common functionality.
 */
public abstract class AbstractScannerCheck implements IScannerCheck {

    protected final MontoyaApi api;

    protected AbstractScannerCheck(MontoyaApi api) {
        this.api = api;
    }

    /**
     * Create a new finding builder pre-populated with this check's category.
     */
    protected ScanFinding.Builder createFinding(String title) {
        return new ScanFinding.Builder()
                .title(title)
                .category(getCategory());
    }

    /**
     * Create a finding builder from the scan context with URL pre-populated.
     */
    protected ScanFinding.Builder createFinding(String title, ScanContext context) {
        return createFinding(title)
                .url(context.getUrl())
                .socketId(context.getSocketId());
    }

    /**
     * Log a message to Burp's output.
     */
    protected void log(String message) {
        api.logging().logToOutput("[Scanner:" + getId() + "] " + message);
    }

    /**
     * Log an error to Burp's error output.
     */
    protected void logError(String message) {
        api.logging().logToError("[Scanner:" + getId() + "] " + message);
    }

    /**
     * Log an error with exception to Burp's error output.
     */
    protected void logError(String message, Throwable t) {
        api.logging().logToError("[Scanner:" + getId() + "] " + message + ": " + t.getMessage());
    }

    /**
     * Helper to create an empty findings list.
     */
    protected List<ScanFinding> noFindings() {
        return new ArrayList<>();
    }

    /**
     * Helper to create a single-item findings list.
     */
    protected List<ScanFinding> singleFinding(ScanFinding finding) {
        List<ScanFinding> findings = new ArrayList<>();
        findings.add(finding);
        return findings;
    }

    /**
     * Check if the scan has been cancelled.
     * Checks should call this periodically during long operations.
     */
    protected boolean isCancelled() {
        return Thread.currentThread().isInterrupted();
    }

    /**
     * Sleep for the specified duration, respecting cancellation.
     *
     * @param millis Duration to sleep in milliseconds
     * @return true if sleep completed, false if interrupted
     */
    protected boolean sleepWithCancellation(long millis) {
        try {
            Thread.sleep(millis);
            return true;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return false;
        }
    }
}
