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

import java.util.List;

/**
 * Interface for WebSocket scanner checks.
 * Each check implementation detects a specific vulnerability type.
 */
public interface IScannerCheck {

    /**
     * Unique identifier for this check.
     * Used for configuration and logging.
     */
    String getId();

    /**
     * Display name shown in the UI.
     */
    String getName();

    /**
     * Description of what this check detects.
     */
    String getDescription();

    /**
     * Category for grouping related checks.
     */
    ScanCheckCategory getCategory();

    /**
     * Returns true if this check only analyzes existing data (no payloads sent).
     * Passive checks are safe to run and don't modify state.
     */
    boolean isPassive();

    /**
     * Run the check and return any findings.
     *
     * @param context The scan context containing all data needed for analysis
     * @return List of findings discovered by this check (empty list if none)
     */
    List<ScanFinding> runCheck(ScanContext context);

    /**
     * Check if this check is applicable to the target.
     * Override to skip checks that don't apply to certain targets.
     *
     * @param context The scan context
     * @return true if this check should run, false to skip
     */
    default boolean isApplicable(ScanContext context) {
        return true;
    }

    /**
     * Estimated time to run this check in milliseconds.
     * Used for progress estimation.
     */
    default int getEstimatedDuration() {
        return isPassive() ? 100 : 1000;
    }
}
