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
package socketsleuth.scanner.checks.active;

import burp.api.montoya.MontoyaApi;
import socketsleuth.scanner.AbstractActiveCheck;
import socketsleuth.scanner.ScanCheckCategory;
import socketsleuth.scanner.ScanContext;
import socketsleuth.scanner.ScanFinding;
import socketsleuth.scanner.ScanSeverity;
import socketsleuth.scanner.utils.MessageParser;
import socketsleuth.scanner.utils.MessageParser.InjectionPoint;
import socketsleuth.scanner.utils.ResponseAnalyzer;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * Active check for Broken Object Level Authorization (BOLA/IDOR) vulnerabilities.
 * Tests whether modifying ID parameters allows access to other users' data.
 */
public class BOLACheck extends AbstractActiveCheck {

    private static final String REMEDIATION = 
            "Implement proper authorization checks:\n\n" +
            "1. Always verify the authenticated user owns or has access to the requested resource\n" +
            "2. Don't rely solely on client-supplied IDs - validate ownership server-side\n" +
            "3. Use indirect references (map user-specific indices to actual IDs)\n" +
            "4. Implement access control lists (ACLs) for shared resources\n" +
            "5. Log and monitor access patterns for anomalies\n" +
            "6. Use UUIDs or other non-sequential identifiers to reduce enumeration risk";

    public BOLACheck(MontoyaApi api) {
        super(api);
    }

    @Override
    public String getId() {
        return "active-bola";
    }

    @Override
    public String getName() {
        return "BOLA/IDOR Check (Active)";
    }

    @Override
    public String getDescription() {
        return "Tests for Broken Object Level Authorization by modifying ID parameters " +
               "and checking if unauthorized data access is possible.";
    }

    @Override
    public ScanCheckCategory getCategory() {
        return ScanCheckCategory.AUTHORIZATION;
    }

    @Override
    public int getEstimatedDuration() {
        return 10000; // BOLA checks may take longer
    }

    @Override
    public List<ScanFinding> runCheck(ScanContext context) {
        List<ScanFinding> findings = new ArrayList<>();

        List<String> templateMessages = getTemplateMessages(context);
        if (templateMessages.isEmpty()) {
            log("No messages to test");
            return findings;
        }

        for (String templateMessage : templateMessages) {
            if (isCancelled()) break;
            
            // Find ID parameters specifically
            List<InjectionPoint> idParams = MessageParser.findIdParameters(templateMessage);
            
            if (idParams.isEmpty()) {
                log("No ID parameters found in message");
                continue;
            }

            log("Found " + idParams.size() + " ID parameter(s), testing BOLA...");

            // Get baseline response
            String baselineResponse = sendAndWaitForResponse(context, templateMessage, DEFAULT_TIMEOUT_MS);

            for (InjectionPoint point : idParams) {
                if (isCancelled()) break;

                // Generate modified ID values
                List<String> modifiedIds = generateModifiedIds(point.getOriginalValue());

                for (String modifiedId : modifiedIds) {
                    if (isCancelled()) break;

                    String modifiedMessage = MessageParser.injectPayload(
                        templateMessage, point, modifiedId);

                    String response = sendAndWaitForResponse(context, modifiedMessage, DEFAULT_TIMEOUT_MS);

                    if (response == null) continue;

                    // Analyze: Did we get different data without an error?
                    boolean isDifferentResponse = baselineResponse != null &&
                        ResponseAnalyzer.responseDiffersSignificantly(baselineResponse, response);
                    boolean hasError = ResponseAnalyzer.containsGenericError(response);
                    boolean hasAuthError = containsAuthError(response);

                    if (isDifferentResponse && !hasError && !hasAuthError) {
                        findings.add(createFinding(
                            "Potential BOLA: " + point.getParamName(), context)
                            .severity(ScanSeverity.HIGH)
                            .description(
                                "A potential Broken Object Level Authorization (BOLA/IDOR) " +
                                "vulnerability was detected.\n\n" +
                                "When the '" + point.getParamName() + "' parameter was modified from '" +
                                point.getOriginalValue() + "' to '" + modifiedId + "', " +
                                "the server returned different data without an authorization error.\n\n" +
                                "This may indicate that the application does not properly verify " +
                                "that the authenticated user owns or has access to the requested resource.")
                            .evidence(String.format(
                                "Parameter: %s\nOriginal ID: %s\nModified ID: %s\n\n" +
                                "The response differed significantly without returning an authorization error.",
                                point.getParamName(), point.getOriginalValue(), modifiedId))
                            .remediation(REMEDIATION)
                            .request(truncateForDisplay(modifiedMessage))
                            .response(truncateForDisplay(response))
                            .build());
                        
                        break; // Found issue for this parameter
                    }

                    sleepWithCancellation(DEFAULT_DELAY_MS);
                }
            }
        }

        return findings;
    }

    /**
     * Generates modified ID values to test BOLA.
     */
    private List<String> generateModifiedIds(String originalValue) {
        List<String> ids = new ArrayList<>();
        
        if (MessageParser.isNumericId(originalValue)) {
            long numId = Long.parseLong(originalValue);
            ids.add(String.valueOf(numId + 1));      // Increment
            ids.add(String.valueOf(numId - 1));      // Decrement
            ids.add("1");                             // Common first ID
            ids.add("0");                             // Edge case
            ids.add("999999");                        // Large number
        } else if (MessageParser.isUuid(originalValue)) {
            // Generate a random UUID
            ids.add(UUID.randomUUID().toString());
            // Also try a zeroed UUID
            ids.add("00000000-0000-0000-0000-000000000000");
        } else if (MessageParser.isMongoId(originalValue)) {
            // Generate a different MongoDB-like ID
            ids.add("000000000000000000000001");
            ids.add("aaaaaaaaaaaaaaaaaaaaaaaa");
        } else {
            // String ID - try common variations
            ids.add("admin");
            ids.add("test");
            ids.add("1");
            ids.add(originalValue + "1");
        }
        
        return ids;
    }

    /**
     * Checks if response contains authorization/permission error indicators.
     */
    private boolean containsAuthError(String response) {
        if (response == null) return false;
        String lower = response.toLowerCase();
        return lower.contains("unauthorized") ||
               lower.contains("forbidden") ||
               lower.contains("permission denied") ||
               lower.contains("access denied") ||
               lower.contains("not allowed") ||
               lower.contains("403") ||
               lower.contains("401");
    }
}
