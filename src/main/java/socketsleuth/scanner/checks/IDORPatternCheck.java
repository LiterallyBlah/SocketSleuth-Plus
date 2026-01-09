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
package socketsleuth.scanner.checks;

import burp.api.montoya.MontoyaApi;
import socketsleuth.scanner.AbstractScannerCheck;
import socketsleuth.scanner.ScanCheckCategory;
import socketsleuth.scanner.ScanContext;
import socketsleuth.scanner.ScanFinding;
import socketsleuth.scanner.ScanSeverity;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Identifies potential Insecure Direct Object Reference (IDOR) patterns in WebSocket messages.
 * This check looks for object identifiers that could be manipulated to access unauthorized resources.
 */
public class IDORPatternCheck extends AbstractScannerCheck {

    // Common IDOR-prone parameter names
    private static final Set<String> IDOR_PARAM_NAMES = new HashSet<>(Arrays.asList(
            "id", "uid", "userid", "user_id", "userId",
            "accountid", "account_id", "accountId",
            "orderid", "order_id", "orderId",
            "docid", "doc_id", "docId", "documentid", "document_id", "documentId",
            "fileid", "file_id", "fileId",
            "recordid", "record_id", "recordId",
            "itemid", "item_id", "itemId",
            "objectid", "object_id", "objectId",
            "messageid", "message_id", "messageId",
            "transactionid", "transaction_id", "transactionId",
            "invoiceid", "invoice_id", "invoiceId",
            "customerid", "customer_id", "customerId",
            "profileid", "profile_id", "profileId",
            "sessionid", "session_id", "sessionId",
            "resourceid", "resource_id", "resourceId"
    ));

    // Pattern to find JSON key-value pairs with ID-like fields
    private static final Pattern JSON_ID_PATTERN = Pattern.compile(
            "\"([^\"]*(?:id|Id|ID)[^\"]*)\"\\s*:\\s*(\\d+|\"[^\"]+\")"
    );

    // Pattern for UUID/GUID
    private static final Pattern UUID_PATTERN = Pattern.compile(
            "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
    );

    // Pattern for MongoDB ObjectId
    private static final Pattern MONGODB_ID_PATTERN = Pattern.compile(
            "[0-9a-fA-F]{24}"
    );

    // Track observed IDs for sequence detection
    private Map<String, List<Long>> observedNumericIds;
    private Set<String> reportedParameters;

    private static final String REMEDIATION = 
            "Implement proper authorization checks for all object references:\n\n" +
            "1. Verify the authenticated user has permission to access the requested resource\n" +
            "2. Use indirect references (mapping user-specific indices to actual IDs)\n" +
            "3. Implement access control lists (ACLs) for resources\n" +
            "4. Log and monitor access patterns for anomaly detection\n" +
            "5. Consider using UUIDs instead of sequential IDs to make enumeration harder";

    public IDORPatternCheck(MontoyaApi api) {
        super(api);
    }

    @Override
    public String getId() {
        return "idor-pattern";
    }

    @Override
    public String getName() {
        return "IDOR Pattern Detection";
    }

    @Override
    public String getDescription() {
        return "Identifies potential Insecure Direct Object Reference (IDOR) patterns " +
               "in WebSocket messages by detecting object identifiers that could be " +
               "manipulated to access unauthorized resources.";
    }

    @Override
    public ScanCheckCategory getCategory() {
        return ScanCheckCategory.AUTHORIZATION;
    }

    @Override
    public boolean isPassive() {
        return true;
    }

    // Store the first message content for each finding type for display
    private Map<String, String> firstMessageForFinding;

    @Override
    public List<ScanFinding> runCheck(ScanContext context) {
        List<ScanFinding> findings = new ArrayList<>();
        observedNumericIds = new HashMap<>();
        reportedParameters = new HashSet<>();
        firstMessageForFinding = new HashMap<>();

        int messageCount = context.getMessageCount();
        
        // First pass: collect all IDs
        for (int i = 0; i < messageCount; i++) {
            if (isCancelled()) {
                break;
            }
            
            Object messageObj = context.getMessage(i);
            if (messageObj == null) {
                continue;
            }

            String messageContent = extractMessageContent(messageObj);
            if (messageContent == null || messageContent.isEmpty()) {
                continue;
            }

            // Analyze message for ID patterns
            analyzeMessage(messageContent, context, findings);
        }

        // Second pass: check for sequential patterns
        checkSequentialPatterns(context, findings);

        return findings;
    }

    private String extractMessageContent(Object messageObj) {
        try {
            java.lang.reflect.Method getMessageMethod = messageObj.getClass().getMethod("getMessage");
            Object result = getMessageMethod.invoke(messageObj);
            if (result != null) {
                return result.toString();
            }
        } catch (Exception e) {
            return messageObj.toString();
        }
        return null;
    }

    private void analyzeMessage(String content, ScanContext context, List<ScanFinding> findings) {
        String truncatedContent = truncateForDisplay(content);
        
        // Check for JSON ID fields
        Matcher jsonMatcher = JSON_ID_PATTERN.matcher(content);
        while (jsonMatcher.find()) {
            String paramName = jsonMatcher.group(1);
            String paramValue = jsonMatcher.group(2).replaceAll("\"", "");
            
            String paramNameLower = paramName.toLowerCase();
            
            // Track numeric IDs for sequence detection
            try {
                long numericValue = Long.parseLong(paramValue);
                observedNumericIds.computeIfAbsent(paramNameLower, k -> new ArrayList<>()).add(numericValue);
                // Store first message for this parameter
                if (!firstMessageForFinding.containsKey("seq-" + paramNameLower)) {
                    firstMessageForFinding.put("seq-" + paramNameLower, truncatedContent);
                }
            } catch (NumberFormatException e) {
                // Not a numeric ID
            }

            // Check if this is a known IDOR-prone parameter
            if (isIdorProneParameter(paramNameLower) && !reportedParameters.contains(paramNameLower)) {
                reportedParameters.add(paramNameLower);
                findings.add(createFinding("Potential IDOR Parameter: " + paramName, context)
                        .severity(ScanSeverity.INFO)
                        .description(
                                "A parameter named '" + paramName + "' was detected in WebSocket messages. " +
                                "This parameter name suggests it may reference a specific resource or object. " +
                                "If the application does not properly validate that the authenticated user " +
                                "has permission to access this resource, it could be vulnerable to " +
                                "Insecure Direct Object Reference (IDOR) attacks.\n\n" +
                                "IDOR vulnerabilities allow attackers to access resources belonging to " +
                                "other users by manipulating these identifier values.")
                        .evidence(String.format("Parameter: %s\nExample value: %s", paramName, paramValue))
                        .remediation(REMEDIATION)
                        .response(truncatedContent)
                        .build());
            }
        }

        // Check for UUIDs
        checkUUIDs(content, context, truncatedContent, findings);

        // Check for MongoDB ObjectIds
        checkMongoDBIds(content, context, truncatedContent, findings);
    }

    private boolean isIdorProneParameter(String paramName) {
        // Direct match
        if (IDOR_PARAM_NAMES.contains(paramName)) {
            return true;
        }
        
        // Check if it ends with common ID suffixes
        return paramName.endsWith("id") || paramName.endsWith("_id") || 
               paramName.endsWith("Id") || paramName.endsWith("ID");
    }

    private void checkUUIDs(String content, ScanContext context, String truncatedContent, List<ScanFinding> findings) {
        Matcher uuidMatcher = UUID_PATTERN.matcher(content);
        Set<String> foundUuids = new HashSet<>();
        
        while (uuidMatcher.find()) {
            foundUuids.add(uuidMatcher.group());
        }

        if (!foundUuids.isEmpty() && !reportedParameters.contains("uuid")) {
            reportedParameters.add("uuid");
            findings.add(createFinding("UUID/GUID References Detected", context)
                    .severity(ScanSeverity.INFO)
                    .description(
                            "UUID/GUID identifiers were detected in WebSocket messages. " +
                            "While UUIDs are harder to enumerate than sequential IDs, they " +
                            "should still be protected with proper authorization checks. " +
                            "If UUIDs are leaked or predictable, IDOR vulnerabilities may still exist.")
                    .evidence(String.format("Found %d unique UUID(s)\nExamples: %s",
                            foundUuids.size(),
                            String.join(", ", limitSet(foundUuids, 3))))
                    .remediation(REMEDIATION)
                    .response(truncatedContent)
                    .build());
        }
    }

    private void checkMongoDBIds(String content, ScanContext context, String truncatedContent, List<ScanFinding> findings) {
        // Only check if content looks like it might contain MongoDB IDs (has JSON structure)
        if (!content.contains("\"_id\"") && !content.contains("\"id\"")) {
            return;
        }

        Matcher mongoMatcher = MONGODB_ID_PATTERN.matcher(content);
        Set<String> foundMongoIds = new HashSet<>();
        
        while (mongoMatcher.find()) {
            String match = mongoMatcher.group();
            // Exclude matches that are clearly not MongoDB IDs (like UUIDs without dashes)
            if (match.length() == 24) {
                foundMongoIds.add(match);
            }
        }

        if (foundMongoIds.size() >= 2 && !reportedParameters.contains("mongodb")) {
            reportedParameters.add("mongodb");
            findings.add(createFinding("MongoDB ObjectId References Detected", context)
                    .severity(ScanSeverity.INFO)
                    .description(
                            "MongoDB ObjectId identifiers were detected in WebSocket messages. " +
                            "These are 24-character hexadecimal strings used as document identifiers. " +
                            "While somewhat random, they contain timestamp information and should " +
                            "be protected with proper authorization checks.")
                    .evidence(String.format("Found %d potential MongoDB ObjectId(s)\nExamples: %s",
                            foundMongoIds.size(),
                            String.join(", ", limitSet(foundMongoIds, 3))))
                    .remediation(REMEDIATION)
                    .response(truncatedContent)
                    .build());
        }
    }

    private void checkSequentialPatterns(ScanContext context, List<ScanFinding> findings) {
        for (Map.Entry<String, List<Long>> entry : observedNumericIds.entrySet()) {
            String paramName = entry.getKey();
            List<Long> ids = entry.getValue();

            if (ids.size() < 3) {
                continue;
            }

            // Check for sequential or near-sequential patterns
            int sequentialCount = 0;
            List<Long> sortedIds = new ArrayList<>(ids);
            sortedIds.sort(Long::compareTo);

            for (int i = 1; i < sortedIds.size(); i++) {
                long diff = sortedIds.get(i) - sortedIds.get(i - 1);
                if (diff >= 1 && diff <= 10) {
                    sequentialCount++;
                }
            }

            // If more than half of the IDs are near-sequential
            if (sequentialCount >= (sortedIds.size() - 1) / 2 && !reportedParameters.contains("seq-" + paramName)) {
                reportedParameters.add("seq-" + paramName);
                ScanFinding.Builder builder = createFinding("Sequential ID Pattern: " + paramName, context)
                        .severity(ScanSeverity.INFO)
                        .description(
                                "Sequential or near-sequential numeric IDs were detected for the '" + 
                                paramName + "' parameter. Sequential IDs make it easy for attackers " +
                                "to enumerate resources by incrementing or decrementing the ID value. " +
                                "This pattern significantly increases the risk of successful IDOR attacks.")
                        .evidence(String.format("Parameter: %s\nObserved IDs: %s\nPattern: Sequential/enumerable",
                                paramName, formatIdList(sortedIds)))
                        .remediation(REMEDIATION + "\n\nConsider using random UUIDs instead of " +
                                "sequential numeric IDs to make enumeration more difficult.");
                
                // Add first message that contained this parameter
                String firstMessage = firstMessageForFinding.get("seq-" + paramName);
                if (firstMessage != null) {
                    builder.response(firstMessage);
                }
                findings.add(builder.build());
            }
        }
    }

    /**
     * Truncates content for display in findings to avoid excessive length.
     */
    private String truncateForDisplay(String content) {
        if (content == null) {
            return null;
        }
        if (content.length() <= 2000) {
            return content;
        }
        return content.substring(0, 2000) + "\n... [truncated, " + (content.length() - 2000) + " more characters]";
    }

    /**
     * Limits a set to the first N elements.
     */
    private Set<String> limitSet(Set<String> set, int limit) {
        Set<String> limited = new HashSet<>();
        int count = 0;
        for (String item : set) {
            if (count >= limit) break;
            limited.add(item);
            count++;
        }
        return limited;
    }

    /**
     * Formats a list of IDs for display.
     */
    private String formatIdList(List<Long> ids) {
        if (ids.size() <= 5) {
            return ids.toString();
        }
        return String.format("[%d, %d, ... %d more ... %d, %d]",
                ids.get(0), ids.get(1), ids.size() - 4,
                ids.get(ids.size() - 2), ids.get(ids.size() - 1));
    }
}
