package socketsleuth.scanner.checks.active;

import burp.api.montoya.MontoyaApi;
import socketsleuth.scanner.AbstractActiveCheck;
import socketsleuth.scanner.ScanCheckCategory;
import socketsleuth.scanner.ScanContext;
import socketsleuth.scanner.ScanFinding;
import socketsleuth.scanner.ScanSeverity;
import socketsleuth.scanner.utils.ResponseAnalyzer;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Active check for authentication bypass vulnerabilities.
 * Tests if authenticated operations work without proper credentials.
 */
public class AuthBypassCheck extends AbstractActiveCheck {

    private static final String REMEDIATION = 
            "Ensure proper authentication:\n\n" +
            "1. Validate session tokens on every WebSocket message\n" +
            "2. Implement token expiration and refresh mechanisms\n" +
            "3. Reject requests with missing or invalid authentication\n" +
            "4. Don't trust client-supplied authentication state\n" +
            "5. Log authentication failures for monitoring\n" +
            "6. Consider implementing per-message authentication for sensitive operations";

    // Patterns to identify tokens in messages
    private static final Pattern JWT_PATTERN = Pattern.compile(
        "eyJ[A-Za-z0-9_-]+\\.eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+"
    );
    private static final Pattern TOKEN_PARAM_PATTERN = Pattern.compile(
        "\"(token|auth|session|jwt|bearer|apikey|api_key|access_token|accessToken)\"\\s*:\\s*\"([^\"]+)\"",
        Pattern.CASE_INSENSITIVE
    );

    public AuthBypassCheck(MontoyaApi api) {
        super(api);
    }

    @Override
    public String getId() {
        return "active-auth-bypass";
    }

    @Override
    public String getName() {
        return "Authentication Bypass Check (Active)";
    }

    @Override
    public String getDescription() {
        return "Tests for authentication bypass vulnerabilities by removing or " +
               "invalidating authentication tokens in WebSocket messages.";
    }

    @Override
    public ScanCheckCategory getCategory() {
        return ScanCheckCategory.AUTHORIZATION;
    }

    @Override
    public int getEstimatedDuration() {
        return 15000; // Auth checks may take longer due to multiple tests
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

            // Get baseline response with valid auth
            String baselineResponse = sendAndWaitForResponse(context, templateMessage, DEFAULT_TIMEOUT_MS);
            if (baselineResponse == null) continue;

            // Test 1: Remove token parameters from message
            findings.addAll(testTokenRemoval(context, templateMessage, baselineResponse));

            // Test 2: Replace tokens with invalid values
            findings.addAll(testInvalidTokens(context, templateMessage, baselineResponse));

            // Test 3: Check if message contains embedded JWTs
            findings.addAll(testJwtManipulation(context, templateMessage, baselineResponse));
        }

        return findings;
    }

    /**
     * Tests removing token parameters from the message.
     */
    private List<ScanFinding> testTokenRemoval(ScanContext context, String message, String baseline) {
        List<ScanFinding> findings = new ArrayList<>();
        
        Matcher matcher = TOKEN_PARAM_PATTERN.matcher(message);
        while (matcher.find() && !isCancelled()) {
            String paramName = matcher.group(1);
            String tokenValue = matcher.group(2);
            
            // Remove the token (set to empty string)
            String modifiedMessage = message.substring(0, matcher.start(2)) + 
                                    "" + 
                                    message.substring(matcher.end(2));

            String response = sendAndWaitForResponse(context, modifiedMessage, DEFAULT_TIMEOUT_MS);
            if (response == null) continue;

            // Check if we still got a successful response
            boolean hasError = ResponseAnalyzer.containsGenericError(response);
            boolean hasAuthError = containsAuthError(response);
            boolean responseSimilar = !ResponseAnalyzer.responseDiffersSignificantly(baseline, response);

            if (!hasError && !hasAuthError && responseSimilar) {
                findings.add(createFinding(
                    "Authentication Bypass: Missing " + paramName, context)
                    .severity(ScanSeverity.CRITICAL)
                    .description(
                        "An authentication bypass vulnerability was detected.\n\n" +
                        "When the '" + paramName + "' authentication token was removed from the " +
                        "WebSocket message, the server still processed the request successfully " +
                        "without returning an authentication error.\n\n" +
                        "This indicates the server may not be properly validating authentication " +
                        "tokens on WebSocket messages.")
                    .evidence(String.format(
                        "Parameter removed: %s\nOriginal token length: %d chars\n\n" +
                        "Server accepted the request without the authentication token.",
                        paramName, tokenValue.length()))
                    .remediation(REMEDIATION)
                    .request(truncateForDisplay(modifiedMessage))
                    .response(truncateForDisplay(response))
                    .build());
            }

            sleepWithCancellation(DEFAULT_DELAY_MS);
        }
        
        return findings;
    }

    /**
     * Tests replacing tokens with invalid values.
     */
    private List<ScanFinding> testInvalidTokens(ScanContext context, String message, String baseline) {
        List<ScanFinding> findings = new ArrayList<>();
        
        Matcher matcher = TOKEN_PARAM_PATTERN.matcher(message);
        while (matcher.find() && !isCancelled()) {
            String paramName = matcher.group(1);
            
            // Replace with obviously invalid token
            String[] invalidTokens = {"invalid", "null", "undefined", "test123", ""};
            
            for (String invalidToken : invalidTokens) {
                if (isCancelled()) break;
                
                String modifiedMessage = message.substring(0, matcher.start(2)) + 
                                        invalidToken + 
                                        message.substring(matcher.end(2));

                String response = sendAndWaitForResponse(context, modifiedMessage, DEFAULT_TIMEOUT_MS);
                if (response == null) continue;

                boolean hasAuthError = containsAuthError(response);
                boolean responseSimilar = !ResponseAnalyzer.responseDiffersSignificantly(baseline, response);

                if (!hasAuthError && responseSimilar) {
                    findings.add(createFinding(
                        "Weak Token Validation: " + paramName, context)
                        .severity(ScanSeverity.HIGH)
                        .description(
                            "Weak authentication token validation was detected.\n\n" +
                            "When the '" + paramName + "' token was replaced with '" + invalidToken + "', " +
                            "the server still processed the request without proper rejection.\n\n" +
                            "This suggests the application may not be properly validating tokens.")
                        .evidence(String.format(
                            "Parameter: %s\nInvalid token used: '%s'\n\n" +
                            "Server accepted the invalid token without error.",
                            paramName, invalidToken))
                        .remediation(REMEDIATION)
                        .request(truncateForDisplay(modifiedMessage))
                        .response(truncateForDisplay(response))
                        .build());
                    
                    break; // Found issue
                }

                sleepWithCancellation(DEFAULT_DELAY_MS / 2);
            }
        }
        
        return findings;
    }

    /**
     * Tests JWT signature manipulation.
     */
    private List<ScanFinding> testJwtManipulation(ScanContext context, String message, String baseline) {
        List<ScanFinding> findings = new ArrayList<>();
        
        Matcher matcher = JWT_PATTERN.matcher(message);
        if (!matcher.find()) {
            return findings; // No JWT in message
        }

        String originalJwt = matcher.group();
        
        // Test with expired/invalid JWT (replace signature with invalid one)
        int lastDot = originalJwt.lastIndexOf('.');
        if (lastDot <= 0) return findings;
        
        String invalidJwt = originalJwt.substring(0, lastDot + 1) + "invalid_signature";
        String modifiedMessage = message.replace(originalJwt, invalidJwt);

        String response = sendAndWaitForResponse(context, modifiedMessage, DEFAULT_TIMEOUT_MS);
        if (response == null) return findings;

        boolean hasAuthError = containsAuthError(response);
        boolean responseSimilar = !ResponseAnalyzer.responseDiffersSignificantly(baseline, response);

        if (!hasAuthError && responseSimilar) {
            findings.add(createFinding(
                "JWT Signature Not Validated", context)
                .severity(ScanSeverity.CRITICAL)
                .description(
                    "JWT signature validation appears to be bypassed.\n\n" +
                    "When the JWT signature was replaced with an invalid value, " +
                    "the server still accepted and processed the token.\n\n" +
                    "This is a critical vulnerability that allows attackers to forge tokens.")
                .evidence("Original JWT length: " + originalJwt.length() + " chars\n" +
                         "Modified signature portion to 'invalid_signature'\n\n" +
                         "Server accepted the tampered JWT.")
                .remediation(REMEDIATION + "\n\n" +
                    "Additionally:\n" +
                    "- Always verify JWT signatures using the correct algorithm\n" +
                    "- Use a well-tested JWT library\n" +
                    "- Check the 'alg' header to prevent algorithm confusion attacks")
                .request(truncateForDisplay(modifiedMessage))
                .response(truncateForDisplay(response))
                .build());
        }
        
        return findings;
    }

    /**
     * Checks if response contains authentication error indicators.
     */
    private boolean containsAuthError(String response) {
        if (response == null) return false;
        String lower = response.toLowerCase();
        return lower.contains("unauthorized") ||
               lower.contains("unauthenticated") ||
               lower.contains("invalid token") ||
               lower.contains("token expired") ||
               lower.contains("authentication failed") ||
               (lower.contains("auth") && lower.contains("error")) ||
               lower.contains("forbidden") ||
               lower.contains("access denied") ||
               lower.contains("401") ||
               lower.contains("403");
    }
}
