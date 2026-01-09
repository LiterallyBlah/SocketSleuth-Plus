package socketsleuth.scanner.checks.active;

import burp.api.montoya.MontoyaApi;
import socketsleuth.scanner.AbstractActiveCheck;
import socketsleuth.scanner.ScanCheckCategory;
import socketsleuth.scanner.ScanContext;
import socketsleuth.scanner.ScanFinding;
import socketsleuth.scanner.ScanSeverity;
import socketsleuth.scanner.payloads.PayloadGenerator;
import socketsleuth.scanner.utils.MessageParser;
import socketsleuth.scanner.utils.ResponseAnalyzer;

import java.util.ArrayList;
import java.util.List;

/**
 * Active check for NoSQL Injection vulnerabilities in WebSocket messages.
 * Tests for MongoDB, CouchDB, and other NoSQL injection vectors.
 */
public class NoSQLInjectionCheck extends AbstractActiveCheck {

    private static final String REMEDIATION = 
            "Implement proper NoSQL injection defenses:\n\n" +
            "1. Use typed query builders instead of string concatenation\n" +
            "2. Validate and sanitize all user inputs before using in queries\n" +
            "3. Avoid using $where, $function, and other operators that execute JavaScript\n" +
            "4. Implement strict schema validation\n" +
            "5. Use allowlists for acceptable query operators\n" +
            "6. Encode special characters appropriately for the database being used";

    public NoSQLInjectionCheck(MontoyaApi api) {
        super(api);
    }

    @Override
    public String getId() {
        return "active-nosql-injection";
    }

    @Override
    public String getName() {
        return "NoSQL Injection (Active)";
    }

    @Override
    public String getDescription() {
        return "Actively tests for NoSQL injection vulnerabilities by sending MongoDB/CouchDB " +
               "payloads through WebSocket messages and analyzing responses for error indicators.";
    }

    @Override
    public ScanCheckCategory getCategory() {
        return ScanCheckCategory.INJECTION;
    }

    @Override
    public boolean isApplicable(ScanContext context) {
        if (!super.isApplicable(context)) {
            return false;
        }
        // More applicable if we detect JSON messages
        String template = getLastOutgoingMessage(context);
        return template != null && MessageParser.isJson(template);
    }

    @Override
    public List<ScanFinding> runCheck(ScanContext context) {
        List<ScanFinding> findings = new ArrayList<>();

        String templateMessage = getLastOutgoingMessage(context);
        if (templateMessage == null || templateMessage.isEmpty()) {
            log("No outgoing messages found to use as template");
            return findings;
        }

        // Only test if it looks like JSON
        if (!MessageParser.isJson(templateMessage)) {
            log("Template message is not JSON, skipping NoSQL injection check");
            return findings;
        }

        List<MessageParser.InjectionPoint> injectionPoints = 
                MessageParser.findInjectionPoints(templateMessage);
        
        if (injectionPoints.isEmpty()) {
            log("No injection points found in message");
            return findings;
        }

        log("Found " + injectionPoints.size() + " injection points, testing NoSQL injection...");

        // Get baseline response for comparison
        String baselineResponse = sendAndWaitForResponse(context, templateMessage, DEFAULT_TIMEOUT_MS);

        // Get NoSQL payloads
        List<String> payloads = PayloadGenerator.getMongoDbPayloads();

        for (MessageParser.InjectionPoint point : injectionPoints) {
            if (isCancelled()) break;

            // Test with subset of payloads
            List<String> testPayloads = payloads.subList(0, Math.min(6, payloads.size()));
            
            for (String payload : testPayloads) {
                if (isCancelled()) break;

                // For NoSQL, we often replace the entire value with the payload
                String injectedMessage = MessageParser.injectPayload(templateMessage, point, payload);

                String response = sendAndWaitForResponse(context, injectedMessage, DEFAULT_TIMEOUT_MS);

                if (response == null) {
                    continue;
                }

                // Check for NoSQL error indicators
                ResponseAnalyzer.AnalysisResult result = 
                        ResponseAnalyzer.analyzeNoSqlInjection(response);

                if (result.isVulnerable()) {
                    findings.add(createFinding("NoSQL Injection in Parameter: " + 
                            point.getParamName(), context)
                            .severity(ScanSeverity.CRITICAL)
                            .description(
                                    "A NoSQL injection vulnerability was detected in the WebSocket message. " +
                                    "The parameter '" + point.getParamName() + "' appears to be vulnerable " +
                                    "to NoSQL injection attacks.\n\n" +
                                    "The server returned a NoSQL error message in response to the injected payload, " +
                                    "indicating that user input is being incorporated into NoSQL queries without " +
                                    "proper validation.\n\n" +
                                    "This vulnerability could allow an attacker to:\n" +
                                    "- Bypass authentication by manipulating query operators\n" +
                                    "- Extract data from the database\n" +
                                    "- Modify or delete database records\n" +
                                    "- Execute arbitrary JavaScript on the database server (with $where)")
                            .evidence(String.format(
                                    "Parameter: %s\nOriginal Value: %s\nPayload: %s\n\nNoSQL Error Detected:\n%s",
                                    point.getParamName(), point.getOriginalValue(), payload, result.getEvidence()))
                            .remediation(REMEDIATION)
                            .request(truncateForDisplay(injectedMessage))
                            .response(truncateForDisplay(response))
                            .build());

                    break; // Found vulnerability for this parameter
                }

                // Check for behavior change that might indicate successful injection
                if (baselineResponse != null && 
                    ResponseAnalyzer.responseDiffersSignificantly(baselineResponse, response)) {
                    
                    findings.add(createFinding("Potential NoSQL Injection in Parameter: " + 
                            point.getParamName(), context)
                            .severity(ScanSeverity.MEDIUM)
                            .description(
                                    "A potential NoSQL injection vulnerability was detected. " +
                                    "The parameter '" + point.getParamName() + "' caused a significant " +
                                    "change in the server response when a NoSQL operator payload was injected.\n\n" +
                                    "This behavior change could indicate that the payload modified the database query.")
                            .evidence(String.format(
                                    "Parameter: %s\nPayload: %s\n\nResponse changed significantly from baseline. " +
                                    "Baseline length: %d, Response length: %d",
                                    point.getParamName(), payload, 
                                    baselineResponse.length(), response.length()))
                            .remediation(REMEDIATION)
                            .request(truncateForDisplay(injectedMessage))
                            .response(truncateForDisplay(response))
                            .build());
                }

                sleepWithCancellation(DEFAULT_DELAY_MS);
            }
        }

        return findings;
    }
}
