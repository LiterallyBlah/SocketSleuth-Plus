package socketsleuth.scanner.checks.active;

import burp.api.montoya.MontoyaApi;
import socketsleuth.scanner.AbstractActiveCheck;
import socketsleuth.scanner.ScanCheckCategory;
import socketsleuth.scanner.ScanContext;
import socketsleuth.scanner.ScanFinding;
import socketsleuth.scanner.ScanSeverity;
import socketsleuth.scanner.payloads.PayloadGenerator;
import socketsleuth.scanner.utils.MessageParser;
import socketsleuth.scanner.utils.MessageParser.InjectedMessage;
import socketsleuth.scanner.utils.ResponseAnalyzer;

import java.util.ArrayList;
import java.util.List;

/**
 * Active check for SQL Injection vulnerabilities in WebSocket messages.
 * Sends SQL injection payloads and analyzes responses for error indicators.
 */
public class SQLInjectionCheck extends AbstractActiveCheck {

    private static final String REMEDIATION = 
            "Implement proper SQL injection defenses:\n\n" +
            "1. Use parameterized queries (prepared statements) for all database operations\n" +
            "2. Apply input validation and sanitization on all user inputs\n" +
            "3. Use an ORM or query builder that handles escaping automatically\n" +
            "4. Implement least privilege database accounts\n" +
            "5. Enable Web Application Firewall (WAF) rules for SQL injection";

    public SQLInjectionCheck(MontoyaApi api) {
        super(api);
    }

    @Override
    public String getId() {
        return "active-sql-injection";
    }

    @Override
    public String getName() {
        return "SQL Injection (Active)";
    }

    @Override
    public String getDescription() {
        return "Actively tests for SQL injection vulnerabilities by sending SQL payloads " +
               "through WebSocket messages and analyzing responses for error indicators.";
    }

    @Override
    public ScanCheckCategory getCategory() {
        return ScanCheckCategory.INJECTION;
    }

    @Override
    public List<ScanFinding> runCheck(ScanContext context) {
        List<ScanFinding> findings = new ArrayList<>();

        // Get a template message to work with
        String templateMessage = getLastOutgoingMessage(context);
        if (templateMessage == null || templateMessage.isEmpty()) {
            log("No outgoing messages found to use as template");
            return findings;
        }

        // Find injection points
        List<MessageParser.InjectionPoint> injectionPoints = 
                MessageParser.findInjectionPoints(templateMessage);
        
        if (injectionPoints.isEmpty()) {
            log("No injection points found in message");
            return findings;
        }

        log("Found " + injectionPoints.size() + " injection points, testing SQL injection...");

        // Get SQL payloads
        List<String> payloads = PayloadGenerator.getSqlErrorPayloads();

        // Test each injection point with a subset of payloads
        for (MessageParser.InjectionPoint point : injectionPoints) {
            if (isCancelled()) break;

            // Use first few payloads to avoid being too noisy
            List<String> testPayloads = payloads.subList(0, Math.min(5, payloads.size()));
            
            for (String payload : testPayloads) {
                if (isCancelled()) break;

                // Create injected message
                String injectedMessage = MessageParser.injectPayload(templateMessage, point, 
                        point.getOriginalValue() + payload);

                // Send and get response
                String response = sendAndWaitForResponse(context, injectedMessage, DEFAULT_TIMEOUT_MS);

                if (response == null) {
                    continue;
                }

                // Analyze response for SQL errors
                ResponseAnalyzer.AnalysisResult result = 
                        ResponseAnalyzer.analyzeSqlInjection(response);

                if (result.isVulnerable()) {
                    findings.add(createFinding("SQL Injection in Parameter: " + point.getParamName(), context)
                            .severity(ScanSeverity.CRITICAL)
                            .description(
                                    "A SQL injection vulnerability was detected in the WebSocket message. " +
                                    "The parameter '" + point.getParamName() + "' appears to be vulnerable " +
                                    "to SQL injection attacks.\n\n" +
                                    "The server returned a SQL error message in response to the injected payload, " +
                                    "indicating that user input is being incorporated into SQL queries without " +
                                    "proper sanitization or parameterization.\n\n" +
                                    "This vulnerability could allow an attacker to:\n" +
                                    "- Access or modify database contents\n" +
                                    "- Bypass authentication mechanisms\n" +
                                    "- Execute administrative operations on the database\n" +
                                    "- In some cases, execute commands on the database server")
                            .evidence(String.format(
                                    "Parameter: %s\nOriginal Value: %s\nPayload: %s\n\nSQL Error Detected:\n%s",
                                    point.getParamName(), point.getOriginalValue(), payload, result.getEvidence()))
                            .remediation(REMEDIATION)
                            .request(truncateForDisplay(injectedMessage))
                            .response(truncateForDisplay(response))
                            .build());

                    // Found vulnerability for this parameter, skip remaining payloads
                    break;
                }

                // Small delay between payloads
                sleepWithCancellation(DEFAULT_DELAY_MS);
            }
        }

        // If no error-based findings, try time-based detection
        if (findings.isEmpty() && !isCancelled()) {
            findings.addAll(testTimeBasedInjection(context, templateMessage, injectionPoints));
        }

        return findings;
    }

    /**
     * Tests for time-based blind SQL injection.
     */
    private List<ScanFinding> testTimeBasedInjection(ScanContext context, 
            String templateMessage, List<MessageParser.InjectionPoint> injectionPoints) {
        
        List<ScanFinding> findings = new ArrayList<>();
        List<String> timePayloads = PayloadGenerator.getSqlTimeBasedPayloads();

        // Only test first injection point for time-based (it's slow)
        if (injectionPoints.isEmpty() || timePayloads.isEmpty()) {
            return findings;
        }

        MessageParser.InjectionPoint point = injectionPoints.get(0);
        
        // First, get baseline response time
        long baselineTime = measureResponseTime(context, templateMessage);
        if (baselineTime < 0) {
            return findings;
        }

        log("Baseline response time: " + baselineTime + "ms, testing time-based SQL injection...");

        // Test with time-based payloads (only first 2 to avoid long scan times)
        for (int i = 0; i < Math.min(2, timePayloads.size()); i++) {
            if (isCancelled()) break;

            String payload = timePayloads.get(i);
            String injectedMessage = MessageParser.injectPayload(templateMessage, point, 
                    point.getOriginalValue() + payload);

            long startTime = System.currentTimeMillis();
            String response = sendAndWaitForResponse(context, injectedMessage, 10000); // Longer timeout
            long responseTime = System.currentTimeMillis() - startTime;

            // Check if response was significantly delayed (5+ seconds more than baseline)
            if (ResponseAnalyzer.analyzeTimingDifference(baselineTime, responseTime, 4000)) {
                findings.add(createFinding("Blind SQL Injection (Time-Based) in Parameter: " + 
                        point.getParamName(), context)
                        .severity(ScanSeverity.HIGH)
                        .description(
                                "A potential time-based blind SQL injection vulnerability was detected. " +
                                "The parameter '" + point.getParamName() + "' caused a significant delay " +
                                "in the server response when a time-delay SQL payload was injected.\n\n" +
                                "Time-based blind SQL injection occurs when user input is incorporated " +
                                "into SQL queries but errors are not visible. The attacker can infer " +
                                "information by observing response timing differences.")
                        .evidence(String.format(
                                "Parameter: %s\nPayload: %s\nBaseline Response Time: %dms\n" +
                                "Injected Response Time: %dms\nDifference: %dms",
                                point.getParamName(), payload, baselineTime, responseTime, 
                                responseTime - baselineTime))
                        .remediation(REMEDIATION)
                        .request(truncateForDisplay(injectedMessage))
                        .response(response != null ? truncateForDisplay(response) : "Response received after delay")
                        .build());

                break; // Found vulnerability
            }

            sleepWithCancellation(DEFAULT_DELAY_MS);
        }

        return findings;
    }

    /**
     * Measures baseline response time.
     */
    private long measureResponseTime(ScanContext context, String message) {
        long startTime = System.currentTimeMillis();
        String response = sendAndWaitForResponse(context, message, DEFAULT_TIMEOUT_MS);
        if (response == null) {
            return -1;
        }
        return System.currentTimeMillis() - startTime;
    }
}
