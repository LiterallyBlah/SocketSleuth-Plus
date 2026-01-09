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
 * Active check for Command Injection (OS Command Injection) vulnerabilities.
 * Tests for the ability to execute operating system commands through WebSocket input.
 */
public class CommandInjectionCheck extends AbstractActiveCheck {

    private static final String REMEDIATION = 
            "Implement proper command injection defenses:\n\n" +
            "1. Avoid using system commands with user input whenever possible\n" +
            "2. Use parameterized APIs or libraries instead of shell commands\n" +
            "3. If commands are necessary, use strict allowlist validation\n" +
            "4. Escape or sanitize all special characters (;, |, &, $, `, etc.)\n" +
            "5. Run processes with minimal privileges\n" +
            "6. Use language-specific safe execution methods\n" +
            "7. Implement input length limits and format validation";

    public CommandInjectionCheck(MontoyaApi api) {
        super(api);
    }

    @Override
    public String getId() {
        return "active-command-injection";
    }

    @Override
    public String getName() {
        return "Command Injection (Active)";
    }

    @Override
    public String getDescription() {
        return "Actively tests for OS command injection vulnerabilities by sending shell command " +
               "payloads through WebSocket messages and checking for command execution indicators.";
    }

    @Override
    public ScanCheckCategory getCategory() {
        return ScanCheckCategory.INJECTION;
    }

    @Override
    public List<ScanFinding> runCheck(ScanContext context) {
        List<ScanFinding> findings = new ArrayList<>();

        String templateMessage = getLastOutgoingMessage(context);
        if (templateMessage == null || templateMessage.isEmpty()) {
            log("No outgoing messages found to use as template");
            return findings;
        }

        List<MessageParser.InjectionPoint> injectionPoints = 
                MessageParser.findInjectionPoints(templateMessage);
        
        if (injectionPoints.isEmpty()) {
            log("No injection points found in message");
            return findings;
        }

        log("Found " + injectionPoints.size() + " injection points, testing command injection...");

        // Get command payloads (both Unix and Windows)
        List<String> payloads = PayloadGenerator.getAllCommandPayloads();

        for (MessageParser.InjectionPoint point : injectionPoints) {
            if (isCancelled()) break;

            // Test with a subset of payloads (mix of Unix and Windows)
            List<String> testPayloads = selectMixedPayloads(payloads, 8);
            
            for (String payload : testPayloads) {
                if (isCancelled()) break;

                // Append payload to original value
                String injectedMessage = MessageParser.injectPayload(templateMessage, point, 
                        point.getOriginalValue() + payload);

                String response = sendAndWaitForResponse(context, injectedMessage, DEFAULT_TIMEOUT_MS);

                if (response == null) {
                    continue;
                }

                // Check for command execution output
                ResponseAnalyzer.AnalysisResult result = 
                        ResponseAnalyzer.analyzeCommandInjection(response);

                if (result.isVulnerable()) {
                    findings.add(createFinding("Command Injection in Parameter: " + 
                            point.getParamName(), context)
                            .severity(ScanSeverity.CRITICAL)
                            .description(
                                    "A command injection vulnerability was detected in the WebSocket message. " +
                                    "The parameter '" + point.getParamName() + "' appears to be vulnerable " +
                                    "to OS command injection attacks.\n\n" +
                                    "The server response contains output that indicates operating system " +
                                    "commands are being executed with user-supplied input.\n\n" +
                                    "This vulnerability could allow an attacker to:\n" +
                                    "- Execute arbitrary commands on the server\n" +
                                    "- Read, modify, or delete files on the server\n" +
                                    "- Establish a reverse shell for persistent access\n" +
                                    "- Pivot to attack other internal systems\n" +
                                    "- Exfiltrate sensitive data")
                            .evidence(String.format(
                                    "Parameter: %s\nOriginal Value: %s\nPayload: %s\n\n" +
                                    "Command Output Detected:\n%s",
                                    point.getParamName(), point.getOriginalValue(), payload, result.getEvidence()))
                            .remediation(REMEDIATION)
                            .request(truncateForDisplay(injectedMessage))
                            .response(truncateForDisplay(response))
                            .build());

                    break; // Found vulnerability for this parameter
                }

                sleepWithCancellation(DEFAULT_DELAY_MS);
            }
        }

        // Test for time-based blind command injection
        if (findings.isEmpty() && !isCancelled()) {
            findings.addAll(testTimeBasedCommandInjection(context, templateMessage, injectionPoints));
        }

        return findings;
    }

    /**
     * Tests for time-based blind command injection using sleep/timeout commands.
     */
    private List<ScanFinding> testTimeBasedCommandInjection(ScanContext context,
            String templateMessage, List<MessageParser.InjectionPoint> injectionPoints) {
        
        List<ScanFinding> findings = new ArrayList<>();
        
        if (injectionPoints.isEmpty()) {
            return findings;
        }

        MessageParser.InjectionPoint point = injectionPoints.get(0);

        // Get baseline response time
        long baselineTime = measureResponseTime(context, templateMessage);
        if (baselineTime < 0) {
            return findings;
        }

        log("Baseline response time: " + baselineTime + "ms, testing time-based command injection...");

        // Time-based command injection payloads
        String[] timePayloads = {
                "; sleep 5",
                "| sleep 5",
                "$(sleep 5)",
                "& timeout /t 5",
                "| ping -n 5 127.0.0.1"
        };

        for (String payload : timePayloads) {
            if (isCancelled()) break;

            String injectedMessage = MessageParser.injectPayload(templateMessage, point, 
                    point.getOriginalValue() + payload);

            long startTime = System.currentTimeMillis();
            String response = sendAndWaitForResponse(context, injectedMessage, 10000);
            long responseTime = System.currentTimeMillis() - startTime;

            // Check if response was significantly delayed (4+ seconds more than baseline)
            if (ResponseAnalyzer.analyzeTimingDifference(baselineTime, responseTime, 4000)) {
                findings.add(createFinding("Blind Command Injection (Time-Based) in Parameter: " + 
                        point.getParamName(), context)
                        .severity(ScanSeverity.HIGH)
                        .description(
                                "A potential time-based blind command injection vulnerability was detected. " +
                                "The parameter '" + point.getParamName() + "' caused a significant delay " +
                                "in the server response when a time-delay command payload was injected.\n\n" +
                                "This indicates that shell commands may be executed on the server with " +
                                "user-supplied input.")
                        .evidence(String.format(
                                "Parameter: %s\nPayload: %s\nBaseline Response Time: %dms\n" +
                                "Injected Response Time: %dms\nDifference: %dms",
                                point.getParamName(), payload, baselineTime, responseTime, 
                                responseTime - baselineTime))
                        .remediation(REMEDIATION)
                        .request(truncateForDisplay(injectedMessage))
                        .response(response != null ? truncateForDisplay(response) : "Response received after delay")
                        .build());

                break;
            }

            sleepWithCancellation(DEFAULT_DELAY_MS);
        }

        return findings;
    }

    /**
     * Selects a mix of Unix and Windows payloads for testing.
     */
    private List<String> selectMixedPayloads(List<String> allPayloads, int count) {
        List<String> unixPayloads = PayloadGenerator.getUnixCommandPayloads();
        List<String> windowsPayloads = PayloadGenerator.getWindowsCommandPayloads();
        
        List<String> mixed = new ArrayList<>();
        int half = count / 2;
        
        for (int i = 0; i < half && i < unixPayloads.size(); i++) {
            mixed.add(unixPayloads.get(i));
        }
        for (int i = 0; i < half && i < windowsPayloads.size(); i++) {
            mixed.add(windowsPayloads.get(i));
        }
        
        return mixed;
    }

    private long measureResponseTime(ScanContext context, String message) {
        long startTime = System.currentTimeMillis();
        String response = sendAndWaitForResponse(context, message, DEFAULT_TIMEOUT_MS);
        if (response == null) {
            return -1;
        }
        return System.currentTimeMillis() - startTime;
    }
}
