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
import socketsleuth.scanner.payloads.PayloadGenerator;
import socketsleuth.scanner.utils.MessageParser;
import socketsleuth.scanner.utils.ResponseAnalyzer;

import java.util.ArrayList;
import java.util.List;

/**
 * Active check for Cross-Site Scripting (XSS) vulnerabilities in WebSocket messages.
 * Tests for payload reflection that could lead to script execution.
 */
public class XSSInjectionCheck extends AbstractActiveCheck {

    private static final String REMEDIATION = 
            "Implement proper XSS defenses:\n\n" +
            "1. Output encode all user-supplied data before rendering\n" +
            "   - HTML entity encoding for HTML context\n" +
            "   - JavaScript encoding for JS context\n" +
            "   - URL encoding for URL context\n" +
            "2. Use Content Security Policy (CSP) headers\n" +
            "3. Use HttpOnly and Secure flags on cookies\n" +
            "4. Implement input validation with allowlists\n" +
            "5. Use modern framework features that auto-escape output\n" +
            "6. Sanitize HTML content using a library like DOMPurify";

    public XSSInjectionCheck(MontoyaApi api) {
        super(api);
    }

    @Override
    public String getId() {
        return "active-xss-injection";
    }

    @Override
    public String getName() {
        return "XSS Injection (Active)";
    }

    @Override
    public String getDescription() {
        return "Actively tests for Cross-Site Scripting vulnerabilities by sending XSS payloads " +
               "through WebSocket messages and checking for unescaped reflection in responses.";
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

        log("Found " + injectionPoints.size() + " injection points, testing XSS...");

        // Get XSS payloads
        List<String> basicPayloads = PayloadGenerator.getBasicXssPayloads();
        List<String> eventPayloads = PayloadGenerator.getEventHandlerXssPayloads();

        for (MessageParser.InjectionPoint point : injectionPoints) {
            if (isCancelled()) break;

            // Test with basic XSS payloads first
            boolean foundVuln = testXssPayloads(context, templateMessage, point, basicPayloads, 
                    findings, ScanSeverity.HIGH, "XSS");
            
            // If no basic XSS found, try event handler payloads
            if (!foundVuln && !isCancelled()) {
                testXssPayloads(context, templateMessage, point, eventPayloads, 
                        findings, ScanSeverity.MEDIUM, "DOM-based XSS (Event Handler)");
            }
        }

        return findings;
    }

    /**
     * Tests a set of XSS payloads against an injection point.
     * 
     * @return true if vulnerability was found
     */
    private boolean testXssPayloads(ScanContext context, String templateMessage,
            MessageParser.InjectionPoint point, List<String> payloads,
            List<ScanFinding> findings, ScanSeverity severity, String vulnType) {
        
        // Test with subset of payloads
        List<String> testPayloads = payloads.subList(0, Math.min(5, payloads.size()));
        
        for (String payload : testPayloads) {
            if (isCancelled()) break;

            // Replace value with payload
            String injectedMessage = MessageParser.injectPayload(templateMessage, point, payload);

            String response = sendAndWaitForResponse(context, injectedMessage, DEFAULT_TIMEOUT_MS);

            if (response == null) {
                continue;
            }

            // Check if payload is reflected in response
            ResponseAnalyzer.AnalysisResult result = 
                    ResponseAnalyzer.analyzeXssReflection(response, payload);

            if (result.isVulnerable()) {
                findings.add(createFinding(vulnType + " in Parameter: " + 
                        point.getParamName(), context)
                        .severity(severity)
                        .description(
                                "A Cross-Site Scripting (XSS) vulnerability was detected in the WebSocket message. " +
                                "The parameter '" + point.getParamName() + "' reflects user input in the response " +
                                "without proper encoding.\n\n" +
                                "The injected XSS payload was found in the server response, indicating that " +
                                "malicious scripts could be executed if this data is rendered in a browser.\n\n" +
                                "This vulnerability could allow an attacker to:\n" +
                                "- Steal session cookies and authentication tokens\n" +
                                "- Perform actions on behalf of the user\n" +
                                "- Redirect users to malicious websites\n" +
                                "- Deface the web application\n" +
                                "- Capture sensitive user input")
                        .evidence(String.format(
                                "Parameter: %s\nPayload: %s\n\nReflection Detected:\n%s",
                                point.getParamName(), payload, result.getEvidence()))
                        .remediation(REMEDIATION)
                        .request(truncateForDisplay(injectedMessage))
                        .response(truncateForDisplay(response))
                        .build());

                return true; // Found vulnerability
            }

            sleepWithCancellation(DEFAULT_DELAY_MS);
        }

        return false;
    }
}
