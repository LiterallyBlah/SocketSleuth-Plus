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
 * Active check for XPath Injection vulnerabilities in WebSocket messages.
 * Tests for the ability to manipulate XPath queries through user input.
 */
public class XPathInjectionCheck extends AbstractActiveCheck {

    private static final String REMEDIATION = 
            "Implement proper XPath injection defenses:\n\n" +
            "1. Use parameterized XPath queries when available\n" +
            "2. Escape all XPath special characters in user input:\n" +
            "   - ' (single quote)\n" +
            "   - \" (double quote)\n" +
            "   - [ and ] (brackets)\n" +
            "   - / (forward slash)\n" +
            "3. Validate input against strict patterns\n" +
            "4. Consider using XQuery with parameterized queries instead\n" +
            "5. Implement proper error handling that doesn't expose XPath details";

    public XPathInjectionCheck(MontoyaApi api) {
        super(api);
    }

    @Override
    public String getId() {
        return "active-xpath-injection";
    }

    @Override
    public String getName() {
        return "XPath Injection (Active)";
    }

    @Override
    public String getDescription() {
        return "Actively tests for XPath injection vulnerabilities by sending XPath manipulation " +
               "payloads through WebSocket messages and checking for error indicators.";
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

        log("Found " + injectionPoints.size() + " injection points, testing XPath injection...");

        // Get baseline response
        String baselineResponse = sendAndWaitForResponse(context, templateMessage, DEFAULT_TIMEOUT_MS);

        // Get XPath payloads
        List<String> payloads = PayloadGenerator.getXpathPayloads();

        for (MessageParser.InjectionPoint point : injectionPoints) {
            if (isCancelled()) break;

            // Test with subset of payloads
            List<String> testPayloads = payloads.subList(0, Math.min(6, payloads.size()));
            
            for (String payload : testPayloads) {
                if (isCancelled()) break;

                // Append payload to original value
                String injectedMessage = MessageParser.injectPayload(templateMessage, point, 
                        point.getOriginalValue() + payload);

                String response = sendAndWaitForResponse(context, injectedMessage, DEFAULT_TIMEOUT_MS);

                if (response == null) {
                    continue;
                }

                // Check for XPath error indicators
                ResponseAnalyzer.AnalysisResult result = 
                        ResponseAnalyzer.analyzeXpathInjection(response);

                if (result.isVulnerable()) {
                    findings.add(createFinding("XPath Injection in Parameter: " + 
                            point.getParamName(), context)
                            .severity(ScanSeverity.HIGH)
                            .description(
                                    "An XPath injection vulnerability was detected in the WebSocket message. " +
                                    "The parameter '" + point.getParamName() + "' appears to be vulnerable " +
                                    "to XPath injection attacks.\n\n" +
                                    "The server returned an XPath-related error message in response to " +
                                    "the injected payload, indicating that user input is being incorporated " +
                                    "into XPath queries without proper sanitization.\n\n" +
                                    "This vulnerability could allow an attacker to:\n" +
                                    "- Bypass authentication mechanisms\n" +
                                    "- Access unauthorized XML data\n" +
                                    "- Extract sensitive information from XML documents\n" +
                                    "- Enumerate the structure of XML data stores")
                            .evidence(String.format(
                                    "Parameter: %s\nOriginal Value: %s\nPayload: %s\n\n" +
                                    "XPath Error Detected:\n%s",
                                    point.getParamName(), point.getOriginalValue(), payload, result.getEvidence()))
                            .remediation(REMEDIATION)
                            .request(truncateForDisplay(injectedMessage))
                            .response(truncateForDisplay(response))
                            .build());

                    break; // Found vulnerability for this parameter
                }

                // Check for boolean-based XPath injection (response differs with OR 1=1)
                if (payload.contains("or '1'='1") && baselineResponse != null &&
                    ResponseAnalyzer.responseDiffersSignificantly(baselineResponse, response) &&
                    !ResponseAnalyzer.containsGenericError(response)) {
                    
                    // The response changed in a way that suggests the query was manipulated
                    findings.add(createFinding("Potential Boolean-Based XPath Injection in Parameter: " + 
                            point.getParamName(), context)
                            .severity(ScanSeverity.MEDIUM)
                            .description(
                                    "A potential boolean-based XPath injection was detected. " +
                                    "The parameter '" + point.getParamName() + "' caused a significantly " +
                                    "different response when an XPath boolean payload was injected.\n\n" +
                                    "This could indicate that the XPath query logic was altered by " +
                                    "the injected condition, allowing an attacker to bypass filters or " +
                                    "access unauthorized data.")
                            .evidence(String.format(
                                    "Parameter: %s\nPayload: %s\n\n" +
                                    "Response changed when boolean condition was injected.\n" +
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
