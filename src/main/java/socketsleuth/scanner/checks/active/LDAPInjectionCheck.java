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
 * Active check for LDAP Injection vulnerabilities in WebSocket messages.
 * Tests for the ability to manipulate LDAP queries through user input.
 */
public class LDAPInjectionCheck extends AbstractActiveCheck {

    private static final String REMEDIATION = 
            "Implement proper LDAP injection defenses:\n\n" +
            "1. Use parameterized LDAP queries when available\n" +
            "2. Escape all special LDAP characters in user input:\n" +
            "   - * (asterisk)\n" +
            "   - ( and ) (parentheses)\n" +
            "   - \\ (backslash)\n" +
            "   - NUL (null character)\n" +
            "3. Validate input against a strict allowlist of expected characters\n" +
            "4. Use the principle of least privilege for LDAP bind accounts\n" +
            "5. Implement proper error handling that doesn't expose LDAP details";

    public LDAPInjectionCheck(MontoyaApi api) {
        super(api);
    }

    @Override
    public String getId() {
        return "active-ldap-injection";
    }

    @Override
    public String getName() {
        return "LDAP Injection (Active)";
    }

    @Override
    public String getDescription() {
        return "Actively tests for LDAP injection vulnerabilities by sending LDAP manipulation " +
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

        log("Found " + injectionPoints.size() + " injection points, testing LDAP injection...");

        // Get baseline response
        String baselineResponse = sendAndWaitForResponse(context, templateMessage, DEFAULT_TIMEOUT_MS);

        // Get LDAP payloads
        List<String> payloads = PayloadGenerator.getLdapPayloads();

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

                // Check for LDAP error indicators
                ResponseAnalyzer.AnalysisResult result = 
                        ResponseAnalyzer.analyzeLdapInjection(response);

                if (result.isVulnerable()) {
                    findings.add(createFinding("LDAP Injection in Parameter: " + 
                            point.getParamName(), context)
                            .severity(ScanSeverity.HIGH)
                            .description(
                                    "An LDAP injection vulnerability was detected in the WebSocket message. " +
                                    "The parameter '" + point.getParamName() + "' appears to be vulnerable " +
                                    "to LDAP injection attacks.\n\n" +
                                    "The server returned an LDAP-related error message in response to " +
                                    "the injected payload, indicating that user input is being incorporated " +
                                    "into LDAP queries without proper sanitization.\n\n" +
                                    "This vulnerability could allow an attacker to:\n" +
                                    "- Bypass authentication mechanisms\n" +
                                    "- Access unauthorized directory information\n" +
                                    "- Modify directory entries (if write access exists)\n" +
                                    "- Extract sensitive user information")
                            .evidence(String.format(
                                    "Parameter: %s\nOriginal Value: %s\nPayload: %s\n\n" +
                                    "LDAP Error Detected:\n%s",
                                    point.getParamName(), point.getOriginalValue(), payload, result.getEvidence()))
                            .remediation(REMEDIATION)
                            .request(truncateForDisplay(injectedMessage))
                            .response(truncateForDisplay(response))
                            .build());

                    break; // Found vulnerability for this parameter
                }

                // Check for wildcard injection success (different response when using *)
                if (payload.equals("*") && baselineResponse != null &&
                    ResponseAnalyzer.responseDiffersSignificantly(baselineResponse, response) &&
                    !ResponseAnalyzer.containsGenericError(response)) {
                    
                    findings.add(createFinding("Potential LDAP Wildcard Injection in Parameter: " + 
                            point.getParamName(), context)
                            .severity(ScanSeverity.MEDIUM)
                            .description(
                                    "A potential LDAP wildcard injection was detected. " +
                                    "The parameter '" + point.getParamName() + "' caused a significantly " +
                                    "different response when an LDAP wildcard (*) character was injected.\n\n" +
                                    "This could indicate that the wildcard is being interpreted by an LDAP " +
                                    "query, allowing an attacker to enumerate or access directory entries.")
                            .evidence(String.format(
                                    "Parameter: %s\nPayload: %s\n\n" +
                                    "Response changed significantly when wildcard was used.",
                                    point.getParamName(), payload))
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
