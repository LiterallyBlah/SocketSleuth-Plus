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
import burp.api.montoya.http.message.requests.HttpRequest;
import socketsleuth.scanner.AbstractScannerCheck;
import socketsleuth.scanner.ScanCheckCategory;
import socketsleuth.scanner.ScanContext;
import socketsleuth.scanner.ScanFinding;
import socketsleuth.scanner.ScanSeverity;

import java.util.ArrayList;
import java.util.List;

/**
 * Detects Cross-Site WebSocket Hijacking (CSWSH) vulnerabilities by analyzing
 * the Origin header in WebSocket upgrade requests.
 */
public class CSWSHOriginCheck extends AbstractScannerCheck {

    private static final String REMEDIATION = 
            "Implement strict Origin header validation on the server side. " +
            "The server should verify that the Origin header matches the expected domain(s) " +
            "before accepting WebSocket connections. Reject connections with missing, " +
            "null, or unexpected Origin values.";

    public CSWSHOriginCheck(MontoyaApi api) {
        super(api);
    }

    @Override
    public String getId() {
        return "cswsh-origin";
    }

    @Override
    public String getName() {
        return "CSWSH - Origin Header Analysis";
    }

    @Override
    public String getDescription() {
        return "Analyzes the Origin header in WebSocket upgrade requests to detect " +
               "potential Cross-Site WebSocket Hijacking vulnerabilities.";
    }

    @Override
    public ScanCheckCategory getCategory() {
        return ScanCheckCategory.CSWSH;
    }

    @Override
    public boolean isPassive() {
        return true;
    }

    @Override
    public boolean isApplicable(ScanContext context) {
        // Only applicable if we have an upgrade request to analyze
        return context.getUpgradeRequest() != null;
    }

    @Override
    public List<ScanFinding> runCheck(ScanContext context) {
        List<ScanFinding> findings = new ArrayList<>();
        
        HttpRequest upgradeRequest = context.getUpgradeRequest();
        if (upgradeRequest == null) {
            return findings;
        }

        String originHeader = null;
        String hostHeader = null;

        // Extract Origin and Host headers
        try {
            if (upgradeRequest.hasHeader("Origin")) {
                originHeader = upgradeRequest.headerValue("Origin");
            }
            if (upgradeRequest.hasHeader("Host")) {
                hostHeader = upgradeRequest.headerValue("Host");
            }
        } catch (Exception e) {
            logError("Error reading headers", e);
            return findings;
        }

        String requestStr = upgradeRequest.toString();

        // Check for missing Origin header
        if (originHeader == null || originHeader.trim().isEmpty()) {
            findings.add(createFinding("Missing Origin Header in WebSocket Upgrade", context)
                    .severity(ScanSeverity.HIGH)
                    .description(
                            "The WebSocket upgrade request does not contain an Origin header. " +
                            "This means the server cannot validate the origin of the request, " +
                            "potentially allowing Cross-Site WebSocket Hijacking (CSWSH) attacks. " +
                            "An attacker could create a malicious webpage that establishes a " +
                            "WebSocket connection to this endpoint on behalf of authenticated users.")
                    .evidence("Origin header: Not present")
                    .remediation(REMEDIATION)
                    .request(requestStr)
                    .build());
            return findings;
        }

        // Check for "null" origin (can occur with file:// or sandboxed iframes)
        if ("null".equalsIgnoreCase(originHeader.trim())) {
            findings.add(createFinding("Null Origin in WebSocket Upgrade", context)
                    .severity(ScanSeverity.MEDIUM)
                    .description(
                            "The WebSocket upgrade request has a 'null' Origin header. " +
                            "This can occur when requests originate from file:// URLs, " +
                            "sandboxed iframes, or certain redirects. If the server accepts " +
                            "null origins, it may be vulnerable to CSWSH attacks.")
                    .evidence("Origin header: null")
                    .remediation(REMEDIATION + " Do not accept 'null' as a valid Origin.")
                    .request(requestStr)
                    .build());
            return findings;
        }

        // Extract host from Origin header for comparison
        String originHost = extractHostFromOrigin(originHeader);
        
        // Compare Origin with Host header
        if (hostHeader != null && !hostHeader.trim().isEmpty()) {
            String normalizedHost = normalizeHost(hostHeader);
            String normalizedOriginHost = normalizeHost(originHost);

            if (!normalizedHost.equalsIgnoreCase(normalizedOriginHost)) {
                findings.add(createFinding("Origin Differs from Host", context)
                        .severity(ScanSeverity.MEDIUM)
                        .description(
                                "The Origin header domain differs from the Host header. " +
                                "This may indicate cross-origin communication or a potential " +
                                "misconfiguration. While this could be intentional for CORS scenarios, " +
                                "it warrants investigation to ensure the server properly validates origins.")
                        .evidence(String.format("Origin: %s\nHost: %s", originHeader, hostHeader))
                        .remediation(REMEDIATION)
                        .request(requestStr)
                        .build());
            } else {
                // Origin matches Host - this is the expected secure configuration
                findings.add(createFinding("Origin Header Present and Valid", context)
                        .severity(ScanSeverity.INFO)
                        .description(
                                "The WebSocket upgrade request contains an Origin header that " +
                                "matches the target host. This is the expected configuration for " +
                                "same-origin WebSocket connections.")
                        .evidence(String.format("Origin: %s\nHost: %s", originHeader, hostHeader))
                        .remediation("No action required. Ensure server-side Origin validation is implemented.")
                        .request(requestStr)
                        .build());
            }
        }

        return findings;
    }

    /**
     * Extracts the host portion from an Origin header value.
     * Origin format: scheme://host[:port]
     */
    private String extractHostFromOrigin(String origin) {
        if (origin == null) {
            return "";
        }
        
        String host = origin;
        
        // Remove scheme if present
        if (host.contains("://")) {
            host = host.substring(host.indexOf("://") + 3);
        }
        
        // Remove path if present
        if (host.contains("/")) {
            host = host.substring(0, host.indexOf("/"));
        }
        
        return host;
    }

    /**
     * Normalizes a host string by removing default ports.
     */
    private String normalizeHost(String host) {
        if (host == null) {
            return "";
        }
        
        // Remove default ports
        host = host.replaceAll(":80$", "");
        host = host.replaceAll(":443$", "");
        
        return host.toLowerCase().trim();
    }
}
