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
package socketsleuth.scanner;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

/**
 * Converts ScanFinding objects to Burp's AuditIssue format
 * and registers them with Burp's native issue panel.
 */
public class BurpIssueReporter {
    private final MontoyaApi api;
    private boolean enabled = false;

    public BurpIssueReporter(MontoyaApi api) {
        this.api = api;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public boolean isEnabled() {
        return enabled;
    }

    /**
     * Reports a ScanFinding to Burp's issue panel.
     */
    public void reportFinding(ScanFinding finding) {
        if (!enabled) return;
        
        try {
            AuditIssueSeverity severity = mapSeverity(finding.getSeverity());
            AuditIssueConfidence confidence = mapConfidence(finding);
            
            // Create the audit issue
            AuditIssue issue = AuditIssue.auditIssue(
                "[WebSocket] " + finding.getTitle(),           // name
                buildDetailHtml(finding),                       // detail
                finding.getRemediation(),                       // remediation
                finding.getUrl(),                               // baseUrl
                severity,                                       // severity
                confidence,                                     // confidence
                buildBackground(finding),                       // background
                null,                                           // remediationBackground
                severity,                                       // typicalSeverity
                buildRequestResponse(finding)                   // requestResponses (varargs)
            );

            api.siteMap().add(issue);
            api.logging().logToOutput("[BurpIssueReporter] Reported: " + finding.getTitle());
        } catch (Exception e) {
            api.logging().logToError("[BurpIssueReporter] Error: " + e.getMessage());
        }
    }

    /**
     * Maps ScanSeverity to Burp's AuditIssueSeverity.
     */
    private AuditIssueSeverity mapSeverity(ScanSeverity severity) {
        switch (severity) {
            case CRITICAL:
            case HIGH:
                return AuditIssueSeverity.HIGH;
            case MEDIUM:
                return AuditIssueSeverity.MEDIUM;
            case LOW:
                return AuditIssueSeverity.LOW;
            case INFO:
            default:
                return AuditIssueSeverity.INFORMATION;
        }
    }

    /**
     * Determines confidence level based on finding evidence.
     */
    private AuditIssueConfidence mapConfidence(ScanFinding finding) {
        // Active checks with evidence = CERTAIN, passive = TENTATIVE
        if (finding.getEvidence() != null && !finding.getEvidence().isEmpty()) {
            return AuditIssueConfidence.CERTAIN;
        }
        return AuditIssueConfidence.TENTATIVE;
    }

    /**
     * Builds HTML detail content for the issue.
     */
    private String buildDetailHtml(ScanFinding finding) {
        StringBuilder html = new StringBuilder();
        html.append("<p>").append(escapeHtml(finding.getDescription())).append("</p>");
        if (finding.getEvidence() != null) {
            html.append("<h4>Evidence</h4><pre>")
                .append(escapeHtml(finding.getEvidence()))
                .append("</pre>");
        }
        html.append("<p><b>Category:</b> ").append(finding.getCategory().getDisplayName()).append("</p>");
        html.append("<p><b>Socket ID:</b> ").append(finding.getSocketId()).append("</p>");
        return html.toString();
    }

    /**
     * Builds background information for the issue.
     */
    private String buildBackground(ScanFinding finding) {
        return "This issue was detected by the SocketSleuth+ WebSocket Scanner in the " 
               + finding.getCategory().getDisplayName() + " category.";
    }

    /**
     * Builds an HttpRequestResponse for the sitemap entry.
     */
    private HttpRequestResponse buildRequestResponse(ScanFinding finding) {
        // Build a mock request/response for the sitemap
        // Use the upgrade request URL if available
        String url = finding.getUrl() != null ? finding.getUrl() : "wss://unknown";
        
        HttpRequest request;
        if (finding.getRequest() != null && !finding.getRequest().isEmpty()) {
            try {
                request = HttpRequest.httpRequest(finding.getRequest());
            } catch (Exception e) {
                request = HttpRequest.httpRequestFromUrl(url);
            }
        } else {
            request = HttpRequest.httpRequestFromUrl(url);
        }
        
        HttpResponse response = null;
        if (finding.getResponse() != null && !finding.getResponse().isEmpty()) {
            try {
                response = HttpResponse.httpResponse(finding.getResponse());
            } catch (Exception e) {
                // Response parsing failed, leave as null
            }
        }
        
        return HttpRequestResponse.httpRequestResponse(request, response);
    }

    /**
     * Escapes HTML special characters.
     */
    private String escapeHtml(String text) {
        if (text == null) return "";
        return text.replace("&", "&amp;")
                   .replace("<", "&lt;")
                   .replace(">", "&gt;")
                   .replace("\n", "<br>");
    }
}
