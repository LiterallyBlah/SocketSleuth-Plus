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

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Detects sensitive tokens, credentials, and session identifiers exposed in WebSocket URLs.
 */
public class TokenInURLCheck extends AbstractScannerCheck {

    // High-priority sensitive parameter names (session/auth related)
    private static final Set<String> HIGH_SENSITIVITY_PARAMS = new HashSet<>(Arrays.asList(
            "token", "auth", "auth_token", "authtoken", "authentication",
            "session", "sessionid", "session_id", "sid",
            "jwt", "bearer", "access_token", "accesstoken",
            "refresh_token", "refreshtoken", "id_token", "idtoken",
            "password", "pwd", "pass", "passwd", "credential", "credentials",
            "secret", "api_secret", "apisecret", "client_secret"
    ));

    // Medium-priority sensitive parameter names (API keys, etc.)
    private static final Set<String> MEDIUM_SENSITIVITY_PARAMS = new HashSet<>(Arrays.asList(
            "key", "api_key", "apikey", "api-key",
            "private_key", "privatekey", "secret_key", "secretkey",
            "app_key", "appkey", "app_secret", "appsecret",
            "oauth", "oauth_token", "oauthtoken"
    ));

    // JWT pattern: base64.base64.signature
    private static final Pattern JWT_PATTERN = Pattern.compile(
            "eyJ[A-Za-z0-9_-]*\\.eyJ[A-Za-z0-9_-]*\\.[A-Za-z0-9_-]*"
    );

    // Generic token pattern: long alphanumeric strings that look like tokens
    private static final Pattern GENERIC_TOKEN_PATTERN = Pattern.compile(
            "[A-Za-z0-9_-]{32,}"
    );

    private static final String REMEDIATION = 
            "Never include sensitive tokens, credentials, or session identifiers in URLs. " +
            "URLs are logged in browser history, server logs, proxy logs, and can be leaked " +
            "through the Referer header. Instead:\n\n" +
            "- Use WebSocket subprotocols for authentication\n" +
            "- Send tokens in the first WebSocket message after connection\n" +
            "- Use secure cookies with HttpOnly and Secure flags\n" +
            "- Implement token rotation and short expiration times";

    public TokenInURLCheck(MontoyaApi api) {
        super(api);
    }

    @Override
    public String getId() {
        return "token-in-url";
    }

    @Override
    public String getName() {
        return "Sensitive Token in URL";
    }

    @Override
    public String getDescription() {
        return "Detects sensitive tokens, credentials, and session identifiers " +
               "exposed in WebSocket URLs and query parameters.";
    }

    @Override
    public ScanCheckCategory getCategory() {
        return ScanCheckCategory.MISCONFIGURATION;
    }

    @Override
    public boolean isPassive() {
        return true;
    }

    @Override
    public List<ScanFinding> runCheck(ScanContext context) {
        List<ScanFinding> findings = new ArrayList<>();
        
        String url = context.getUrl();
        if (url == null || url.isEmpty()) {
            return findings;
        }

        // Get the upgrade request for inclusion in findings
        HttpRequest upgradeRequest = context.getUpgradeRequest();
        String requestStr = upgradeRequest != null ? upgradeRequest.toString() : null;

        // Check for JWT in URL
        checkForJWT(url, context, requestStr, findings);

        // Check query parameters
        checkQueryParameters(url, context, requestStr, findings);

        // Check URL path for token-like values
        checkUrlPath(url, context, requestStr, findings);

        return findings;
    }

    private void checkForJWT(String url, ScanContext context, String requestStr, List<ScanFinding> findings) {
        Matcher jwtMatcher = JWT_PATTERN.matcher(url);
        if (jwtMatcher.find()) {
            String jwt = jwtMatcher.group();
            ScanFinding.Builder builder = createFinding("JWT Token Exposed in URL", context)
                    .severity(ScanSeverity.HIGH)
                    .description(
                            "A JSON Web Token (JWT) was found in the WebSocket URL. " +
                            "JWTs often contain sensitive claims including user identity, " +
                            "permissions, and session data. Exposing JWTs in URLs creates " +
                            "several security risks:\n\n" +
                            "- Browser history exposure\n" +
                            "- Server/proxy log exposure\n" +
                            "- Referer header leakage\n" +
                            "- Shoulder surfing vulnerability\n" +
                            "- Bookmark/sharing risks")
                    .evidence("JWT found: " + maskToken(jwt) + "\nFull URL: " + maskUrl(url))
                    .remediation(REMEDIATION);
            if (requestStr != null) {
                builder.request(requestStr);
            }
            findings.add(builder.build());
        }
    }

    private void checkQueryParameters(String url, ScanContext context, String requestStr, List<ScanFinding> findings) {
        int queryStart = url.indexOf('?');
        if (queryStart == -1) {
            return;
        }

        String queryString = url.substring(queryStart + 1);
        String[] params = queryString.split("&");

        for (String param : params) {
            String[] keyValue = param.split("=", 2);
            if (keyValue.length != 2) {
                continue;
            }

            String paramName = keyValue[0].toLowerCase();
            String paramValue = decodeUrlComponent(keyValue[1]);

            // Check high sensitivity parameters
            if (HIGH_SENSITIVITY_PARAMS.contains(paramName)) {
                ScanFinding.Builder builder = createFinding("Session/Auth Token in URL Parameter", context)
                        .severity(ScanSeverity.HIGH)
                        .description(
                                "A sensitive authentication or session parameter was found in " +
                                "the WebSocket URL query string. The parameter '" + keyValue[0] + "' " +
                                "appears to contain a session token or credential that should not " +
                                "be exposed in URLs.")
                        .evidence(String.format("Parameter: %s\nValue: %s\nURL: %s",
                                keyValue[0], maskToken(paramValue), maskUrl(url)))
                        .remediation(REMEDIATION);
                if (requestStr != null) {
                    builder.request(requestStr);
                }
                findings.add(builder.build());
                continue;
            }

            // Check medium sensitivity parameters
            if (MEDIUM_SENSITIVITY_PARAMS.contains(paramName)) {
                ScanFinding.Builder builder = createFinding("API Key in URL Parameter", context)
                        .severity(ScanSeverity.MEDIUM)
                        .description(
                                "A potentially sensitive API key or secret was found in the " +
                                "WebSocket URL query string. The parameter '" + keyValue[0] + "' " +
                                "may contain credentials that could be exposed through URL logging.")
                        .evidence(String.format("Parameter: %s\nValue: %s\nURL: %s",
                                keyValue[0], maskToken(paramValue), maskUrl(url)))
                        .remediation(REMEDIATION);
                if (requestStr != null) {
                    builder.request(requestStr);
                }
                findings.add(builder.build());
                continue;
            }

            // Check for token-like values in any parameter
            if (paramValue.length() >= 32 && GENERIC_TOKEN_PATTERN.matcher(paramValue).matches()) {
                // Check if the parameter name suggests it's a token
                if (paramName.contains("token") || paramName.contains("key") || 
                    paramName.contains("auth") || paramName.contains("secret")) {
                    ScanFinding.Builder builder = createFinding("Potential Token in URL Parameter", context)
                            .severity(ScanSeverity.MEDIUM)
                            .description(
                                    "A parameter with a token-like value was found in the URL. " +
                                    "The parameter '" + keyValue[0] + "' contains a long alphanumeric " +
                                    "value that may be a security token.")
                            .evidence(String.format("Parameter: %s\nValue: %s\nURL: %s",
                                    keyValue[0], maskToken(paramValue), maskUrl(url)))
                            .remediation(REMEDIATION);
                    if (requestStr != null) {
                        builder.request(requestStr);
                    }
                    findings.add(builder.build());
                }
            }
        }
    }

    private void checkUrlPath(String url, ScanContext context, String requestStr, List<ScanFinding> findings) {
        // Extract path from URL
        String path = url;
        
        // Remove scheme
        if (path.contains("://")) {
            path = path.substring(path.indexOf("://") + 3);
        }
        
        // Remove host
        if (path.contains("/")) {
            path = path.substring(path.indexOf("/"));
        }
        
        // Remove query string
        if (path.contains("?")) {
            path = path.substring(0, path.indexOf("?"));
        }

        // Check for JWT in path
        Matcher jwtMatcher = JWT_PATTERN.matcher(path);
        if (jwtMatcher.find()) {
            // Already handled by checkForJWT, skip
            return;
        }

        // Check path segments for long token-like values
        String[] segments = path.split("/");
        for (String segment : segments) {
            if (segment.length() >= 40 && GENERIC_TOKEN_PATTERN.matcher(segment).matches()) {
                ScanFinding.Builder builder = createFinding("Potential Token in URL Path", context)
                        .severity(ScanSeverity.LOW)
                        .description(
                                "A token-like value was found in the URL path. This long " +
                                "alphanumeric string may be a session token, API key, or other " +
                                "sensitive identifier that should not be exposed in URLs.")
                        .evidence(String.format("Path segment: %s\nURL: %s",
                                maskToken(segment), maskUrl(url)))
                        .remediation(REMEDIATION);
                if (requestStr != null) {
                    builder.request(requestStr);
                }
                findings.add(builder.build());
            }
        }
    }

    /**
     * Masks a token value for safe display in findings.
     */
    private String maskToken(String token) {
        if (token == null || token.length() <= 8) {
            return "****";
        }
        return token.substring(0, 4) + "..." + token.substring(token.length() - 4);
    }

    /**
     * Masks sensitive parts of a URL for safe display.
     */
    private String maskUrl(String url) {
        // Replace JWT tokens
        String masked = JWT_PATTERN.matcher(url).replaceAll("[JWT_REDACTED]");
        
        // Replace long token-like values in query params
        masked = masked.replaceAll("=([A-Za-z0-9_-]{32,})", "=[TOKEN_REDACTED]");
        
        return masked;
    }

    /**
     * URL-decodes a component safely.
     */
    private String decodeUrlComponent(String value) {
        try {
            return URLDecoder.decode(value, "UTF-8");
        } catch (UnsupportedEncodingException | IllegalArgumentException e) {
            return value;
        }
    }
}
