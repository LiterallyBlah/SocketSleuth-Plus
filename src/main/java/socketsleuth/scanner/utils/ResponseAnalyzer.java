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
package socketsleuth.scanner.utils;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Centralized response analysis for detecting vulnerability indicators.
 */
public class ResponseAnalyzer {

    // ============= SQL Error Patterns =============
    
    private static final Pattern[] SQL_ERROR_PATTERNS = {
            Pattern.compile("SQL\\s+syntax", Pattern.CASE_INSENSITIVE),
            Pattern.compile("syntax\\s+error.*SQL", Pattern.CASE_INSENSITIVE),
            Pattern.compile("mysql_", Pattern.CASE_INSENSITIVE),
            Pattern.compile("mysqli_", Pattern.CASE_INSENSITIVE),
            Pattern.compile("pg_query", Pattern.CASE_INSENSITIVE),
            Pattern.compile("ORA-\\d{5}", Pattern.CASE_INSENSITIVE),
            Pattern.compile("SQLSTATE\\[", Pattern.CASE_INSENSITIVE),
            Pattern.compile("sqlite3?_", Pattern.CASE_INSENSITIVE),
            Pattern.compile("mssql_", Pattern.CASE_INSENSITIVE),
            Pattern.compile("sqlsrv_", Pattern.CASE_INSENSITIVE),
            Pattern.compile("You have an error in your SQL syntax", Pattern.CASE_INSENSITIVE),
            Pattern.compile("Query failed", Pattern.CASE_INSENSITIVE),
            Pattern.compile("Unclosed quotation mark", Pattern.CASE_INSENSITIVE),
            Pattern.compile("Incorrect syntax near", Pattern.CASE_INSENSITIVE),
            Pattern.compile("ODBC SQL Server Driver", Pattern.CASE_INSENSITIVE),
            Pattern.compile("PostgreSQL.*ERROR", Pattern.CASE_INSENSITIVE),
            Pattern.compile("PLS-\\d+", Pattern.CASE_INSENSITIVE),
            Pattern.compile("quoted string not properly terminated", Pattern.CASE_INSENSITIVE),
            Pattern.compile("unterminated.*string", Pattern.CASE_INSENSITIVE),
            Pattern.compile("sql command not properly ended", Pattern.CASE_INSENSITIVE),
            Pattern.compile("invalid.*column", Pattern.CASE_INSENSITIVE),
            Pattern.compile("Unknown column", Pattern.CASE_INSENSITIVE)
    };

    // ============= NoSQL Error Patterns =============
    
    private static final Pattern[] NOSQL_ERROR_PATTERNS = {
            Pattern.compile("MongoError", Pattern.CASE_INSENSITIVE),
            Pattern.compile("MongoDB.*Error", Pattern.CASE_INSENSITIVE),
            Pattern.compile("\\$where.*not allowed", Pattern.CASE_INSENSITIVE),
            Pattern.compile("invalid operator", Pattern.CASE_INSENSITIVE),
            Pattern.compile("\\$gt requires", Pattern.CASE_INSENSITIVE),
            Pattern.compile("\\$regex.*error", Pattern.CASE_INSENSITIVE),
            Pattern.compile("CouchDB.*error", Pattern.CASE_INSENSITIVE),
            Pattern.compile("RethinkDB.*error", Pattern.CASE_INSENSITIVE),
            Pattern.compile("invalid JSON", Pattern.CASE_INSENSITIVE),
            Pattern.compile("SyntaxError.*JSON", Pattern.CASE_INSENSITIVE),
            Pattern.compile("not a valid.*operator", Pattern.CASE_INSENSITIVE),
            Pattern.compile("BadValue", Pattern.CASE_INSENSITIVE)
    };

    // ============= Command Execution Patterns =============
    
    private static final Pattern[] COMMAND_OUTPUT_PATTERNS = {
            // Unix patterns
            Pattern.compile("uid=\\d+\\([^)]+\\)\\s+gid=\\d+", Pattern.CASE_INSENSITIVE),  // id command
            Pattern.compile("root:x:0:0", Pattern.CASE_INSENSITIVE),  // /etc/passwd
            Pattern.compile("Linux.*\\d+\\.\\d+", Pattern.CASE_INSENSITIVE),  // uname -a
            Pattern.compile("total\\s+\\d+.*drwx", Pattern.CASE_INSENSITIVE),  // ls -la
            Pattern.compile("/bin/(ba)?sh", Pattern.CASE_INSENSITIVE),
            Pattern.compile("^[a-z_][a-z0-9_-]*$", Pattern.MULTILINE),  // whoami output
            // Windows patterns
            Pattern.compile("\\\\Users\\\\[^\\\\]+", Pattern.CASE_INSENSITIVE),  // whoami
            Pattern.compile("Volume Serial Number", Pattern.CASE_INSENSITIVE),  // dir
            Pattern.compile("\\[fonts\\]", Pattern.CASE_INSENSITIVE),  // win.ini
            Pattern.compile("Windows IP Configuration", Pattern.CASE_INSENSITIVE),  // ipconfig
            Pattern.compile("Host Name:", Pattern.CASE_INSENSITIVE),  // systeminfo
            Pattern.compile("User accounts for", Pattern.CASE_INSENSITIVE)  // net user
    };

    // ============= XSS Reflection Detection =============
    
    /**
     * XSS payload signatures to check for reflection.
     */
    private static final String[] XSS_SIGNATURES = {
            "<script>",
            "javascript:",
            "onerror=",
            "onload=",
            "onmouseover=",
            "<svg",
            "<img src=x",
            "alert(",
            "prompt(",
            "confirm("
    };

    // ============= LDAP Error Patterns =============
    
    private static final Pattern[] LDAP_ERROR_PATTERNS = {
            Pattern.compile("LDAP.*error", Pattern.CASE_INSENSITIVE),
            Pattern.compile("Invalid DN syntax", Pattern.CASE_INSENSITIVE),
            Pattern.compile("Bad search filter", Pattern.CASE_INSENSITIVE),
            Pattern.compile("Filter.*invalid", Pattern.CASE_INSENSITIVE),
            Pattern.compile("javax\\.naming\\..*Exception", Pattern.CASE_INSENSITIVE),
            Pattern.compile("LDAPException", Pattern.CASE_INSENSITIVE),
            Pattern.compile("LDAP://", Pattern.CASE_INSENSITIVE),
            Pattern.compile("object class.*invalid", Pattern.CASE_INSENSITIVE),
            Pattern.compile("attribute.*invalid", Pattern.CASE_INSENSITIVE)
    };

    // ============= XPath Error Patterns =============
    
    private static final Pattern[] XPATH_ERROR_PATTERNS = {
            Pattern.compile("XPath.*error", Pattern.CASE_INSENSITIVE),
            Pattern.compile("XPathException", Pattern.CASE_INSENSITIVE),
            Pattern.compile("Invalid XPath", Pattern.CASE_INSENSITIVE),
            Pattern.compile("XPath syntax", Pattern.CASE_INSENSITIVE),
            Pattern.compile("xmlXPath.*error", Pattern.CASE_INSENSITIVE),
            Pattern.compile("SimpleXMLElement::xpath", Pattern.CASE_INSENSITIVE),
            Pattern.compile("javax\\.xml\\.xpath", Pattern.CASE_INSENSITIVE),
            Pattern.compile("DOMXPath", Pattern.CASE_INSENSITIVE),
            Pattern.compile("Expected.*but found", Pattern.CASE_INSENSITIVE),
            Pattern.compile("XPATH syntax error", Pattern.CASE_INSENSITIVE)
    };

    // ============= Analysis Methods =============

    /**
     * Checks if a response contains SQL injection indicators.
     */
    public static AnalysisResult analyzeSqlInjection(String response) {
        return analyzeWithPatterns(response, SQL_ERROR_PATTERNS, "SQL Injection");
    }

    /**
     * Checks if a response contains NoSQL injection indicators.
     */
    public static AnalysisResult analyzeNoSqlInjection(String response) {
        return analyzeWithPatterns(response, NOSQL_ERROR_PATTERNS, "NoSQL Injection");
    }

    /**
     * Checks if a response contains command execution output.
     */
    public static AnalysisResult analyzeCommandInjection(String response) {
        return analyzeWithPatterns(response, COMMAND_OUTPUT_PATTERNS, "Command Injection");
    }

    /**
     * Checks if an XSS payload is reflected in the response.
     */
    public static AnalysisResult analyzeXssReflection(String response, String payload) {
        if (response == null || response.isEmpty()) {
            return new AnalysisResult(false, null, "XSS Reflection");
        }

        String responseLower = response.toLowerCase();
        String payloadLower = payload.toLowerCase();

        // Check for direct reflection
        if (responseLower.contains(payloadLower)) {
            return new AnalysisResult(true, "Payload reflected: " + payload, "XSS Reflection");
        }

        // Check for XSS signature reflection
        for (String signature : XSS_SIGNATURES) {
            if (payloadLower.contains(signature.toLowerCase()) && 
                responseLower.contains(signature.toLowerCase())) {
                return new AnalysisResult(true, 
                        "XSS signature reflected: " + signature, "XSS Reflection");
            }
        }

        return new AnalysisResult(false, null, "XSS Reflection");
    }

    /**
     * Checks if a response contains LDAP injection indicators.
     */
    public static AnalysisResult analyzeLdapInjection(String response) {
        return analyzeWithPatterns(response, LDAP_ERROR_PATTERNS, "LDAP Injection");
    }

    /**
     * Checks if a response contains XPath injection indicators.
     */
    public static AnalysisResult analyzeXpathInjection(String response) {
        return analyzeWithPatterns(response, XPATH_ERROR_PATTERNS, "XPath Injection");
    }

    /**
     * Analyzes timing to detect blind injection vulnerabilities.
     * 
     * @param baselineMs   Normal response time
     * @param responseMs   Response time with payload
     * @param thresholdMs  Minimum difference to consider significant
     * @return true if timing suggests blind injection
     */
    public static boolean analyzeTimingDifference(long baselineMs, long responseMs, long thresholdMs) {
        return responseMs - baselineMs >= thresholdMs;
    }

    /**
     * Checks if a response differs significantly from a baseline.
     * Useful for detecting successful injection that changes behavior.
     */
    public static boolean responseDiffersSignificantly(String baseline, String response) {
        if (baseline == null || response == null) {
            return baseline != response;
        }

        // Length difference check
        int lengthDiff = Math.abs(baseline.length() - response.length());
        if (lengthDiff > Math.max(baseline.length(), response.length()) * 0.2) {
            return true;
        }

        // Check for error indicators in response but not baseline
        boolean baselineHasError = containsGenericError(baseline);
        boolean responseHasError = containsGenericError(response);
        
        return !baselineHasError && responseHasError;
    }

    /**
     * Checks for generic error indicators.
     */
    public static boolean containsGenericError(String response) {
        if (response == null) return false;
        
        String lower = response.toLowerCase();
        return lower.contains("error") ||
               lower.contains("exception") ||
               lower.contains("failed") ||
               lower.contains("invalid") ||
               lower.contains("syntax");
    }

    // ============= Helper Methods =============

    private static AnalysisResult analyzeWithPatterns(String response, Pattern[] patterns, String type) {
        if (response == null || response.isEmpty()) {
            return new AnalysisResult(false, null, type);
        }

        List<String> matches = new ArrayList<>();
        for (Pattern pattern : patterns) {
            Matcher matcher = pattern.matcher(response);
            if (matcher.find()) {
                String match = matcher.group();
                if (match.length() > 100) {
                    match = match.substring(0, 100) + "...";
                }
                matches.add(match);
            }
        }

        if (!matches.isEmpty()) {
            String evidence = String.join("\n", matches.subList(0, Math.min(3, matches.size())));
            return new AnalysisResult(true, evidence, type);
        }

        return new AnalysisResult(false, null, type);
    }

    /**
     * Represents the result of a response analysis.
     */
    public static class AnalysisResult {
        private final boolean vulnerable;
        private final String evidence;
        private final String type;

        public AnalysisResult(boolean vulnerable, String evidence, String type) {
            this.vulnerable = vulnerable;
            this.evidence = evidence;
            this.type = type;
        }

        public boolean isVulnerable() {
            return vulnerable;
        }

        public String getEvidence() {
            return evidence;
        }

        public String getType() {
            return type;
        }

        @Override
        public String toString() {
            if (vulnerable) {
                return type + ": VULNERABLE - " + evidence;
            }
            return type + ": Not detected";
        }
    }
}
