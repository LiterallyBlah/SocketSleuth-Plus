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
import socketsleuth.scanner.AbstractScannerCheck;
import socketsleuth.scanner.ScanCheckCategory;
import socketsleuth.scanner.ScanContext;
import socketsleuth.scanner.ScanFinding;
import socketsleuth.scanner.ScanSeverity;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Detects information disclosure through verbose error messages in WebSocket responses.
 */
public class VerboseErrorCheck extends AbstractScannerCheck {

    // Stack trace patterns for various languages
    private static final Pattern JAVA_STACK_TRACE = Pattern.compile(
            "at\\s+[a-zA-Z0-9.$_]+\\([A-Za-z0-9_]+\\.java:\\d+\\)"
    );
    
    private static final Pattern PYTHON_STACK_TRACE = Pattern.compile(
            "File\\s+\"[^\"]+\",\\s+line\\s+\\d+"
    );
    
    private static final Pattern NODEJS_STACK_TRACE = Pattern.compile(
            "at\\s+.+\\s+\\([^)]+:\\d+:\\d+\\)"
    );
    
    private static final Pattern DOTNET_STACK_TRACE = Pattern.compile(
            "at\\s+[A-Za-z0-9._]+\\([^)]*\\)\\s+in\\s+[^:]+:\\s*line\\s+\\d+"
    );
    
    private static final Pattern PHP_STACK_TRACE = Pattern.compile(
            "#\\d+\\s+[^\\s]+\\(\\d+\\):\\s+"
    );

    // SQL error patterns
    private static final Pattern SQL_SYNTAX_ERROR = Pattern.compile(
            "(SQL\\s+syntax|syntax\\s+error.*SQL|mysql_|mysqli_|pg_query|ORA-\\d{5}|" +
            "SQLSTATE\\[|sqlite3?_|mssql_|sqlsrv_)", Pattern.CASE_INSENSITIVE
    );
    
    private static final Pattern SQL_ERROR_MESSAGE = Pattern.compile(
            "(You have an error in your SQL|Query failed|SQL error|" +
            "Unclosed quotation mark|Incorrect syntax near|" +
            "ODBC SQL Server Driver|PostgreSQL.*ERROR|" +
            "ORA-\\d+|PLS-\\d+)", Pattern.CASE_INSENSITIVE
    );

    // Path disclosure patterns
    private static final Pattern UNIX_PATH = Pattern.compile(
            "(/var/www/|/home/[a-z]+/|/usr/|/etc/|/opt/|/tmp/|/srv/)[^\\s\"'<>]+"
    );
    
    private static final Pattern WINDOWS_PATH = Pattern.compile(
            "([A-Za-z]:\\\\[^\\s\"'<>]+|\\\\\\\\[^\\s\"'<>]+)"
    );

    // Internal IP address patterns (RFC 1918)
    private static final Pattern INTERNAL_IP = Pattern.compile(
            "\\b(10\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}|" +
            "172\\.(1[6-9]|2[0-9]|3[0-1])\\.\\d{1,3}\\.\\d{1,3}|" +
            "192\\.168\\.\\d{1,3}\\.\\d{1,3}|" +
            "127\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})\\b"
    );

    // Debug/verbose mode indicators
    private static final Pattern DEBUG_INDICATOR = Pattern.compile(
            "(\\\"debug\\\"\\s*:\\s*true|DEBUG\\s*=\\s*true|debug\\s+mode|" +
            "development\\s+mode|stack\\s*trace|exception\\s+details)", Pattern.CASE_INSENSITIVE
    );

    // Server/framework version patterns
    private static final Pattern VERSION_DISCLOSURE = Pattern.compile(
            "(Apache/[\\d.]+|nginx/[\\d.]+|PHP/[\\d.]+|Python/[\\d.]+|" +
            "Node\\.js/v[\\d.]+|Express/[\\d.]+|Django/[\\d.]+|" +
            "Rails/[\\d.]+|ASP\\.NET[^\\s]*|Tomcat/[\\d.]+)", Pattern.CASE_INSENSITIVE
    );

    private static final String REMEDIATION = 
            "Configure the application to use generic error messages in production. " +
            "Implement proper error handling that:\n\n" +
            "- Logs detailed errors server-side for debugging\n" +
            "- Returns generic error messages to clients\n" +
            "- Disables debug/development mode in production\n" +
            "- Removes or sanitizes stack traces before sending responses";

    // Track what we've already reported to avoid duplicates
    private Set<String> reportedIssues;

    public VerboseErrorCheck(MontoyaApi api) {
        super(api);
    }

    @Override
    public String getId() {
        return "verbose-error";
    }

    @Override
    public String getName() {
        return "Verbose Error Information Disclosure";
    }

    @Override
    public String getDescription() {
        return "Detects information disclosure through verbose error messages, " +
               "stack traces, and debug information in WebSocket responses.";
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
        reportedIssues = new HashSet<>();

        int messageCount = context.getMessageCount();
        
        for (int i = 0; i < messageCount; i++) {
            if (isCancelled()) {
                break;
            }
            
            Object messageObj = context.getMessage(i);
            if (messageObj == null) {
                continue;
            }

            // Extract message content via reflection
            String messageContent = extractMessageContent(messageObj);
            if (messageContent == null || messageContent.isEmpty()) {
                continue;
            }

            // Check for various disclosure types (pass messageContent for inclusion in findings)
            checkStackTraces(messageContent, context, findings);
            checkSQLErrors(messageContent, context, findings);
            checkPathDisclosure(messageContent, context, findings);
            checkInternalIPs(messageContent, context, findings);
            checkDebugIndicators(messageContent, context, findings);
            checkVersionDisclosure(messageContent, context, findings);
        }

        return findings;
    }

    private String extractMessageContent(Object messageObj) {
        try {
            // Try getMessage() method
            java.lang.reflect.Method getMessageMethod = messageObj.getClass().getMethod("getMessage");
            Object result = getMessageMethod.invoke(messageObj);
            if (result != null) {
                return result.toString();
            }
        } catch (Exception e) {
            // Try toString as fallback
            return messageObj.toString();
        }
        return null;
    }

    private void checkStackTraces(String content, ScanContext context, List<ScanFinding> findings) {
        String truncatedContent = truncateForDisplay(content);
        
        // Java stack trace
        if (JAVA_STACK_TRACE.matcher(content).find() && !reportedIssues.contains("java-stack")) {
            reportedIssues.add("java-stack");
            findings.add(createFinding("Java Stack Trace Detected", context)
                    .severity(ScanSeverity.MEDIUM)
                    .description(
                            "A Java stack trace was detected in a WebSocket message. " +
                            "Stack traces expose internal application structure, class names, " +
                            "file paths, and line numbers that can help attackers understand " +
                            "the application architecture and identify vulnerabilities.")
                    .evidence(extractEvidence(content, JAVA_STACK_TRACE))
                    .remediation(REMEDIATION)
                    .response(truncatedContent)
                    .build());
        }

        // Python stack trace
        if (PYTHON_STACK_TRACE.matcher(content).find() && !reportedIssues.contains("python-stack")) {
            reportedIssues.add("python-stack");
            findings.add(createFinding("Python Stack Trace Detected", context)
                    .severity(ScanSeverity.MEDIUM)
                    .description(
                            "A Python stack trace was detected in a WebSocket message. " +
                            "This exposes internal file paths, function names, and code structure.")
                    .evidence(extractEvidence(content, PYTHON_STACK_TRACE))
                    .remediation(REMEDIATION)
                    .response(truncatedContent)
                    .build());
        }

        // Node.js stack trace
        if (NODEJS_STACK_TRACE.matcher(content).find() && !reportedIssues.contains("nodejs-stack")) {
            reportedIssues.add("nodejs-stack");
            findings.add(createFinding("Node.js Stack Trace Detected", context)
                    .severity(ScanSeverity.MEDIUM)
                    .description(
                            "A Node.js stack trace was detected in a WebSocket message. " +
                            "This exposes internal module paths and code structure.")
                    .evidence(extractEvidence(content, NODEJS_STACK_TRACE))
                    .remediation(REMEDIATION)
                    .response(truncatedContent)
                    .build());
        }

        // .NET stack trace
        if (DOTNET_STACK_TRACE.matcher(content).find() && !reportedIssues.contains("dotnet-stack")) {
            reportedIssues.add("dotnet-stack");
            findings.add(createFinding(".NET Stack Trace Detected", context)
                    .severity(ScanSeverity.MEDIUM)
                    .description(
                            "A .NET stack trace was detected in a WebSocket message. " +
                            "This exposes internal assembly names, namespaces, and file paths.")
                    .evidence(extractEvidence(content, DOTNET_STACK_TRACE))
                    .remediation(REMEDIATION)
                    .response(truncatedContent)
                    .build());
        }

        // PHP stack trace
        if (PHP_STACK_TRACE.matcher(content).find() && !reportedIssues.contains("php-stack")) {
            reportedIssues.add("php-stack");
            findings.add(createFinding("PHP Stack Trace Detected", context)
                    .severity(ScanSeverity.MEDIUM)
                    .description(
                            "A PHP stack trace was detected in a WebSocket message. " +
                            "This exposes internal file paths and function calls.")
                    .evidence(extractEvidence(content, PHP_STACK_TRACE))
                    .remediation(REMEDIATION)
                    .response(truncatedContent)
                    .build());
        }
    }

    private void checkSQLErrors(String content, ScanContext context, List<ScanFinding> findings) {
        if ((SQL_SYNTAX_ERROR.matcher(content).find() || SQL_ERROR_MESSAGE.matcher(content).find()) 
                && !reportedIssues.contains("sql-error")) {
            reportedIssues.add("sql-error");
            findings.add(createFinding("SQL Error Message Detected", context)
                    .severity(ScanSeverity.MEDIUM)
                    .description(
                            "An SQL error message was detected in a WebSocket message. " +
                            "SQL error messages can expose database structure, query syntax, " +
                            "and may indicate SQL injection vulnerabilities. They also reveal " +
                            "the database technology in use.")
                    .evidence(extractEvidence(content, SQL_SYNTAX_ERROR, SQL_ERROR_MESSAGE))
                    .remediation(REMEDIATION + "\n\nAdditionally, use parameterized queries " +
                            "to prevent SQL injection vulnerabilities.")
                    .response(truncateForDisplay(content))
                    .build());
        }
    }

    private void checkPathDisclosure(String content, ScanContext context, List<ScanFinding> findings) {
        String truncatedContent = truncateForDisplay(content);
        
        // Unix paths
        if (UNIX_PATH.matcher(content).find() && !reportedIssues.contains("unix-path")) {
            reportedIssues.add("unix-path");
            findings.add(createFinding("Unix File Path Disclosed", context)
                    .severity(ScanSeverity.LOW)
                    .description(
                            "A Unix file system path was detected in a WebSocket message. " +
                            "Path disclosure reveals the server's directory structure and can " +
                            "help attackers identify sensitive files or craft path traversal attacks.")
                    .evidence(extractEvidence(content, UNIX_PATH))
                    .remediation(REMEDIATION)
                    .response(truncatedContent)
                    .build());
        }

        // Windows paths
        if (WINDOWS_PATH.matcher(content).find() && !reportedIssues.contains("windows-path")) {
            reportedIssues.add("windows-path");
            findings.add(createFinding("Windows File Path Disclosed", context)
                    .severity(ScanSeverity.LOW)
                    .description(
                            "A Windows file system path was detected in a WebSocket message. " +
                            "This reveals the server's operating system and directory structure.")
                    .evidence(extractEvidence(content, WINDOWS_PATH))
                    .remediation(REMEDIATION)
                    .response(truncatedContent)
                    .build());
        }
    }

    private void checkInternalIPs(String content, ScanContext context, List<ScanFinding> findings) {
        if (INTERNAL_IP.matcher(content).find() && !reportedIssues.contains("internal-ip")) {
            reportedIssues.add("internal-ip");
            findings.add(createFinding("Internal IP Address Disclosed", context)
                    .severity(ScanSeverity.LOW)
                    .description(
                            "An internal (RFC 1918) IP address was detected in a WebSocket message. " +
                            "This reveals information about the internal network infrastructure " +
                            "and may help attackers plan further attacks.")
                    .evidence(extractEvidence(content, INTERNAL_IP))
                    .remediation(REMEDIATION + "\n\nEnsure internal IP addresses are not " +
                            "included in client-facing responses.")
                    .response(truncateForDisplay(content))
                    .build());
        }
    }

    private void checkDebugIndicators(String content, ScanContext context, List<ScanFinding> findings) {
        if (DEBUG_INDICATOR.matcher(content).find() && !reportedIssues.contains("debug-mode")) {
            reportedIssues.add("debug-mode");
            findings.add(createFinding("Debug Mode Indicator Detected", context)
                    .severity(ScanSeverity.INFO)
                    .description(
                            "Indicators of debug or development mode were detected in a " +
                            "WebSocket message. If this is a production environment, debug " +
                            "mode may expose additional sensitive information.")
                    .evidence(extractEvidence(content, DEBUG_INDICATOR))
                    .remediation("Ensure debug mode is disabled in production environments.")
                    .response(truncateForDisplay(content))
                    .build());
        }
    }

    private void checkVersionDisclosure(String content, ScanContext context, List<ScanFinding> findings) {
        if (VERSION_DISCLOSURE.matcher(content).find() && !reportedIssues.contains("version-disclosure")) {
            reportedIssues.add("version-disclosure");
            findings.add(createFinding("Server/Framework Version Disclosed", context)
                    .severity(ScanSeverity.INFO)
                    .description(
                            "Server or framework version information was detected in a " +
                            "WebSocket message. Version disclosure can help attackers identify " +
                            "known vulnerabilities specific to that version.")
                    .evidence(extractEvidence(content, VERSION_DISCLOSURE))
                    .remediation("Configure servers to hide version information in responses.")
                    .response(truncateForDisplay(content))
                    .build());
        }
    }

    /**
     * Truncates content for display in findings to avoid excessive length.
     */
    private String truncateForDisplay(String content) {
        if (content == null) {
            return null;
        }
        if (content.length() <= 2000) {
            return content;
        }
        return content.substring(0, 2000) + "\n... [truncated, " + (content.length() - 2000) + " more characters]";
    }

    /**
     * Extracts matching evidence from content, limited to reasonable length.
     */
    private String extractEvidence(String content, Pattern... patterns) {
        StringBuilder evidence = new StringBuilder();
        
        for (Pattern pattern : patterns) {
            Matcher matcher = pattern.matcher(content);
            int count = 0;
            while (matcher.find() && count < 3) {
                if (evidence.length() > 0) {
                    evidence.append("\n");
                }
                String match = matcher.group();
                if (match.length() > 200) {
                    match = match.substring(0, 200) + "...";
                }
                evidence.append("Match: ").append(match);
                count++;
            }
        }
        
        if (evidence.length() == 0) {
            return "Pattern matched in message content";
        }
        
        return evidence.toString();
    }
}
