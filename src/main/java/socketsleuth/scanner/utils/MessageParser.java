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
 * Utility for parsing WebSocket messages and finding injection points.
 * Supports JSON messages and key=value text formats.
 */
public class MessageParser {

    // Pattern to match JSON string values: "key": "value" or "key":"value"
    private static final Pattern JSON_STRING_VALUE = Pattern.compile(
            "\"([^\"]+)\"\\s*:\\s*\"([^\"]*)\""
    );

    // Pattern to match JSON numeric/boolean values: "key": 123 or "key": true
    private static final Pattern JSON_OTHER_VALUE = Pattern.compile(
            "\"([^\"]+)\"\\s*:\\s*([0-9.]+|true|false|null)"
    );

    // Pattern to match key=value pairs (URL-encoded or plain text)
    private static final Pattern KEY_VALUE_PAIR = Pattern.compile(
            "([a-zA-Z_][a-zA-Z0-9_]*)=([^&\\s]*)"
    );

    // Patterns for identifying ID-like parameter names (case-insensitive matching done in code)
    private static final String[] ID_PARAM_PATTERNS = {
        "user_id", "userId", "user", "uid",
        "account_id", "accountId", "account", "acct",
        "id", "ID", "_id", "objectId", "oid",
        "profile_id", "profileId", "profile",
        "customer_id", "customerId", "customer",
        "order_id", "orderId", "order",
        "session_id", "sessionId", "session",
        "doc_id", "docId", "document_id", "documentId",
        "record_id", "recordId", "item_id", "itemId",
        "member_id", "memberId", "org_id", "orgId"
    };

    // UUID pattern
    private static final Pattern UUID_PATTERN = Pattern.compile(
        "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
    );

    // MongoDB ObjectId pattern (24 hex chars)
    private static final Pattern MONGO_ID_PATTERN = Pattern.compile(
        "[0-9a-fA-F]{24}"
    );

    /**
     * Represents an injection point in a message.
     */
    public static class InjectionPoint {
        private final String paramName;
        private final String originalValue;
        private final int startIndex;
        private final int endIndex;
        private final InjectionType type;

        public InjectionPoint(String paramName, String originalValue, 
                              int startIndex, int endIndex, InjectionType type) {
            this.paramName = paramName;
            this.originalValue = originalValue;
            this.startIndex = startIndex;
            this.endIndex = endIndex;
            this.type = type;
        }

        public String getParamName() {
            return paramName;
        }

        public String getOriginalValue() {
            return originalValue;
        }

        public int getStartIndex() {
            return startIndex;
        }

        public int getEndIndex() {
            return endIndex;
        }

        public InjectionType getType() {
            return type;
        }

        @Override
        public String toString() {
            return String.format("%s=%s [%d:%d] (%s)", 
                    paramName, originalValue, startIndex, endIndex, type);
        }
    }

    /**
     * Types of injection points.
     */
    public enum InjectionType {
        JSON_STRING,
        JSON_NUMBER,
        JSON_BOOLEAN,
        KEY_VALUE,
        RAW_TEXT
    }

    /**
     * Finds all injection points in a message.
     * Automatically detects JSON vs key=value format.
     *
     * @param message The message to parse
     * @return List of injection points found
     */
    public static List<InjectionPoint> findInjectionPoints(String message) {
        List<InjectionPoint> points = new ArrayList<>();
        
        if (message == null || message.isEmpty()) {
            return points;
        }

        String trimmed = message.trim();
        
        // Check if it's JSON
        if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
            points.addAll(findJsonInjectionPoints(message));
        }
        
        // Also check for key=value patterns (could be in URL params or form data)
        points.addAll(findKeyValueInjectionPoints(message));

        return points;
    }

    /**
     * Finds injection points in JSON messages.
     */
    private static List<InjectionPoint> findJsonInjectionPoints(String message) {
        List<InjectionPoint> points = new ArrayList<>();

        // Find string values
        Matcher stringMatcher = JSON_STRING_VALUE.matcher(message);
        while (stringMatcher.find()) {
            String key = stringMatcher.group(1);
            String value = stringMatcher.group(2);
            
            // Calculate the actual position of the value (including quotes)
            int valueStart = stringMatcher.start(2);
            int valueEnd = stringMatcher.end(2);
            
            points.add(new InjectionPoint(key, value, valueStart, valueEnd, InjectionType.JSON_STRING));
        }

        // Find numeric/boolean values
        Matcher otherMatcher = JSON_OTHER_VALUE.matcher(message);
        while (otherMatcher.find()) {
            String key = otherMatcher.group(1);
            String value = otherMatcher.group(2);
            int valueStart = otherMatcher.start(2);
            int valueEnd = otherMatcher.end(2);
            
            InjectionType type = InjectionType.JSON_NUMBER;
            if ("true".equals(value) || "false".equals(value)) {
                type = InjectionType.JSON_BOOLEAN;
            }
            
            points.add(new InjectionPoint(key, value, valueStart, valueEnd, type));
        }

        return points;
    }

    /**
     * Finds injection points in key=value formatted messages.
     */
    private static List<InjectionPoint> findKeyValueInjectionPoints(String message) {
        List<InjectionPoint> points = new ArrayList<>();

        Matcher matcher = KEY_VALUE_PAIR.matcher(message);
        while (matcher.find()) {
            String key = matcher.group(1);
            String value = matcher.group(2);
            int valueStart = matcher.start(2);
            int valueEnd = matcher.end(2);
            
            points.add(new InjectionPoint(key, value, valueStart, valueEnd, InjectionType.KEY_VALUE));
        }

        return points;
    }

    /**
     * Injects a payload at a specific injection point.
     *
     * @param message  The original message
     * @param point    The injection point
     * @param payload  The payload to inject
     * @return The modified message with payload injected
     */
    public static String injectPayload(String message, InjectionPoint point, String payload) {
        if (message == null || point == null || payload == null) {
            return message;
        }

        StringBuilder sb = new StringBuilder();
        sb.append(message.substring(0, point.getStartIndex()));
        sb.append(payload);
        sb.append(message.substring(point.getEndIndex()));
        
        return sb.toString();
    }

    /**
     * Injects a payload by appending to the original value.
     *
     * @param message  The original message
     * @param point    The injection point
     * @param payload  The payload to append
     * @return The modified message with payload appended
     */
    public static String appendPayload(String message, InjectionPoint point, String payload) {
        if (message == null || point == null || payload == null) {
            return message;
        }

        StringBuilder sb = new StringBuilder();
        sb.append(message.substring(0, point.getEndIndex()));
        sb.append(payload);
        sb.append(message.substring(point.getEndIndex()));
        
        return sb.toString();
    }

    /**
     * Creates multiple message variants, each with a payload injected at a different point.
     *
     * @param message   The original message
     * @param payload   The payload to inject
     * @return List of message variants with injection metadata
     */
    public static List<InjectedMessage> createInjectedVariants(String message, String payload) {
        List<InjectedMessage> variants = new ArrayList<>();
        List<InjectionPoint> points = findInjectionPoints(message);

        for (InjectionPoint point : points) {
            String injectedMessage = injectPayload(message, point, payload);
            variants.add(new InjectedMessage(injectedMessage, point, payload));
        }

        return variants;
    }

    /**
     * Creates message variants by appending payloads to original values.
     */
    public static List<InjectedMessage> createAppendedVariants(String message, String payload) {
        List<InjectedMessage> variants = new ArrayList<>();
        List<InjectionPoint> points = findInjectionPoints(message);

        for (InjectionPoint point : points) {
            String injectedMessage = appendPayload(message, point, payload);
            variants.add(new InjectedMessage(injectedMessage, point, payload));
        }

        return variants;
    }

    /**
     * Checks if a message appears to be JSON.
     */
    public static boolean isJson(String message) {
        if (message == null || message.isEmpty()) {
            return false;
        }
        String trimmed = message.trim();
        return (trimmed.startsWith("{") && trimmed.endsWith("}")) ||
               (trimmed.startsWith("[") && trimmed.endsWith("]"));
    }

    /**
     * Finds injection points that appear to be ID parameters (for BOLA testing).
     * Only returns points whose parameter name suggests they are identifiers.
     */
    public static List<InjectionPoint> findIdParameters(String message) {
        List<InjectionPoint> allPoints = findInjectionPoints(message);
        List<InjectionPoint> idPoints = new ArrayList<>();
        
        for (InjectionPoint point : allPoints) {
            if (isIdParameterName(point.getParamName())) {
                idPoints.add(point);
            }
        }
        
        return idPoints;
    }

    /**
     * Checks if a parameter name suggests it's an ID field.
     */
    public static boolean isIdParameterName(String paramName) {
        if (paramName == null) return false;
        String lower = paramName.toLowerCase();
        
        for (String pattern : ID_PARAM_PATTERNS) {
            if (lower.equals(pattern.toLowerCase()) || 
                lower.contains(pattern.toLowerCase())) {
                return true;
            }
        }
        return false;
    }

    /**
     * Checks if a value looks like a UUID.
     */
    public static boolean isUuid(String value) {
        return value != null && UUID_PATTERN.matcher(value).matches();
    }

    /**
     * Checks if a value looks like a MongoDB ObjectId.
     */
    public static boolean isMongoId(String value) {
        return value != null && MONGO_ID_PATTERN.matcher(value).matches();
    }

    /**
     * Checks if a value looks like a numeric ID.
     */
    public static boolean isNumericId(String value) {
        if (value == null || value.isEmpty()) return false;
        try {
            Long.parseLong(value);
            return true;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    /**
     * Represents a message with an injected payload.
     */
    public static class InjectedMessage {
        private final String message;
        private final InjectionPoint injectionPoint;
        private final String payload;

        public InjectedMessage(String message, InjectionPoint injectionPoint, String payload) {
            this.message = message;
            this.injectionPoint = injectionPoint;
            this.payload = payload;
        }

        public String getMessage() {
            return message;
        }

        public InjectionPoint getInjectionPoint() {
            return injectionPoint;
        }

        public String getPayload() {
            return payload;
        }

        public String getParamName() {
            return injectionPoint.getParamName();
        }
    }
}
