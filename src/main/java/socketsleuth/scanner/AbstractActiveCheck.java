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
import burp.api.montoya.proxy.websocket.ProxyWebSocket;
import burp.api.montoya.websocket.Direction;
import burp.api.montoya.websocket.TextMessage;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import java.util.regex.Pattern;

/**
 * Abstract base class for active scanner checks that send payloads and analyze responses.
 * Provides utilities for message sending, response collection, and payload iteration.
 */
public abstract class AbstractActiveCheck extends AbstractScannerCheck {

    protected static final int DEFAULT_TIMEOUT_MS = 5000;
    protected static final int DEFAULT_DELAY_MS = 100;
    protected static final int MAX_RESPONSE_LENGTH = 2000;

    protected AbstractActiveCheck(MontoyaApi api) {
        super(api);
    }

    @Override
    public boolean isPassive() {
        return false;
    }

    @Override
    public boolean isApplicable(ScanContext context) {
        // Active checks require an open WebSocket connection
        return context.hasActiveConnection() && context.isActiveMode();
    }

    @Override
    public int getEstimatedDuration() {
        return 5000; // Active checks typically take longer
    }

    /**
     * Sends a message and waits for a response with a timeout.
     *
     * @param context   The scan context
     * @param message   The message to send
     * @param timeoutMs Maximum time to wait for response
     * @return The response message, or null if timeout/error
     */
    protected String sendAndWaitForResponse(ScanContext context, String message, int timeoutMs) {
        ProxyWebSocket ws = context.getProxyWebSocket();
        if (ws == null) {
            logError("No active WebSocket connection");
            return null;
        }

        BlockingQueue<String> responseQueue = new LinkedBlockingQueue<>();
        
        Consumer<TextMessage> responseHandler = textMessage -> {
            if (textMessage.direction() == Direction.SERVER_TO_CLIENT) {
                responseQueue.offer(textMessage.payload());
            }
        };

        try {
            // Subscribe to responses
            context.getMessageProvider().subscribeTextMessage(context.getSocketId(), responseHandler);

            // Send the message
            ws.sendTextMessage(message, Direction.CLIENT_TO_SERVER);
            log("Sent payload: " + truncateForLog(message));

            // Wait for response
            String response = responseQueue.poll(timeoutMs, TimeUnit.MILLISECONDS);
            
            if (response != null) {
                log("Received response: " + truncateForLog(response));
            }
            
            return response;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return null;
        } finally {
            // Unsubscribe from responses
            context.getMessageProvider().unsubscribeTextMessage(context.getSocketId(), responseHandler);
        }
    }

    /**
     * Sends a message without waiting for response.
     */
    protected void sendMessage(ScanContext context, String message) {
        ProxyWebSocket ws = context.getProxyWebSocket();
        if (ws == null) {
            logError("No active WebSocket connection");
            return;
        }
        ws.sendTextMessage(message, Direction.CLIENT_TO_SERVER);
        log("Sent payload: " + truncateForLog(message));
    }

    /**
     * Collects responses for a period of time after sending a message.
     *
     * @param context     The scan context
     * @param message     The message to send
     * @param collectMs   Time to collect responses
     * @return List of responses received
     */
    protected List<String> sendAndCollectResponses(ScanContext context, String message, int collectMs) {
        ProxyWebSocket ws = context.getProxyWebSocket();
        List<String> responses = new ArrayList<>();
        
        if (ws == null) {
            logError("No active WebSocket connection");
            return responses;
        }

        BlockingQueue<String> responseQueue = new LinkedBlockingQueue<>();
        
        Consumer<TextMessage> responseHandler = textMessage -> {
            if (textMessage.direction() == Direction.SERVER_TO_CLIENT) {
                responseQueue.offer(textMessage.payload());
            }
        };

        try {
            context.getMessageProvider().subscribeTextMessage(context.getSocketId(), responseHandler);
            ws.sendTextMessage(message, Direction.CLIENT_TO_SERVER);
            
            long endTime = System.currentTimeMillis() + collectMs;
            while (System.currentTimeMillis() < endTime && !isCancelled()) {
                String response = responseQueue.poll(100, TimeUnit.MILLISECONDS);
                if (response != null) {
                    responses.add(response);
                }
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } finally {
            context.getMessageProvider().unsubscribeTextMessage(context.getSocketId(), responseHandler);
        }

        return responses;
    }

    /**
     * Iterates through payloads, sending each and collecting responses.
     *
     * @param context  The scan context
     * @param payloads List of messages to send
     * @param delayMs  Delay between each payload
     * @return List of responses (may be fewer than payloads if cancelled)
     */
    protected List<PayloadResponse> sendPayloadsAndCollectResponses(
            ScanContext context, List<String> payloads, int delayMs) {
        
        List<PayloadResponse> results = new ArrayList<>();
        
        for (String payload : payloads) {
            if (isCancelled()) {
                break;
            }

            long startTime = System.currentTimeMillis();
            String response = sendAndWaitForResponse(context, payload, DEFAULT_TIMEOUT_MS);
            long responseTime = System.currentTimeMillis() - startTime;

            results.add(new PayloadResponse(payload, response, responseTime));

            if (delayMs > 0 && !isCancelled()) {
                sleepWithCancellation(delayMs);
            }
        }

        return results;
    }

    /**
     * Checks if a response contains any of the specified error patterns.
     */
    protected boolean containsErrorIndicator(String response, Pattern[] patterns) {
        if (response == null || response.isEmpty()) {
            return false;
        }
        for (Pattern pattern : patterns) {
            if (pattern.matcher(response).find()) {
                return true;
            }
        }
        return false;
    }

    /**
     * Checks if a response contains a specific string (case-insensitive).
     */
    protected boolean containsString(String response, String search) {
        if (response == null || search == null) {
            return false;
        }
        return response.toLowerCase().contains(search.toLowerCase());
    }

    /**
     * Gets the last outgoing message from the stream to use as a template.
     */
    protected String getLastOutgoingMessage(ScanContext context) {
        int messageCount = context.getMessageCount();
        
        for (int i = messageCount - 1; i >= 0; i--) {
            Object messageObj = context.getMessage(i);
            if (messageObj == null) continue;
            
            try {
                // Check direction
                Object directionObj = messageObj.getClass().getMethod("getDirection").invoke(messageObj);
                if (directionObj != null && directionObj.toString().contains("CLIENT")) {
                    // Get message content
                    Object contentObj = messageObj.getClass().getMethod("getMessage").invoke(messageObj);
                    if (contentObj != null) {
                        return contentObj.toString();
                    }
                }
            } catch (Exception e) {
                // Continue to next message
            }
        }
        return null;
    }

    /**
     * Truncates a string for logging purposes.
     */
    protected String truncateForLog(String str) {
        if (str == null) return "null";
        if (str.length() <= 100) return str;
        return str.substring(0, 100) + "...";
    }

    /**
     * Truncates content for display in findings.
     */
    protected String truncateForDisplay(String content) {
        if (content == null) return null;
        if (content.length() <= MAX_RESPONSE_LENGTH) return content;
        return content.substring(0, MAX_RESPONSE_LENGTH) + 
               "\n... [truncated, " + (content.length() - MAX_RESPONSE_LENGTH) + " more characters]";
    }

    /**
     * Represents a payload-response pair with timing information.
     */
    public static class PayloadResponse {
        private final String payload;
        private final String response;
        private final long responseTimeMs;

        public PayloadResponse(String payload, String response, long responseTimeMs) {
            this.payload = payload;
            this.response = response;
            this.responseTimeMs = responseTimeMs;
        }

        public String getPayload() {
            return payload;
        }

        public String getResponse() {
            return response;
        }

        public long getResponseTimeMs() {
            return responseTimeMs;
        }

        public boolean hasResponse() {
            return response != null && !response.isEmpty();
        }
    }
}
