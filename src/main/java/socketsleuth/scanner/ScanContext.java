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
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.proxy.websocket.ProxyWebSocket;
import burp.api.montoya.websocket.Direction;
import websocket.MessageProvider;

import java.util.ArrayList;
import java.util.List;


/**
 * Context passed to scanner checks containing all data needed for analysis.
 */
public class ScanContext {
    private final MontoyaApi api;
    private final int socketId;
    private final String url;
    private final HttpRequest upgradeRequest;
    private final Object streamModel; // WebSocketStreamTableModel from default package
    private final ProxyWebSocket proxyWebSocket;
    private final MessageProvider messageProvider;
    private final boolean isActiveMode;
    private final List<String> templateMessages;

    private ScanContext(Builder builder) {
        this.api = builder.api;
        this.socketId = builder.socketId;
        this.url = builder.url;
        this.upgradeRequest = builder.upgradeRequest;
        this.streamModel = builder.streamModel;
        this.proxyWebSocket = builder.proxyWebSocket;
        this.messageProvider = builder.messageProvider;
        this.isActiveMode = builder.isActiveMode;
        this.templateMessages = builder.templateMessages != null 
            ? new ArrayList<>(builder.templateMessages) 
            : new ArrayList<>();
    }

    public MontoyaApi getApi() {
        return api;
    }

    public int getSocketId() {
        return socketId;
    }

    public String getUrl() {
        return url;
    }

    public HttpRequest getUpgradeRequest() {
        return upgradeRequest;
    }

    public Object getStreamModel() {
        return streamModel;
    }

    public ProxyWebSocket getProxyWebSocket() {
        return proxyWebSocket;
    }

    public MessageProvider getMessageProvider() {
        return messageProvider;
    }

    public boolean isActiveMode() {
        return isActiveMode;
    }

    /**
     * Get the list of template messages selected for active scanning.
     * Returns empty list if none selected (checks should use last outgoing message as fallback).
     */
    public List<String> getTemplateMessages() {
        return new ArrayList<>(templateMessages);
    }

    /**
     * Check if specific template messages were selected.
     */
    public boolean hasTemplateMessages() {
        return templateMessages != null && !templateMessages.isEmpty();
    }

    /**
     * Get the number of messages in the stream.
     */
    public int getMessageCount() {
        if (streamModel == null) {
            return 0;
        }
        try {
            java.lang.reflect.Method method = streamModel.getClass().getMethod("getRowCount");
            return (int) method.invoke(streamModel);
        } catch (Exception e) {
            return 0;
        }
    }

    /**
     * Get a message at the specified index.
     * Returns the raw message object that can be cast as needed.
     */
    public Object getMessage(int index) {
        if (streamModel == null) {
            return null;
        }
        try {
            java.lang.reflect.Method method = streamModel.getClass().getMethod("getStream", int.class);
            return method.invoke(streamModel, index);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Check if the WebSocket connection uses TLS.
     * Handles both ws/wss schemes and http/https schemes (as Burp may display either).
     */
    public boolean isSecure() {
        if (url == null) {
            return false;
        }
        String urlLower = url.toLowerCase();
        // Check for secure WebSocket or HTTPS (Burp may show either)
        return urlLower.startsWith("wss://") || urlLower.startsWith("https://");
    }

    /**
     * Check if there's an active connection available for active scanning.
     */
    public boolean hasActiveConnection() {
        return proxyWebSocket != null;
    }

    /**
     * Builder for constructing ScanContext instances.
     */
    public static class Builder {
        private MontoyaApi api;
        private int socketId;
        private String url;
        private HttpRequest upgradeRequest;
        private Object streamModel;
        private ProxyWebSocket proxyWebSocket;
        private MessageProvider messageProvider;
        private boolean isActiveMode;
        private List<String> templateMessages;

        public Builder api(MontoyaApi api) {
            this.api = api;
            return this;
        }

        public Builder socketId(int socketId) {
            this.socketId = socketId;
            return this;
        }

        public Builder url(String url) {
            this.url = url;
            return this;
        }

        public Builder upgradeRequest(HttpRequest upgradeRequest) {
            this.upgradeRequest = upgradeRequest;
            return this;
        }

        public Builder streamModel(Object streamModel) {
            this.streamModel = streamModel;
            return this;
        }

        public Builder proxyWebSocket(ProxyWebSocket proxyWebSocket) {
            this.proxyWebSocket = proxyWebSocket;
            return this;
        }

        public Builder messageProvider(MessageProvider messageProvider) {
            this.messageProvider = messageProvider;
            return this;
        }

        public Builder activeMode(boolean isActiveMode) {
            this.isActiveMode = isActiveMode;
            return this;
        }

        public Builder templateMessages(List<String> messages) {
            this.templateMessages = messages;
            return this;
        }

        public ScanContext build() {
            if (api == null) {
                throw new IllegalStateException("MontoyaApi is required");
            }
            return new ScanContext(this);
        }
    }
}
