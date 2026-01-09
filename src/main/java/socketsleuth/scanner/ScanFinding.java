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

import java.time.LocalDateTime;

/**
 * Represents a security finding discovered during a WebSocket scan.
 */
public class ScanFinding {
    private final int id;
    private final String title;
    private final String description;
    private final ScanSeverity severity;
    private final ScanCheckCategory category;
    private final String evidence;
    private final String remediation;
    private final String request;
    private final String response;
    private final int socketId;
    private final String url;
    private final LocalDateTime timestamp;

    private ScanFinding(Builder builder) {
        this.id = builder.id;
        this.title = builder.title;
        this.description = builder.description;
        this.severity = builder.severity;
        this.category = builder.category;
        this.evidence = builder.evidence;
        this.remediation = builder.remediation;
        this.request = builder.request;
        this.response = builder.response;
        this.socketId = builder.socketId;
        this.url = builder.url;
        this.timestamp = builder.timestamp != null ? builder.timestamp : LocalDateTime.now();
    }

    public int getId() {
        return id;
    }

    public String getTitle() {
        return title;
    }

    public String getDescription() {
        return description;
    }

    public ScanSeverity getSeverity() {
        return severity;
    }

    public ScanCheckCategory getCategory() {
        return category;
    }

    public String getEvidence() {
        return evidence;
    }

    public String getRemediation() {
        return remediation;
    }

    public String getRequest() {
        return request;
    }

    public String getResponse() {
        return response;
    }

    public int getSocketId() {
        return socketId;
    }

    public String getUrl() {
        return url;
    }

    public LocalDateTime getTimestamp() {
        return timestamp;
    }

    @Override
    public String toString() {
        return String.format("[%s] %s - %s", severity.getDisplayName(), category.getDisplayName(), title);
    }

    /**
     * Builder for constructing ScanFinding instances.
     */
    public static class Builder {
        private int id;
        private String title;
        private String description;
        private ScanSeverity severity;
        private ScanCheckCategory category;
        private String evidence;
        private String remediation;
        private String request;
        private String response;
        private int socketId;
        private String url;
        private LocalDateTime timestamp;

        public Builder() {
        }

        public Builder id(int id) {
            this.id = id;
            return this;
        }

        public Builder title(String title) {
            this.title = title;
            return this;
        }

        public Builder description(String description) {
            this.description = description;
            return this;
        }

        public Builder severity(ScanSeverity severity) {
            this.severity = severity;
            return this;
        }

        public Builder category(ScanCheckCategory category) {
            this.category = category;
            return this;
        }

        public Builder evidence(String evidence) {
            this.evidence = evidence;
            return this;
        }

        public Builder remediation(String remediation) {
            this.remediation = remediation;
            return this;
        }

        public Builder request(String request) {
            this.request = request;
            return this;
        }

        public Builder response(String response) {
            this.response = response;
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

        public Builder timestamp(LocalDateTime timestamp) {
            this.timestamp = timestamp;
            return this;
        }

        public ScanFinding build() {
            if (title == null || title.isEmpty()) {
                throw new IllegalStateException("Title is required");
            }
            if (severity == null) {
                throw new IllegalStateException("Severity is required");
            }
            if (category == null) {
                throw new IllegalStateException("Category is required");
            }
            return new ScanFinding(this);
        }
    }
}
