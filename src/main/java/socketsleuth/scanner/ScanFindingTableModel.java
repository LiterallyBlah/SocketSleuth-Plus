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

import javax.swing.table.AbstractTableModel;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

/**
 * Table model for displaying scan findings in the results window.
 */
public class ScanFindingTableModel extends AbstractTableModel {

    private static final long serialVersionUID = 1L;

    private final List<ScanFinding> findings = new ArrayList<>();
    private final String[] columns = {"ID", "Severity", "Category", "Title", "URL"};
    private final Class<?>[] columnTypes = {Integer.class, String.class, String.class, String.class, String.class};

    private int nextId = 1;

    /**
     * Add a finding to the table.
     */
    public void addFinding(ScanFinding finding) {
        // Create a new finding with the assigned ID if not already set
        ScanFinding findingWithId = new ScanFinding.Builder()
                .id(nextId++)
                .title(finding.getTitle())
                .description(finding.getDescription())
                .severity(finding.getSeverity())
                .category(finding.getCategory())
                .evidence(finding.getEvidence())
                .remediation(finding.getRemediation())
                .request(finding.getRequest())
                .response(finding.getResponse())
                .socketId(finding.getSocketId())
                .url(finding.getUrl())
                .timestamp(finding.getTimestamp())
                .build();

        int index = findings.size();
        findings.add(findingWithId);
        fireTableRowsInserted(index, index);
    }

    /**
     * Get a finding by row index.
     */
    public ScanFinding getFinding(int row) {
        if (row >= 0 && row < findings.size()) {
            return findings.get(row);
        }
        return null;
    }

    /**
     * Get all findings.
     */
    public List<ScanFinding> getFindings() {
        return new ArrayList<>(findings);
    }

    /**
     * Clear all findings.
     */
    public void clear() {
        int size = findings.size();
        if (size > 0) {
            findings.clear();
            nextId = 1;
            fireTableRowsDeleted(0, size - 1);
        }
    }

    /**
     * Get count of findings by severity.
     */
    public Map<ScanSeverity, Integer> getCountBySeverity() {
        Map<ScanSeverity, Integer> counts = new EnumMap<>(ScanSeverity.class);
        for (ScanSeverity severity : ScanSeverity.values()) {
            counts.put(severity, 0);
        }
        for (ScanFinding finding : findings) {
            counts.merge(finding.getSeverity(), 1, Integer::sum);
        }
        return counts;
    }

    /**
     * Get a summary string of finding counts by severity.
     */
    public String getSeveritySummary() {
        Map<ScanSeverity, Integer> counts = getCountBySeverity();
        StringBuilder sb = new StringBuilder();
        boolean first = true;
        for (ScanSeverity severity : ScanSeverity.values()) {
            int count = counts.get(severity);
            if (count > 0) {
                if (!first) {
                    sb.append(", ");
                }
                sb.append(count).append(" ").append(severity.getDisplayName());
                first = false;
            }
        }
        return sb.length() > 0 ? sb.toString() : "No findings";
    }

    @Override
    public int getRowCount() {
        return findings.size();
    }

    @Override
    public int getColumnCount() {
        return columns.length;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        ScanFinding finding = findings.get(rowIndex);
        switch (columnIndex) {
            case 0:
                return finding.getId();
            case 1:
                return finding.getSeverity().getDisplayName();
            case 2:
                return finding.getCategory().getDisplayName();
            case 3:
                return finding.getTitle();
            case 4:
                return finding.getUrl() != null ? finding.getUrl() : "";
            default:
                return null;
        }
    }

    @Override
    public String getColumnName(int column) {
        return columns[column];
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        return columnTypes[columnIndex];
    }
}
