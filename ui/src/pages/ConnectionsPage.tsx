import React, { useEffect, useState, useCallback } from "react";
import TimeRangeSelector, {
  TimeRange,
  timeRangeToSince,
} from "../components/TimeRangeSelector";
import { getConnections, ConnectionEvent } from "../api/client";

// ---------------------------------------------------------------------------
// Styles
// ---------------------------------------------------------------------------

const styles: Record<string, React.CSSProperties> = {
  header: {
    display: "flex",
    justifyContent: "space-between",
    alignItems: "center",
    marginBottom: "24px",
  },
  title: {
    fontSize: "20px",
    fontWeight: 600,
  },
  filters: {
    display: "flex",
    gap: "12px",
    marginBottom: "16px",
    alignItems: "center",
    flexWrap: "wrap" as const,
  },
  filterInput: {
    backgroundColor: "#0d1117",
    border: "1px solid #30363d",
    borderRadius: "6px",
    padding: "6px 12px",
    fontSize: "13px",
    color: "#e6edf3",
    outline: "none",
    minWidth: "160px",
  },
  filterLabel: {
    fontSize: "12px",
    color: "#8b949e",
    marginRight: "4px",
  },
  tableContainer: {
    backgroundColor: "#161b22",
    borderRadius: "8px",
    border: "1px solid #30363d",
    overflow: "hidden",
  },
  table: {
    width: "100%",
    borderCollapse: "collapse" as const,
    fontSize: "13px",
  },
  th: {
    textAlign: "left" as const,
    padding: "10px 12px",
    color: "#8b949e",
    fontWeight: 500,
    borderBottom: "1px solid #30363d",
    fontSize: "12px",
    backgroundColor: "#161b22",
    position: "sticky" as const,
    top: 0,
  },
  td: {
    padding: "8px 12px",
    borderBottom: "1px solid #21262d",
    color: "#e6edf3",
  },
  mono: {
    fontFamily: "monospace",
  },
  pagination: {
    display: "flex",
    justifyContent: "space-between",
    alignItems: "center",
    marginTop: "16px",
  },
  pageButton: {
    padding: "6px 16px",
    backgroundColor: "#21262d",
    border: "1px solid #30363d",
    borderRadius: "6px",
    color: "#e6edf3",
    fontSize: "13px",
    cursor: "pointer",
  },
  pageButtonDisabled: {
    opacity: 0.4,
    cursor: "default",
  },
  pageInfo: {
    fontSize: "13px",
    color: "#8b949e",
  },
  loading: {
    color: "#8b949e",
    textAlign: "center" as const,
    padding: "40px",
  },
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms.toFixed(0)}ms`;
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
  return `${(ms / 60000).toFixed(1)}m`;
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

const PAGE_SIZE = 50;

const ConnectionsPage: React.FC = () => {
  const [connections, setConnections] = useState<ConnectionEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [timeRange, setTimeRange] = useState<TimeRange>("15m");
  const [namespace, setNamespace] = useState("");
  const [service, setService] = useState("");
  const [offset, setOffset] = useState(0);

  const fetchData = useCallback(async () => {
    setLoading(true);
    try {
      const params: Record<string, string | number> = {
        since: timeRangeToSince(timeRange),
        limit: PAGE_SIZE,
        offset,
      };
      if (namespace) params.namespace = namespace;
      if (service) params.service = service;

      const data = await getConnections(params);
      setConnections(data);
    } catch (err) {
      console.error("Failed to fetch connections:", err);
    } finally {
      setLoading(false);
    }
  }, [timeRange, namespace, service, offset]);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  // Reset offset when filters change
  useEffect(() => {
    setOffset(0);
  }, [timeRange, namespace, service]);

  return (
    <div>
      <div style={styles.header}>
        <h1 style={styles.title}>Connection Events</h1>
        <TimeRangeSelector value={timeRange} onChange={setTimeRange} />
      </div>

      <div style={styles.filters}>
        <div>
          <span style={styles.filterLabel}>Namespace:</span>
          <input
            style={styles.filterInput}
            type="text"
            placeholder="All namespaces"
            value={namespace}
            onChange={(e) => setNamespace(e.target.value)}
          />
        </div>
        <div>
          <span style={styles.filterLabel}>Service:</span>
          <input
            style={styles.filterInput}
            type="text"
            placeholder="All services"
            value={service}
            onChange={(e) => setService(e.target.value)}
          />
        </div>
      </div>

      <div style={styles.tableContainer}>
        <table style={styles.table}>
          <thead>
            <tr>
              <th style={styles.th}>Timestamp</th>
              <th style={styles.th}>Source (Pod / Service)</th>
              <th style={styles.th}>Destination (Pod / Service)</th>
              <th style={styles.th}>Bytes Sent</th>
              <th style={styles.th}>Bytes Recv</th>
              <th style={styles.th}>Duration</th>
              <th style={styles.th}>Retransmits</th>
            </tr>
          </thead>
          <tbody>
            {loading && connections.length === 0 ? (
              <tr>
                <td style={styles.loading} colSpan={7}>
                  Loading...
                </td>
              </tr>
            ) : connections.length === 0 ? (
              <tr>
                <td
                  style={{ ...styles.td, textAlign: "center", color: "#484f58" }}
                  colSpan={7}
                >
                  No connections found
                </td>
              </tr>
            ) : (
              connections.map((conn, i) => (
                <tr
                  key={i}
                  style={{
                    backgroundColor:
                      i % 2 === 0 ? "transparent" : "rgba(22,27,34,0.5)",
                  }}
                >
                  <td style={{ ...styles.td, ...styles.mono, fontSize: "12px" }}>
                    {new Date(conn.timestamp).toLocaleString()}
                  </td>
                  <td style={styles.td}>
                    <div style={{ fontSize: "13px" }}>
                      {conn.source_service || "unknown"}
                    </div>
                    <div style={{ fontSize: "11px", color: "#484f58" }}>
                      {conn.source_pod}
                    </div>
                  </td>
                  <td style={styles.td}>
                    <div style={{ fontSize: "13px" }}>
                      {conn.destination_service || "unknown"}
                    </div>
                    <div style={{ fontSize: "11px", color: "#484f58" }}>
                      {conn.destination_pod}
                    </div>
                  </td>
                  <td style={{ ...styles.td, ...styles.mono }}>
                    {formatBytes(conn.bytes_sent)}
                  </td>
                  <td style={{ ...styles.td, ...styles.mono }}>
                    {formatBytes(conn.bytes_received)}
                  </td>
                  <td style={{ ...styles.td, ...styles.mono }}>
                    {formatDuration(conn.duration_ms)}
                  </td>
                  <td
                    style={{
                      ...styles.td,
                      ...styles.mono,
                      color:
                        conn.retransmits > 0 ? "#f85149" : "#8b949e",
                    }}
                  >
                    {conn.retransmits}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      <div style={styles.pagination}>
        <button
          style={{
            ...styles.pageButton,
            ...(offset === 0 ? styles.pageButtonDisabled : {}),
          }}
          disabled={offset === 0}
          onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}
        >
          Previous
        </button>
        <span style={styles.pageInfo}>
          Showing {offset + 1} - {offset + connections.length}
        </span>
        <button
          style={{
            ...styles.pageButton,
            ...(connections.length < PAGE_SIZE ? styles.pageButtonDisabled : {}),
          }}
          disabled={connections.length < PAGE_SIZE}
          onClick={() => setOffset(offset + PAGE_SIZE)}
        >
          Next
        </button>
      </div>
    </div>
  );
};

export default ConnectionsPage;
