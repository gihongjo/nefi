import React, { useEffect, useState, useCallback } from "react";
import TimeRangeSelector, {
  TimeRange,
  timeRangeToSince,
} from "../components/TimeRangeSelector";
import StatusBadge from "../components/StatusBadge";
import { getRequests, HTTPRequestEvent } from "../api/client";

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
    minWidth: "140px",
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
  methodBadge: {
    display: "inline-block",
    padding: "2px 6px",
    fontSize: "11px",
    fontWeight: 700,
    fontFamily: "monospace",
    borderRadius: "3px",
    minWidth: "48px",
    textAlign: "center" as const,
  },
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function methodColor(method: string): React.CSSProperties {
  const colors: Record<string, { bg: string; text: string }> = {
    GET: { bg: "#1c2d3d", text: "#58a6ff" },
    POST: { bg: "#1b3d2a", text: "#3fb950" },
    PUT: { bg: "#3d2e1b", text: "#d29922" },
    PATCH: { bg: "#3d2e1b", text: "#d29922" },
    DELETE: { bg: "#3d1b1b", text: "#f85149" },
  };
  const c = colors[method.toUpperCase()] ?? { bg: "#30363d", text: "#8b949e" };
  return { backgroundColor: c.bg, color: c.text };
}

function latencyColor(ms: number): string {
  if (ms > 1000) return "#f85149";
  if (ms > 200) return "#d29922";
  return "#e6edf3";
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

const PAGE_SIZE = 50;

const RequestsPage: React.FC = () => {
  const [requests, setRequests] = useState<HTTPRequestEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [timeRange, setTimeRange] = useState<TimeRange>("15m");
  const [namespace, setNamespace] = useState("");
  const [service, setService] = useState("");
  const [method, setMethod] = useState("");
  const [statusMin, setStatusMin] = useState("");
  const [statusMax, setStatusMax] = useState("");
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
      if (method) params.method = method;
      if (statusMin) params.status_min = parseInt(statusMin, 10);
      if (statusMax) params.status_max = parseInt(statusMax, 10);

      const data = await getRequests(params);
      setRequests(data);
    } catch (err) {
      console.error("Failed to fetch requests:", err);
    } finally {
      setLoading(false);
    }
  }, [timeRange, namespace, service, method, statusMin, statusMax, offset]);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  useEffect(() => {
    setOffset(0);
  }, [timeRange, namespace, service, method, statusMin, statusMax]);

  return (
    <div>
      <div style={styles.header}>
        <h1 style={styles.title}>HTTP / gRPC Requests</h1>
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
        <div>
          <span style={styles.filterLabel}>Method:</span>
          <input
            style={{ ...styles.filterInput, minWidth: "80px" }}
            type="text"
            placeholder="GET"
            value={method}
            onChange={(e) => setMethod(e.target.value.toUpperCase())}
          />
        </div>
        <div>
          <span style={styles.filterLabel}>Status:</span>
          <input
            style={{ ...styles.filterInput, minWidth: "60px", width: "70px" }}
            type="text"
            placeholder="200"
            value={statusMin}
            onChange={(e) => setStatusMin(e.target.value)}
          />
          <span style={{ color: "#484f58", margin: "0 4px" }}>-</span>
          <input
            style={{ ...styles.filterInput, minWidth: "60px", width: "70px" }}
            type="text"
            placeholder="599"
            value={statusMax}
            onChange={(e) => setStatusMax(e.target.value)}
          />
        </div>
      </div>

      <div style={styles.tableContainer}>
        <table style={styles.table}>
          <thead>
            <tr>
              <th style={styles.th}>Timestamp</th>
              <th style={styles.th}>Source</th>
              <th style={styles.th}>Destination</th>
              <th style={styles.th}>Method</th>
              <th style={styles.th}>Path</th>
              <th style={styles.th}>Status</th>
              <th style={styles.th}>Latency</th>
            </tr>
          </thead>
          <tbody>
            {loading && requests.length === 0 ? (
              <tr>
                <td
                  style={{ ...styles.td, textAlign: "center", color: "#8b949e" }}
                  colSpan={7}
                >
                  Loading...
                </td>
              </tr>
            ) : requests.length === 0 ? (
              <tr>
                <td
                  style={{ ...styles.td, textAlign: "center", color: "#484f58" }}
                  colSpan={7}
                >
                  No requests found
                </td>
              </tr>
            ) : (
              requests.map((req, i) => (
                <tr
                  key={i}
                  style={{
                    backgroundColor:
                      i % 2 === 0 ? "transparent" : "rgba(22,27,34,0.5)",
                  }}
                >
                  <td
                    style={{ ...styles.td, ...styles.mono, fontSize: "12px" }}
                  >
                    {new Date(req.timestamp).toLocaleString()}
                  </td>
                  <td style={styles.td}>
                    <div style={{ fontSize: "13px" }}>
                      {req.source_service || "unknown"}
                    </div>
                    <div style={{ fontSize: "11px", color: "#484f58" }}>
                      {req.source_pod}
                    </div>
                  </td>
                  <td style={styles.td}>
                    <div style={{ fontSize: "13px" }}>
                      {req.destination_service || "unknown"}
                    </div>
                    <div style={{ fontSize: "11px", color: "#484f58" }}>
                      {req.destination_pod}
                    </div>
                  </td>
                  <td style={styles.td}>
                    <span
                      style={{
                        ...styles.methodBadge,
                        ...methodColor(req.method),
                      }}
                    >
                      {req.method}
                    </span>
                  </td>
                  <td
                    style={{
                      ...styles.td,
                      ...styles.mono,
                      maxWidth: "240px",
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      whiteSpace: "nowrap",
                    }}
                    title={req.path}
                  >
                    {req.path}
                  </td>
                  <td style={styles.td}>
                    <StatusBadge statusCode={req.status_code} />
                  </td>
                  <td
                    style={{
                      ...styles.td,
                      ...styles.mono,
                      color: latencyColor(req.latency_ms),
                    }}
                  >
                    {req.latency_ms.toFixed(1)}ms
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
          Showing {offset + 1} - {offset + requests.length}
        </span>
        <button
          style={{
            ...styles.pageButton,
            ...(requests.length < PAGE_SIZE ? styles.pageButtonDisabled : {}),
          }}
          disabled={requests.length < PAGE_SIZE}
          onClick={() => setOffset(offset + PAGE_SIZE)}
        >
          Next
        </button>
      </div>
    </div>
  );
};

export default RequestsPage;
