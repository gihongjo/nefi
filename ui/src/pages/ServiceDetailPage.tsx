import React, { useEffect, useState, useCallback } from "react";
import { useParams, Link } from "react-router-dom";
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from "recharts";
import TimeRangeSelector, {
  TimeRange,
  timeRangeToSince,
} from "../components/TimeRangeSelector";
import StatusBadge from "../components/StatusBadge";
import {
  getLatencies,
  getCallRates,
  getErrorRates,
  getRequests,
  TimeSeriesPoint,
  HTTPRequestEvent,
} from "../api/client";

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
  breadcrumb: {
    fontSize: "13px",
    color: "#8b949e",
    marginBottom: "4px",
  },
  breadcrumbLink: {
    color: "#58a6ff",
    textDecoration: "none",
  },
  chartsGrid: {
    display: "grid",
    gridTemplateColumns: "1fr 1fr 1fr",
    gap: "16px",
    marginBottom: "24px",
  },
  chartCard: {
    backgroundColor: "#161b22",
    borderRadius: "8px",
    border: "1px solid #30363d",
    padding: "16px",
  },
  chartTitle: {
    fontSize: "13px",
    fontWeight: 600,
    color: "#8b949e",
    marginBottom: "12px",
    textTransform: "uppercase" as const,
    letterSpacing: "0.5px",
  },
  tableContainer: {
    backgroundColor: "#161b22",
    borderRadius: "8px",
    border: "1px solid #30363d",
    overflow: "hidden",
  },
  tableHeader: {
    padding: "12px 16px",
    fontSize: "14px",
    fontWeight: 600,
    borderBottom: "1px solid #30363d",
  },
  table: {
    width: "100%",
    borderCollapse: "collapse" as const,
    fontSize: "13px",
  },
  th: {
    textAlign: "left" as const,
    padding: "8px 12px",
    color: "#8b949e",
    fontWeight: 500,
    borderBottom: "1px solid #21262d",
    fontSize: "12px",
  },
  td: {
    padding: "8px 12px",
    borderBottom: "1px solid #21262d",
    color: "#e6edf3",
  },
  loading: {
    color: "#8b949e",
    textAlign: "center" as const,
    padding: "40px",
  },
};

// ---------------------------------------------------------------------------
// Data transform
// ---------------------------------------------------------------------------

function formatTime(iso: string): string {
  const d = new Date(iso);
  return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

interface LatencyChartPoint {
  time: string;
  p50?: number;
  p95?: number;
  p99?: number;
}

function groupLatencies(points: TimeSeriesPoint[]): LatencyChartPoint[] {
  const map = new Map<string, LatencyChartPoint>();
  for (const p of points) {
    const time = formatTime(p.timestamp);
    const existing = map.get(time) ?? { time };
    const label = p.label ?? "p50";
    if (label === "p50") existing.p50 = p.value;
    else if (label === "p95") existing.p95 = p.value;
    else if (label === "p99") existing.p99 = p.value;
    else existing.p50 = p.value;
    map.set(time, existing);
  }
  return Array.from(map.values());
}

interface SimpleChartPoint {
  time: string;
  value: number;
}

function toSimpleChart(points: TimeSeriesPoint[]): SimpleChartPoint[] {
  return points.map((p) => ({
    time: formatTime(p.timestamp),
    value: p.value,
  }));
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

const ServiceDetailPage: React.FC = () => {
  const { name } = useParams<{ name: string }>();
  const [timeRange, setTimeRange] = useState<TimeRange>("15m");
  const [latencyData, setLatencyData] = useState<LatencyChartPoint[]>([]);
  const [callRateData, setCallRateData] = useState<SimpleChartPoint[]>([]);
  const [errorRateData, setErrorRateData] = useState<SimpleChartPoint[]>([]);
  const [requests, setRequests] = useState<HTTPRequestEvent[]>([]);
  const [loading, setLoading] = useState(true);

  const fetchData = useCallback(async () => {
    if (!name) return;
    setLoading(true);
    const since = timeRangeToSince(timeRange);
    const params = { since };

    try {
      const [latencies, callRates, errorRates, reqs] = await Promise.all([
        getLatencies(name, params),
        getCallRates(name, params),
        getErrorRates(name, params),
        getRequests({ service: name, since, limit: 50 }),
      ]);

      setLatencyData(groupLatencies(latencies));
      setCallRateData(toSimpleChart(callRates));
      setErrorRateData(toSimpleChart(errorRates));
      setRequests(reqs);
    } catch (err) {
      console.error("Failed to fetch service data:", err);
    } finally {
      setLoading(false);
    }
  }, [name, timeRange]);

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 10000);
    return () => clearInterval(interval);
  }, [fetchData]);

  if (!name) {
    return <div style={styles.loading}>No service specified</div>;
  }

  const tooltipStyle = {
    backgroundColor: "#161b22",
    border: "1px solid #30363d",
    borderRadius: "6px",
    fontSize: "12px",
  };

  return (
    <div>
      <div style={styles.breadcrumb}>
        <Link to="/topology" style={styles.breadcrumbLink}>
          Topology
        </Link>
        {" / "}
        {name}
      </div>
      <div style={styles.header}>
        <h1 style={styles.title}>{name}</h1>
        <TimeRangeSelector value={timeRange} onChange={setTimeRange} />
      </div>

      {loading && latencyData.length === 0 ? (
        <div style={styles.loading}>Loading service metrics...</div>
      ) : (
        <>
          <div style={styles.chartsGrid}>
            {/* Latency Chart */}
            <div style={styles.chartCard}>
              <div style={styles.chartTitle}>Latency (ms)</div>
              <ResponsiveContainer width="100%" height={200}>
                <LineChart data={latencyData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#21262d" />
                  <XAxis dataKey="time" stroke="#484f58" fontSize={11} />
                  <YAxis stroke="#484f58" fontSize={11} />
                  <Tooltip contentStyle={tooltipStyle} />
                  <Legend />
                  <Line
                    type="monotone"
                    dataKey="p50"
                    stroke="#3fb950"
                    strokeWidth={2}
                    dot={false}
                    name="P50"
                  />
                  <Line
                    type="monotone"
                    dataKey="p95"
                    stroke="#d29922"
                    strokeWidth={2}
                    dot={false}
                    name="P95"
                  />
                  <Line
                    type="monotone"
                    dataKey="p99"
                    stroke="#f85149"
                    strokeWidth={2}
                    dot={false}
                    name="P99"
                  />
                </LineChart>
              </ResponsiveContainer>
            </div>

            {/* Call Rate Chart */}
            <div style={styles.chartCard}>
              <div style={styles.chartTitle}>Call Rate (req/s)</div>
              <ResponsiveContainer width="100%" height={200}>
                <LineChart data={callRateData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#21262d" />
                  <XAxis dataKey="time" stroke="#484f58" fontSize={11} />
                  <YAxis stroke="#484f58" fontSize={11} />
                  <Tooltip contentStyle={tooltipStyle} />
                  <Line
                    type="monotone"
                    dataKey="value"
                    stroke="#58a6ff"
                    strokeWidth={2}
                    dot={false}
                    name="Call Rate"
                  />
                </LineChart>
              </ResponsiveContainer>
            </div>

            {/* Error Rate Chart */}
            <div style={styles.chartCard}>
              <div style={styles.chartTitle}>Error Rate (%)</div>
              <ResponsiveContainer width="100%" height={200}>
                <LineChart data={errorRateData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#21262d" />
                  <XAxis dataKey="time" stroke="#484f58" fontSize={11} />
                  <YAxis stroke="#484f58" fontSize={11} />
                  <Tooltip contentStyle={tooltipStyle} />
                  <Line
                    type="monotone"
                    dataKey="value"
                    stroke="#f85149"
                    strokeWidth={2}
                    dot={false}
                    name="Error Rate"
                  />
                </LineChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Recent Requests Table */}
          <div style={styles.tableContainer}>
            <div style={styles.tableHeader}>Recent Requests</div>
            <table style={styles.table}>
              <thead>
                <tr>
                  <th style={styles.th}>Time</th>
                  <th style={styles.th}>Source</th>
                  <th style={styles.th}>Method</th>
                  <th style={styles.th}>Path</th>
                  <th style={styles.th}>Status</th>
                  <th style={styles.th}>Latency</th>
                </tr>
              </thead>
              <tbody>
                {requests.length === 0 ? (
                  <tr>
                    <td
                      style={{ ...styles.td, textAlign: "center" }}
                      colSpan={6}
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
                          i % 2 === 0 ? "transparent" : "#161b2208",
                      }}
                    >
                      <td style={{ ...styles.td, fontFamily: "monospace" }}>
                        {new Date(req.timestamp).toLocaleTimeString()}
                      </td>
                      <td style={styles.td}>
                        {req.source_service || req.source_pod}
                      </td>
                      <td
                        style={{
                          ...styles.td,
                          fontFamily: "monospace",
                          fontWeight: 600,
                        }}
                      >
                        {req.method}
                      </td>
                      <td style={{ ...styles.td, fontFamily: "monospace" }}>
                        {req.path}
                      </td>
                      <td style={styles.td}>
                        <StatusBadge statusCode={req.status_code} />
                      </td>
                      <td style={{ ...styles.td, fontFamily: "monospace" }}>
                        {req.latency_ms.toFixed(1)}ms
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </>
      )}
    </div>
  );
};

export default ServiceDetailPage;
