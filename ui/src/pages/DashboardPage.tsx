import React, { useEffect, useState, useCallback } from "react";
import {
  BarChart,
  Bar,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Cell,
} from "recharts";
import TimeRangeSelector, {
  TimeRange,
  timeRangeToSince,
} from "../components/TimeRangeSelector";
import {
  getServices,
  getDependencies,
  getTraffic,
  getConnections,
  TopologyNode,
  DependencyLink,
  TimeSeriesPoint,
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
  summaryCards: {
    display: "grid",
    gridTemplateColumns: "repeat(4, 1fr)",
    gap: "16px",
    marginBottom: "24px",
  },
  card: {
    backgroundColor: "#161b22",
    borderRadius: "8px",
    border: "1px solid #30363d",
    padding: "20px",
  },
  cardLabel: {
    fontSize: "12px",
    fontWeight: 500,
    color: "#8b949e",
    textTransform: "uppercase" as const,
    letterSpacing: "0.5px",
    marginBottom: "8px",
  },
  cardValue: {
    fontSize: "28px",
    fontWeight: 700,
    fontFamily: "monospace",
  },
  chartsGrid: {
    display: "grid",
    gridTemplateColumns: "1fr 1fr",
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
    marginBottom: "16px",
    textTransform: "uppercase" as const,
    letterSpacing: "0.5px",
  },
  fullWidthChart: {
    backgroundColor: "#161b22",
    borderRadius: "8px",
    border: "1px solid #30363d",
    padding: "16px",
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

function formatTime(iso: string): string {
  return new Date(iso).toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
  });
}

function errorRateColor(rate: number): string {
  if (rate > 0.05) return "#f85149";
  if (rate > 0.01) return "#d29922";
  return "#3fb950";
}

function latencyColor(ms: number): string {
  if (ms > 500) return "#f85149";
  if (ms > 200) return "#d29922";
  return "#58a6ff";
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

const DashboardPage: React.FC = () => {
  const [timeRange, setTimeRange] = useState<TimeRange>("1h");
  const [services, setServices] = useState<TopologyNode[]>([]);
  const [dependencies, setDependencies] = useState<DependencyLink[]>([]);
  const [trafficData, setTrafficData] = useState<
    { time: string; value: number }[]
  >([]);
  const [connectionCount, setConnectionCount] = useState(0);
  const [loading, setLoading] = useState(true);

  const fetchData = useCallback(async () => {
    setLoading(true);
    const since = timeRangeToSince(timeRange);
    const params = { since };

    try {
      const [svc, deps, traffic, conns] = await Promise.all([
        getServices(params),
        getDependencies(params),
        getTraffic(params),
        getConnections({ since, limit: 1 }),
      ]);

      setServices(svc);
      setDependencies(deps);
      setTrafficData(
        traffic.map((p: TimeSeriesPoint) => ({
          time: formatTime(p.timestamp),
          value: p.value,
        }))
      );
      // Use the presence of data as a rough count indicator
      // The real count would come from a dedicated endpoint
      setConnectionCount(conns.length > 0 ? conns.length : 0);
    } catch (err) {
      console.error("Failed to fetch dashboard data:", err);
    } finally {
      setLoading(false);
    }
  }, [timeRange]);

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 15000);
    return () => clearInterval(interval);
  }, [fetchData]);

  // Top 10 by error rate
  const topErrorServices = [...services]
    .sort((a, b) => b.error_rate - a.error_rate)
    .slice(0, 10)
    .map((s) => ({
      name: s.service,
      errorRate: parseFloat((s.error_rate * 100).toFixed(2)),
    }));

  // Top 10 by latency
  const topLatencyEdges = [...dependencies]
    .sort((a, b) => b.p99_latency_ms - a.p99_latency_ms)
    .slice(0, 10)
    .map((d) => ({
      name: `${d.source} -> ${d.destination}`,
      latency: parseFloat(d.p99_latency_ms.toFixed(1)),
    }));

  const tooltipStyle = {
    backgroundColor: "#161b22",
    border: "1px solid #30363d",
    borderRadius: "6px",
    fontSize: "12px",
  };

  if (loading && services.length === 0) {
    return (
      <div>
        <div style={styles.header}>
          <h1 style={styles.title}>Dashboard</h1>
          <TimeRangeSelector value={timeRange} onChange={setTimeRange} />
        </div>
        <div style={styles.loading}>Loading dashboard data...</div>
      </div>
    );
  }

  return (
    <div>
      <div style={styles.header}>
        <h1 style={styles.title}>Dashboard</h1>
        <TimeRangeSelector value={timeRange} onChange={setTimeRange} />
      </div>

      {/* Summary Cards */}
      <div style={styles.summaryCards}>
        <div style={styles.card}>
          <div style={styles.cardLabel}>Services</div>
          <div style={{ ...styles.cardValue, color: "#58a6ff" }}>
            {services.length}
          </div>
        </div>
        <div style={styles.card}>
          <div style={styles.cardLabel}>Dependencies</div>
          <div style={{ ...styles.cardValue, color: "#bc8cff" }}>
            {dependencies.length}
          </div>
        </div>
        <div style={styles.card}>
          <div style={styles.cardLabel}>Connections</div>
          <div style={{ ...styles.cardValue, color: "#3fb950" }}>
            {connectionCount}
          </div>
        </div>
        <div style={styles.card}>
          <div style={styles.cardLabel}>Avg Error Rate</div>
          <div
            style={{
              ...styles.cardValue,
              color: errorRateColor(
                services.length > 0
                  ? services.reduce((s, svc) => s + svc.error_rate, 0) /
                      services.length
                  : 0
              ),
            }}
          >
            {services.length > 0
              ? (
                  (services.reduce((s, svc) => s + svc.error_rate, 0) /
                    services.length) *
                  100
                ).toFixed(2)
              : "0.00"}
            %
          </div>
        </div>
      </div>

      {/* Charts Grid */}
      <div style={styles.chartsGrid}>
        {/* Top Error Rate Services */}
        <div style={styles.chartCard}>
          <div style={styles.chartTitle}>Top 10 Error Rate Services</div>
          {topErrorServices.length === 0 ? (
            <div style={{ color: "#484f58", fontSize: "13px", padding: "20px" }}>
              No data available
            </div>
          ) : (
            <ResponsiveContainer width="100%" height={280}>
              <BarChart
                data={topErrorServices}
                layout="vertical"
                margin={{ left: 80 }}
              >
                <CartesianGrid strokeDasharray="3 3" stroke="#21262d" />
                <XAxis type="number" stroke="#484f58" fontSize={11} unit="%" />
                <YAxis
                  type="category"
                  dataKey="name"
                  stroke="#484f58"
                  fontSize={11}
                  width={80}
                />
                <Tooltip contentStyle={tooltipStyle} />
                <Bar dataKey="errorRate" name="Error Rate %" radius={[0, 4, 4, 0]}>
                  {topErrorServices.map((entry, index) => (
                    <Cell
                      key={index}
                      fill={errorRateColor(entry.errorRate / 100)}
                    />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>

        {/* Top Latency Edges */}
        <div style={styles.chartCard}>
          <div style={styles.chartTitle}>Top 10 High Latency Edges (P99)</div>
          {topLatencyEdges.length === 0 ? (
            <div style={{ color: "#484f58", fontSize: "13px", padding: "20px" }}>
              No data available
            </div>
          ) : (
            <ResponsiveContainer width="100%" height={280}>
              <BarChart
                data={topLatencyEdges}
                layout="vertical"
                margin={{ left: 120 }}
              >
                <CartesianGrid strokeDasharray="3 3" stroke="#21262d" />
                <XAxis type="number" stroke="#484f58" fontSize={11} unit="ms" />
                <YAxis
                  type="category"
                  dataKey="name"
                  stroke="#484f58"
                  fontSize={10}
                  width={120}
                />
                <Tooltip contentStyle={tooltipStyle} />
                <Bar dataKey="latency" name="P99 Latency (ms)" radius={[0, 4, 4, 0]}>
                  {topLatencyEdges.map((entry, index) => (
                    <Cell
                      key={index}
                      fill={latencyColor(entry.latency)}
                    />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>

      {/* Traffic Trend */}
      <div style={styles.fullWidthChart}>
        <div style={styles.chartTitle}>Total Traffic Trend</div>
        {trafficData.length === 0 ? (
          <div style={{ color: "#484f58", fontSize: "13px", padding: "20px" }}>
            No traffic data available
          </div>
        ) : (
          <ResponsiveContainer width="100%" height={240}>
            <AreaChart data={trafficData}>
              <defs>
                <linearGradient id="trafficGradient" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#58a6ff" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#58a6ff" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#21262d" />
              <XAxis dataKey="time" stroke="#484f58" fontSize={11} />
              <YAxis stroke="#484f58" fontSize={11} />
              <Tooltip contentStyle={tooltipStyle} />
              <Area
                type="monotone"
                dataKey="value"
                stroke="#58a6ff"
                strokeWidth={2}
                fill="url(#trafficGradient)"
                name="Requests"
              />
            </AreaChart>
          </ResponsiveContainer>
        )}
      </div>
    </div>
  );
};

export default DashboardPage;
