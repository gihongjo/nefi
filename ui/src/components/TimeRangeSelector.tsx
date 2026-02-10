import React from "react";

export type TimeRange = "5m" | "15m" | "1h" | "6h" | "24h";

interface TimeRangeSelectorProps {
  value: TimeRange;
  onChange: (range: TimeRange) => void;
}

const RANGES: { label: string; value: TimeRange }[] = [
  { label: "5m", value: "5m" },
  { label: "15m", value: "15m" },
  { label: "1h", value: "1h" },
  { label: "6h", value: "6h" },
  { label: "24h", value: "24h" },
];

const styles: Record<string, React.CSSProperties> = {
  container: {
    display: "flex",
    gap: "4px",
    backgroundColor: "#161b22",
    borderRadius: "6px",
    padding: "4px",
    border: "1px solid #30363d",
  },
  button: {
    padding: "6px 14px",
    fontSize: "12px",
    fontWeight: 500,
    border: "none",
    borderRadius: "4px",
    cursor: "pointer",
    color: "#8b949e",
    backgroundColor: "transparent",
    transition: "background-color 0.15s, color 0.15s",
  },
  buttonActive: {
    color: "#e6edf3",
    backgroundColor: "#30363d",
  },
};

function timeRangeToSince(range: TimeRange): string {
  const now = new Date();
  const durations: Record<TimeRange, number> = {
    "5m": 5 * 60 * 1000,
    "15m": 15 * 60 * 1000,
    "1h": 60 * 60 * 1000,
    "6h": 6 * 60 * 60 * 1000,
    "24h": 24 * 60 * 60 * 1000,
  };
  return new Date(now.getTime() - durations[range]).toISOString();
}

export { timeRangeToSince };

const TimeRangeSelector: React.FC<TimeRangeSelectorProps> = ({
  value,
  onChange,
}) => {
  return (
    <div style={styles.container}>
      {RANGES.map((r) => (
        <button
          key={r.value}
          style={{
            ...styles.button,
            ...(value === r.value ? styles.buttonActive : {}),
          }}
          onClick={() => onChange(r.value)}
        >
          {r.label}
        </button>
      ))}
    </div>
  );
};

export default TimeRangeSelector;
