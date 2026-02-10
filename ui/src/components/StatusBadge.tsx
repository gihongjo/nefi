import React from "react";

interface StatusBadgeProps {
  statusCode: number;
}

function getStatusColor(code: number): { bg: string; text: string } {
  if (code >= 200 && code < 300) {
    return { bg: "#1b3d2a", text: "#3fb950" };
  }
  if (code >= 300 && code < 400) {
    return { bg: "#1c2d3d", text: "#58a6ff" };
  }
  if (code >= 400 && code < 500) {
    return { bg: "#3d2e1b", text: "#d29922" };
  }
  if (code >= 500) {
    return { bg: "#3d1b1b", text: "#f85149" };
  }
  return { bg: "#30363d", text: "#8b949e" };
}

const StatusBadge: React.FC<StatusBadgeProps> = ({ statusCode }) => {
  const colors = getStatusColor(statusCode);

  const style: React.CSSProperties = {
    display: "inline-block",
    padding: "2px 8px",
    fontSize: "12px",
    fontWeight: 600,
    fontFamily: "monospace",
    borderRadius: "4px",
    backgroundColor: colors.bg,
    color: colors.text,
  };

  return <span style={style}>{statusCode}</span>;
};

export default StatusBadge;
