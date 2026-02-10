import React, { useEffect, useState, useCallback, useRef } from "react";
import CytoscapeComponent from "react-cytoscapejs";
import type cytoscape from "cytoscape";
import {
  getTopology,
  connectTopologyWS,
  Topology,
  TopologyNode,
  TopologyEdge,
  TopologyWSHandle,
} from "../api/client";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function edgeColor(errorRate: number): string {
  if (errorRate > 0.05) return "#f85149";
  if (errorRate > 0.01) return "#d29922";
  return "#3fb950";
}

function edgeWidth(callCount: number): number {
  if (callCount > 1000) return 6;
  if (callCount > 100) return 4;
  if (callCount > 10) return 2.5;
  return 1.5;
}

function buildElements(
  topology: Topology
): cytoscape.ElementDefinition[] {
  const nodes: cytoscape.ElementDefinition[] = topology.nodes.map(
    (n: TopologyNode) => ({
      data: {
        id: n.id,
        label: n.service,
        namespace: n.namespace,
        version: n.version,
        nodeType: n.type,
        errorRate: n.error_rate,
        avgLatency: n.avg_latency_ms,
      },
    })
  );

  const edges: cytoscape.ElementDefinition[] = topology.edges.map(
    (e: TopologyEdge, i: number) => ({
      data: {
        id: `edge-${i}`,
        source: e.source,
        target: e.target,
        callCount: e.call_count,
        errorRate: e.error_rate,
        avgLatency: e.avg_latency_ms,
        protocol: e.protocol,
      },
    })
  );

  return [...nodes, ...edges];
}

// ---------------------------------------------------------------------------
// Styles
// ---------------------------------------------------------------------------

const pageStyles: Record<string, React.CSSProperties> = {
  container: {
    display: "flex",
    height: "calc(100vh - 48px)",
    gap: "16px",
  },
  graphContainer: {
    flex: 1,
    backgroundColor: "#0d1117",
    borderRadius: "8px",
    border: "1px solid #30363d",
    overflow: "hidden",
    position: "relative",
  },
  header: {
    display: "flex",
    justifyContent: "space-between",
    alignItems: "center",
    marginBottom: "16px",
  },
  title: {
    fontSize: "20px",
    fontWeight: 600,
  },
  statusDot: {
    display: "inline-block",
    width: "8px",
    height: "8px",
    borderRadius: "50%",
    marginRight: "8px",
  },
  statusText: {
    fontSize: "12px",
    color: "#8b949e",
    display: "flex",
    alignItems: "center",
  },
  detailPanel: {
    width: "320px",
    backgroundColor: "#161b22",
    borderRadius: "8px",
    border: "1px solid #30363d",
    padding: "20px",
    overflowY: "auto" as const,
  },
  detailTitle: {
    fontSize: "16px",
    fontWeight: 600,
    marginBottom: "16px",
    color: "#58a6ff",
  },
  detailRow: {
    display: "flex",
    justifyContent: "space-between",
    padding: "8px 0",
    borderBottom: "1px solid #21262d",
    fontSize: "13px",
  },
  detailLabel: {
    color: "#8b949e",
  },
  detailValue: {
    color: "#e6edf3",
    fontFamily: "monospace",
  },
  placeholder: {
    color: "#484f58",
    fontSize: "13px",
    textAlign: "center" as const,
    marginTop: "40px",
  },
};

const cytoscapeStylesheet: cytoscape.StylesheetStyle[] = [
  {
    selector: "node",
    style: {
      label: "data(label)",
      "text-valign": "bottom",
      "text-halign": "center",
      "text-margin-y": 8,
      "font-size": "11px",
      color: "#e6edf3",
      "background-color": "#1f6feb",
      width: 36,
      height: 36,
      "border-width": 2,
      "border-color": "#388bfd",
      "text-outline-width": 2,
      "text-outline-color": "#0d1117",
    } as cytoscape.Css.Node,
  },
  {
    selector: "node:selected",
    style: {
      "border-color": "#58a6ff",
      "border-width": 3,
      "background-color": "#388bfd",
    } as cytoscape.Css.Node,
  },
  {
    selector: "edge",
    style: {
      width: 2,
      "line-color": "#3fb950",
      "target-arrow-color": "#3fb950",
      "target-arrow-shape": "triangle",
      "curve-style": "bezier",
      "arrow-scale": 0.8,
    } as cytoscape.Css.Edge,
  },
];

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

const TopologyPage: React.FC = () => {
  const [topology, setTopology] = useState<Topology | null>(null);
  const [selectedNode, setSelectedNode] = useState<TopologyNode | null>(null);
  const [wsConnected, setWsConnected] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const wsRef = useRef<TopologyWSHandle | null>(null);
  const cyRef = useRef<cytoscape.Core | null>(null);

  // Fetch initial topology
  const fetchTopology = useCallback(async () => {
    try {
      const data = await getTopology();
      setTopology(data);
      setError(null);
    } catch (err) {
      setError("Failed to fetch topology");
      console.error(err);
    }
  }, []);

  // Connect WebSocket
  useEffect(() => {
    fetchTopology();

    wsRef.current = connectTopologyWS({
      onUpdate: (topo) => {
        setTopology(topo);
        setWsConnected(true);
      },
      onError: () => {
        setWsConnected(false);
      },
      onClose: () => {
        setWsConnected(false);
      },
    });

    // Fallback polling when WS is not available
    const pollInterval = setInterval(() => {
      if (!wsConnected) {
        fetchTopology();
      }
    }, 5000);

    return () => {
      wsRef.current?.close();
      clearInterval(pollInterval);
    };
  }, [fetchTopology, wsConnected]);

  // Apply dynamic edge styles after cy is ready
  useEffect(() => {
    if (!cyRef.current || !topology) return;
    const cy = cyRef.current;

    cy.edges().forEach((edge) => {
      const er = edge.data("errorRate") ?? 0;
      const cc = edge.data("callCount") ?? 0;
      edge.style({
        "line-color": edgeColor(er),
        "target-arrow-color": edgeColor(er),
        width: edgeWidth(cc),
      });
    });
  }, [topology]);

  const handleCyReady = (cy: cytoscape.Core) => {
    cyRef.current = cy;

    cy.on("tap", "node", (evt) => {
      const nodeId = evt.target.id();
      const node = topology?.nodes.find((n) => n.id === nodeId) ?? null;
      setSelectedNode(node);
    });

    cy.on("tap", (evt) => {
      if (evt.target === cy) {
        setSelectedNode(null);
      }
    });
  };

  const elements = topology ? buildElements(topology) : [];

  return (
    <div>
      <div style={pageStyles.header}>
        <h1 style={pageStyles.title}>Service Topology</h1>
        <div style={pageStyles.statusText}>
          <span
            style={{
              ...pageStyles.statusDot,
              backgroundColor: wsConnected ? "#3fb950" : "#484f58",
            }}
          />
          {wsConnected ? "Live" : "Polling"}
          {error && (
            <span style={{ color: "#f85149", marginLeft: "12px" }}>
              {error}
            </span>
          )}
        </div>
      </div>

      <div style={pageStyles.container}>
        <div style={pageStyles.graphContainer}>
          {elements.length > 0 ? (
            <CytoscapeComponent
              elements={elements}
              stylesheet={cytoscapeStylesheet}
              layout={{ name: "cose", animate: true, padding: 50 }}
              style={{ width: "100%", height: "100%" }}
              cy={handleCyReady}
            />
          ) : (
            <div style={pageStyles.placeholder}>
              {error
                ? "Unable to load topology"
                : "No services discovered yet. Waiting for data..."}
            </div>
          )}
        </div>

        {selectedNode && (
          <div style={pageStyles.detailPanel}>
            <div style={pageStyles.detailTitle}>{selectedNode.service}</div>
            <div style={pageStyles.detailRow}>
              <span style={pageStyles.detailLabel}>Namespace</span>
              <span style={pageStyles.detailValue}>
                {selectedNode.namespace}
              </span>
            </div>
            <div style={pageStyles.detailRow}>
              <span style={pageStyles.detailLabel}>Version</span>
              <span style={pageStyles.detailValue}>
                {selectedNode.version || "unknown"}
              </span>
            </div>
            <div style={pageStyles.detailRow}>
              <span style={pageStyles.detailLabel}>Type</span>
              <span style={pageStyles.detailValue}>{selectedNode.type}</span>
            </div>
            <div style={pageStyles.detailRow}>
              <span style={pageStyles.detailLabel}>Error Rate</span>
              <span
                style={{
                  ...pageStyles.detailValue,
                  color:
                    selectedNode.error_rate > 0.05
                      ? "#f85149"
                      : selectedNode.error_rate > 0.01
                        ? "#d29922"
                        : "#3fb950",
                }}
              >
                {(selectedNode.error_rate * 100).toFixed(2)}%
              </span>
            </div>
            <div style={pageStyles.detailRow}>
              <span style={pageStyles.detailLabel}>Avg Latency</span>
              <span style={pageStyles.detailValue}>
                {selectedNode.avg_latency_ms.toFixed(1)}ms
              </span>
            </div>
            <div style={pageStyles.detailRow}>
              <span style={pageStyles.detailLabel}>Endpoints</span>
              <span style={pageStyles.detailValue}>
                {selectedNode.endpoints?.length ?? 0}
              </span>
            </div>

            <div style={{ marginTop: "16px" }}>
              <a
                href={`/services/${encodeURIComponent(selectedNode.service)}`}
                style={{
                  display: "block",
                  textAlign: "center",
                  padding: "8px 16px",
                  backgroundColor: "#1f6feb",
                  color: "#fff",
                  borderRadius: "6px",
                  textDecoration: "none",
                  fontSize: "13px",
                  fontWeight: 500,
                }}
              >
                View Service Details
              </a>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default TopologyPage;
