import axios, { AxiosInstance } from "axios";

// ---------------------------------------------------------------------------
// Types matching Go server models
// ---------------------------------------------------------------------------

export interface Endpoint {
  ip: string;
  port: number;
  pod?: string;
  node?: string;
}

export interface ConnectionEvent {
  timestamp: string;
  source_namespace: string;
  source_service: string;
  source_pod: string;
  destination_namespace: string;
  destination_service: string;
  destination_pod: string;
  bytes_sent: number;
  bytes_received: number;
  duration_ms: number;
  retransmits: number;
}

export interface HTTPRequestEvent {
  timestamp: string;
  source_namespace: string;
  source_service: string;
  source_pod: string;
  destination_namespace: string;
  destination_service: string;
  destination_pod: string;
  method: string;
  path: string;
  protocol: string;
  status_code: number;
  latency_ms: number;
  request_size: number;
  response_size: number;
}

export interface DependencyLink {
  source: string;
  destination: string;
  call_count: number;
  error_count: number;
  avg_latency_ms: number;
  p99_latency_ms: number;
}

export interface TopologyNode {
  id: string;
  service: string;
  namespace: string;
  version: string;
  type: string;
  endpoints: Endpoint[];
  error_rate: number;
  avg_latency_ms: number;
}

export interface TopologyEdge {
  source: string;
  target: string;
  call_count: number;
  error_rate: number;
  avg_latency_ms: number;
  protocol: string;
}

export interface Topology {
  nodes: TopologyNode[];
  edges: TopologyEdge[];
  timestamp: string;
}

export interface TimeSeriesPoint {
  timestamp: string;
  value: number;
  label?: string;
}

// ---------------------------------------------------------------------------
// Query parameter helpers
// ---------------------------------------------------------------------------

interface TimeRangeParams {
  since?: string;
  until?: string;
}

interface PaginationParams {
  offset?: number;
  limit?: number;
}

interface FilterParams extends TimeRangeParams, PaginationParams {
  namespace?: string;
  service?: string;
  method?: string;
  status_min?: number;
  status_max?: number;
}

// ---------------------------------------------------------------------------
// API Client
// ---------------------------------------------------------------------------

const BASE_URL = "/api/v1";

const http: AxiosInstance = axios.create({
  baseURL: BASE_URL,
  headers: {
    "Content-Type": "application/json",
  },
});

// Services
export async function getServices(
  params?: TimeRangeParams
): Promise<TopologyNode[]> {
  const resp = await http.get<TopologyNode[]>("/services", { params });
  return resp.data;
}

// Dependencies
export async function getDependencies(
  params?: TimeRangeParams
): Promise<DependencyLink[]> {
  const resp = await http.get<DependencyLink[]>("/dependencies", { params });
  return resp.data;
}

// Topology
export async function getTopology(params?: TimeRangeParams): Promise<Topology> {
  const resp = await http.get<Topology>("/topology", { params });
  return resp.data;
}

// Latencies for a service
export async function getLatencies(
  service: string,
  params?: TimeRangeParams
): Promise<TimeSeriesPoint[]> {
  const resp = await http.get<TimeSeriesPoint[]>(
    `/services/${encodeURIComponent(service)}/latencies`,
    { params }
  );
  return resp.data;
}

// Call rates for a service
export async function getCallRates(
  service: string,
  params?: TimeRangeParams
): Promise<TimeSeriesPoint[]> {
  const resp = await http.get<TimeSeriesPoint[]>(
    `/services/${encodeURIComponent(service)}/call_rates`,
    { params }
  );
  return resp.data;
}

// Error rates for a service
export async function getErrorRates(
  service: string,
  params?: TimeRangeParams
): Promise<TimeSeriesPoint[]> {
  const resp = await http.get<TimeSeriesPoint[]>(
    `/services/${encodeURIComponent(service)}/error_rates`,
    { params }
  );
  return resp.data;
}

// Traffic summary (global)
export async function getTraffic(
  params?: TimeRangeParams
): Promise<TimeSeriesPoint[]> {
  const resp = await http.get<TimeSeriesPoint[]>("/traffic", { params });
  return resp.data;
}

// Connection events
export async function getConnections(
  params?: FilterParams
): Promise<ConnectionEvent[]> {
  const resp = await http.get<ConnectionEvent[]>("/connections", { params });
  return resp.data;
}

// HTTP request events
export async function getRequests(
  params?: FilterParams
): Promise<HTTPRequestEvent[]> {
  const resp = await http.get<HTTPRequestEvent[]>("/requests", { params });
  return resp.data;
}

// ---------------------------------------------------------------------------
// WebSocket for real-time topology updates
// ---------------------------------------------------------------------------

export interface TopologyWSCallbacks {
  onUpdate: (topology: Topology) => void;
  onError?: (error: Event) => void;
  onClose?: () => void;
}

export interface TopologyWSHandle {
  close: () => void;
}

export function connectTopologyWS(
  callbacks: TopologyWSCallbacks
): TopologyWSHandle {
  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  const wsUrl = `${protocol}//${window.location.host}/api/v1/ws/topology`;
  const ws = new WebSocket(wsUrl);

  ws.onmessage = (event: MessageEvent) => {
    try {
      const topology: Topology = JSON.parse(event.data);
      callbacks.onUpdate(topology);
    } catch {
      // Ignore malformed messages
    }
  };

  ws.onerror = (event: Event) => {
    callbacks.onError?.(event);
  };

  ws.onclose = () => {
    callbacks.onClose?.();
  };

  return {
    close: () => ws.close(),
  };
}
