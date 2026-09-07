import type {
  HealthStatus,
  SystemStatus,
  PaginatedResponse,
  AnalysisJob,
  Flow,
  Alert,
  Incident,
  OverviewData,
  ThreatData,
  TopTalker,
} from '../types';

const API_BASE = '/api/v1';

async function fetchJson<T>(url: string): Promise<T> {
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`API error: ${response.status} ${response.statusText}`);
  }
  return response.json();
}

export async function getHealth(): Promise<HealthStatus> {
  return fetchJson<HealthStatus>('/health');
}

export async function getSystemStatus(): Promise<SystemStatus> {
  return fetchJson<SystemStatus>(`${API_BASE}/system/status`);
}

export async function getOverview(): Promise<OverviewData> {
  return fetchJson<OverviewData>(`${API_BASE}/analytics/overview`);
}

export async function getThreats(): Promise<{ threats: ThreatData[] }> {
  return fetchJson<{ threats: ThreatData[] }>(`${API_BASE}/analytics/threats`);
}

export async function getTopTalkers(): Promise<{ top_talkers: TopTalker[] }> {
  return fetchJson<{ top_talkers: TopTalker[] }>(`${API_BASE}/analytics/top-talkers`);
}

export async function getJobs(
  page = 1,
  pageSize = 20
): Promise<PaginatedResponse<AnalysisJob>> {
  return fetchJson<PaginatedResponse<AnalysisJob>>(
    `${API_BASE}/pcap/jobs?page=${page}&page_size=${pageSize}`
  );
}

export async function getJob(jobId: string): Promise<AnalysisJob> {
  return fetchJson<AnalysisJob>(`${API_BASE}/pcap/jobs/${jobId}`);
}

export async function getFlows(
  page = 1,
  pageSize = 50
): Promise<PaginatedResponse<Flow>> {
  return fetchJson<PaginatedResponse<Flow>>(
    `${API_BASE}/flows?page=${page}&page_size=${pageSize}`
  );
}

export async function getAlerts(
  page = 1,
  pageSize = 50
): Promise<PaginatedResponse<Alert>> {
  return fetchJson<PaginatedResponse<Alert>>(
    `${API_BASE}/alerts?page=${page}&page_size=${pageSize}`
  );
}

export async function getAlert(alertId: string): Promise<Alert> {
  return fetchJson<Alert>(`${API_BASE}/alerts/${alertId}`);
}

export async function getIncidents(
  page = 1,
  pageSize = 20
): Promise<PaginatedResponse<Incident>> {
  return fetchJson<PaginatedResponse<Incident>>(
    `${API_BASE}/incidents?page=${page}&page_size=${pageSize}`
  );
}

export async function getIncident(incidentId: string): Promise<Incident> {
  return fetchJson<Incident>(`${API_BASE}/incidents/${incidentId}`);
}

export async function getHostRisk(ip: string): Promise<{
  ip_address: string;
  risk_score: number;
  severity: string;
  alert_count: number;
  flow_count: number;
  anomaly_score: number;
}> {
  return fetchJson(`${API_BASE}/hosts/${ip}/risk`);
}
