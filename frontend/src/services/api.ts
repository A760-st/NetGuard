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

async function fetchJson<T>(url: string, init?: RequestInit): Promise<T> {
  const response = await fetch(url, init);
  if (!response.ok) {
    let detail = `${response.status} ${response.statusText}`;
    try {
      const body = await response.json();
      if (body?.detail) {
        detail = typeof body.detail === 'string' ? body.detail : JSON.stringify(body.detail);
      }
    } catch {
      /* ignore */
    }
    throw new Error(detail);
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

export async function uploadTrafficFile(file: File): Promise<AnalysisJob> {
  const form = new FormData();
  form.append('file', file);
  return fetchJson<AnalysisJob>(`${API_BASE}/pcap/upload`, {
    method: 'POST',
    body: form,
  });
}

export async function loadDemoDataset(): Promise<AnalysisJob> {
  return fetchJson<AnalysisJob>(`${API_BASE}/pcap/demo`, { method: 'POST' });
}

export async function getFlows(
  page = 1,
  pageSize = 50,
  params?: { job_id?: string; source_ip?: string; destination_ip?: string }
): Promise<PaginatedResponse<Flow>> {
  const qs = new URLSearchParams({
    page: String(page),
    page_size: String(pageSize),
  });
  if (params?.job_id) qs.set('job_id', params.job_id);
  if (params?.source_ip) qs.set('source_ip', params.source_ip);
  if (params?.destination_ip) qs.set('destination_ip', params.destination_ip);
  return fetchJson<PaginatedResponse<Flow>>(`${API_BASE}/flows?${qs}`);
}

export async function getAlerts(
  page = 1,
  pageSize = 50,
  params?: {
    job_id?: string;
    severity?: string;
    threat_class?: string;
    source_ip?: string;
    status?: string;
  }
): Promise<PaginatedResponse<Alert>> {
  const qs = new URLSearchParams({
    page: String(page),
    page_size: String(pageSize),
  });
  if (params?.job_id) qs.set('job_id', params.job_id);
  if (params?.severity) qs.set('severity', params.severity);
  if (params?.threat_class) qs.set('threat_class', params.threat_class);
  if (params?.source_ip) qs.set('source_ip', params.source_ip);
  if (params?.status) qs.set('status', params.status);
  return fetchJson<PaginatedResponse<Alert>>(`${API_BASE}/alerts?${qs}`);
}

export async function getAlert(alertId: string): Promise<Alert> {
  return fetchJson<Alert>(`${API_BASE}/alerts/${alertId}`);
}

export async function getIncidents(
  page = 1,
  pageSize = 20,
  params?: {
    job_id?: string;
    severity?: string;
    status?: string;
    threat_type?: string;
    source?: string;
    destination?: string;
  }
): Promise<PaginatedResponse<Incident>> {
  const qs = new URLSearchParams({
    page: String(page),
    page_size: String(pageSize),
  });
  if (params?.job_id) qs.set('job_id', params.job_id);
  if (params?.severity) qs.set('severity', params.severity);
  if (params?.status) qs.set('status', params.status);
  if (params?.threat_type) qs.set('threat_type', params.threat_type);
  if (params?.source) qs.set('source', params.source);
  if (params?.destination) qs.set('destination', params.destination);
  return fetchJson<PaginatedResponse<Incident>>(`${API_BASE}/incidents?${qs}`);
}

export async function getIncident(incidentId: string): Promise<Incident> {
  return fetchJson<Incident>(`${API_BASE}/incidents/${incidentId}`);
}

export async function updateIncidentStatus(
  incidentId: string,
  status: string
): Promise<Incident> {
  return fetchJson<Incident>(`${API_BASE}/incidents/${incidentId}/status`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ status }),
  });
}

export async function getIncidentAnalyst(incidentId: string): Promise<AnalystSummary> {
  return fetchJson<AnalystSummary>(`${API_BASE}/incidents/${incidentId}/analyst`);
}

export async function getIncidentReport(incidentId: string): Promise<IncidentReport> {
  return fetchJson<IncidentReport>(`${API_BASE}/incidents/${incidentId}/report`);
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

export interface AnalystSummary {
  source: string;
  disclaimer: string;
  incident_summary: string;
  why_it_matters: string;
  evidence: Array<Record<string, unknown>>;
  suspicious_indicators: string[];
  recommended_investigation_steps: string[];
  severity_assessment: {
    severity: string;
    confidence: number;
    risk_score?: number | null;
  };
  why_flagged: string;
  threat_types: string[];
  affected_ips: string[];
}

export interface IncidentReport {
  title: string;
  generated_at: string;
  incident_id: string;
  threat_type?: string | null;
  threat_types: string[];
  severity: string;
  risk_score?: number | null;
  confidence?: number;
  source?: string | null;
  destinations?: string[];
  affected_ips: string[];
  status?: string;
  explanation: string;
  detection_evidence: unknown[];
  relevant_features: Array<Record<string, unknown>>;
  analyst_summary?: AnalystSummary;
  disclaimer?: string;
}
