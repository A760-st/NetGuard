export interface HealthStatus {
  status: string;
  version: string;
  environment: string;
  database: string;
  redis: string;
}

export interface SystemStatus {
  version: string;
  environment: string;
  database: string;
  redis: string;
  packet_engine: string;
  active_jobs: number;
  total_flows: number;
  total_alerts: number;
  total_incidents: number;
}

export interface AnalysisJob {
  id: string;
  filename: string;
  file_size: number;
  status: 'queued' | 'processing' | 'completed' | 'failed' | 'cancelled';
  progress: number;
  packet_count: number | null;
  flow_count: number | null;
  alert_count: number | null;
  error_message: string | null;
  processing_duration: number | null;
  created_at: string;
  updated_at: string;
  completed_at: string | null;
  file_sha256: string | null;
  parser_version: string | null;
  feature_schema_version: string | null;
  detector_config_version: string | null;
  data_quality: DataQuality | null;
}

export interface DataQuality {
  total_packets: number;
  ipv4_packets: number;
  ipv6_packets: number;
  tcp_packets: number;
  udp_packets: number;
  icmp_packets: number;
  other_protocol_packets: number;
  packets_without_ip: number;
  total_flows: number;
  unique_source_ips: number;
  unique_destination_ips: number;
  forward_bytes_total: number;
  backward_bytes_total: number;
  total_bytes: number;
  top_destination_ports?: Record<string, number>;
  protocol_distribution?: Record<string, number>;
}

export interface Flow {
  id: string;
  job_id: string;
  source_ip: string;
  destination_ip: string;
  source_port: number | null;
  destination_port: number | null;
  protocol: number;
  first_seen: string;
  last_seen: string;
  duration: number;
  forward_packets: number;
  backward_packets: number;
  forward_bytes: number;
  backward_bytes: number;
  features: Record<string, unknown> | null;
  anomaly_score: number | null;
  created_at: string;
}

export interface Alert {
  id: string;
  job_id: string;
  flow_id: string | null;
  source_ip: string;
  destination_ip: string;
  source_port: number | null;
  destination_port: number | null;
  protocol: number | null;
  threat_class: string;
  confidence: number;
  risk_score: number;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  supporting_evidence: Record<string, unknown> | null;
  detector_name: string;
  model_version: string | null;
  status: string;
  occurrence_count: number;
  created_at: string;
}

export interface Incident {
  id: string;
  job_id: string;
  title: string;
  threat_types: string[] | null;
  affected_ips: string[] | null;
  severity: string;
  confidence: number;
  related_alert_ids: string[] | null;
  evidence: Record<string, unknown> | null;
  first_seen: string;
  last_seen: string;
  status: string;
  created_at: string;
}

export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  page_size: number;
  pages: number;
}

export interface OverviewData {
  total_flows: number;
  total_alerts: number;
  total_incidents: number;
  total_jobs: number;
  completed_jobs: number;
  critical_alerts: number;
  high_alerts: number;
  medium_alerts: number;
  low_alerts: number;
}

export interface ThreatData {
  threat_class: string;
  count: number;
}

export interface TopTalker {
  ip: string;
  flow_count: number;
  total_bytes: number;
}
