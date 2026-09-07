# API Documentation

## Base URL
`http://localhost:8000`

## Health

### `GET /health`
Returns system health status.

Response:
```json
{
  "status": "healthy",
  "version": "0.1.0",
  "environment": "development",
  "database": "healthy",
  "redis": "healthy"
}
```

## PCAP Jobs

### `POST /api/v1/pcap/upload`
Upload a PCAP file for analysis.

- **Content-Type**: `multipart/form-data`
- **Body**: `file` (PCAP file)
- **Max size**: 500MB

Response: `AnalysisJobResponse`

### `GET /api/v1/pcap/jobs`
List analysis jobs.

- **Query**: `page`, `page_size`, `status`

### `GET /api/v1/pcap/jobs/{job_id}`
Get job details.

### `POST /api/v1/pcap/jobs/{job_id}/cancel`
Cancel a running job.

### `GET /api/v1/pcap/jobs/{job_id}/progress`
SSE stream for job progress updates.

## Flows

### `GET /api/v1/flows`
List flows with filtering.

- **Query**: `page`, `page_size`, `job_id`, `source_ip`, `destination_ip`, `protocol`

### `GET /api/v1/flows/{flow_id}`
Get flow details.

## Alerts

### `GET /api/v1/alerts`
List alerts.

- **Query**: `page`, `page_size`, `job_id`, `severity`, `threat_class`, `source_ip`, `status`

### `GET /api/v1/alerts/{alert_id}`
Get alert details.

## Incidents

### `GET /api/v1/incidents`
List incidents.

- **Query**: `page`, `page_size`, `job_id`, `severity`, `status`

### `GET /api/v1/incidents/{incident_id}`
Get incident details.

## Hosts

### `GET /api/v1/hosts/{ip}/risk`
Get host risk score.

### `GET /api/v1/hosts/{ip}/timeline`
Get host timeline.

## Analytics

### `GET /api/v1/analytics/overview`
Overview statistics.

### `GET /api/v1/analytics/threats`
Threat class distribution.

### `GET /api/v1/analytics/protocols`
Protocol distribution.

### `GET /api/v1/analytics/top-talkers`
Top source IPs by flow count.

## System

### `GET /api/v1/system/status`
System status with all service health checks.
