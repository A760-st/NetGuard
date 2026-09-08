import { useEffect, useMemo, useState } from 'react';
import {
  getIncidents,
  updateIncidentStatus,
  getIncidentReport,
  getIncidentAnalyst,
} from '../services/api';
import type { Incident, PaginatedResponse } from '../types';
import type { AnalystSummary, IncidentReport } from '../services/api';
import SeverityBadge from '../components/SeverityBadge';
import EmptyState from '../components/EmptyState';

const STATUSES = ['open', 'investigating', 'triaged', 'resolved'];

function downloadJson(filename: string, data: unknown) {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

export default function Incidents() {
  const [data, setData] = useState<PaginatedResponse<Incident> | null>(null);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState<Incident | null>(null);
  const [analyst, setAnalyst] = useState<AnalystSummary | null>(null);
  const [severity, setSeverity] = useState('');
  const [status, setStatus] = useState('');
  const [threatType, setThreatType] = useState('');
  const [source, setSource] = useState('');
  const [error, setError] = useState('');

  const load = () => {
    setLoading(true);
    setError('');
    getIncidents(page, 20, {
      severity: severity || undefined,
      status: status || undefined,
      threat_type: threatType || undefined,
      source: source || undefined,
    })
      .then((res) => {
        setData(res);
        if (selected) {
          const updated = res.items.find((i) => i.id === selected.id);
          if (updated) setSelected(updated);
        }
      })
      .catch((err) => setError(err instanceof Error ? err.message : 'Failed to load incidents'))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [page, severity, status, threatType, source]);

  useEffect(() => {
    if (!selected) {
      setAnalyst(null);
      return;
    }
    getIncidentAnalyst(selected.id)
      .then(setAnalyst)
      .catch(() => setAnalyst(null));
  }, [selected]);

  const whyFlagged = useMemo(() => {
    const evidence = selected?.evidence as Record<string, unknown> | null | undefined;
    if (evidence && typeof evidence.why_flagged === 'string') return evidence.why_flagged;
    return analyst?.why_flagged || 'No explanation available for this incident.';
  }, [selected, analyst]);

  const riskScore = useMemo(() => {
    const evidence = selected?.evidence as Record<string, unknown> | null | undefined;
    const value = evidence?.max_risk_score;
    return typeof value === 'number' ? value : null;
  }, [selected]);

  const handleStatus = async (next: string) => {
    if (!selected) return;
    try {
      const updated = await updateIncidentStatus(selected.id, next);
      setSelected(updated);
      load();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Status update failed');
    }
  };

  const handleExport = async () => {
    if (!selected) return;
    try {
      const report: IncidentReport = await getIncidentReport(selected.id);
      downloadJson(`netguard-incident-${selected.id}.json`, report);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Export failed');
    }
  };

  if (loading && !data) return <div className="text-gray-500 text-sm">Loading...</div>;

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap gap-2 items-center">
        <select
          value={severity}
          onChange={(e) => { setPage(1); setSeverity(e.target.value); }}
          className="bg-gray-900 border border-gray-700 text-xs rounded px-2 py-1.5 text-gray-300"
        >
          <option value="">All severities</option>
          {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((s) => (
            <option key={s} value={s}>{s}</option>
          ))}
        </select>
        <select
          value={status}
          onChange={(e) => { setPage(1); setStatus(e.target.value); }}
          className="bg-gray-900 border border-gray-700 text-xs rounded px-2 py-1.5 text-gray-300"
        >
          <option value="">All statuses</option>
          {STATUSES.map((s) => (
            <option key={s} value={s}>{s}</option>
          ))}
        </select>
        <input
          value={threatType}
          onChange={(e) => { setPage(1); setThreatType(e.target.value); }}
          placeholder="Threat type"
          className="bg-gray-900 border border-gray-700 text-xs rounded px-2 py-1.5 text-gray-300 w-36"
        />
        <input
          value={source}
          onChange={(e) => { setPage(1); setSource(e.target.value); }}
          placeholder="Source / host IP"
          className="bg-gray-900 border border-gray-700 text-xs rounded px-2 py-1.5 text-gray-300 w-40"
        />
      </div>

      {error && <p className="text-xs text-red-400">{error}</p>}

      {!data || data.items.length === 0 ? (
        <EmptyState message="No incidents found. Process recorded traffic to generate correlated incidents." />
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <p className="text-xs text-gray-500">{data.total} incidents</p>
              <div className="flex gap-2">
                <button disabled={page <= 1} onClick={() => setPage((p) => p - 1)} className="px-3 py-1 text-xs bg-gray-800 rounded hover:bg-gray-700 disabled:opacity-40">Prev</button>
                <span className="text-xs text-gray-500 py-1">{data.page}/{data.pages || 1}</span>
                <button disabled={page >= data.pages} onClick={() => setPage((p) => p + 1)} className="px-3 py-1 text-xs bg-gray-800 rounded hover:bg-gray-700 disabled:opacity-40">Next</button>
              </div>
            </div>

            {data.items.map((inc) => (
              <button
                key={inc.id}
                type="button"
                onClick={() => setSelected(inc)}
                className={`w-full text-left bg-gray-900 border rounded-lg p-4 transition-colors ${
                  selected?.id === inc.id ? 'border-netguard-600' : 'border-gray-800 hover:border-gray-700'
                }`}
              >
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <h3 className="text-sm font-semibold text-gray-200">{inc.title}</h3>
                    <p className="text-xs text-gray-500 mt-1">{inc.threat_types?.join(', ') || 'Unknown'}</p>
                  </div>
                  <SeverityBadge severity={inc.severity} />
                </div>
                <div className="mt-2 flex flex-wrap gap-3 text-xs text-gray-400">
                  <span>Hosts: {inc.affected_ips?.length || 0}</span>
                  <span>Conf: {(inc.confidence * 100).toFixed(0)}%</span>
                  <span>Status: {inc.status}</span>
                </div>
              </button>
            ))}
          </div>

          <div className="bg-gray-900 border border-gray-800 rounded-lg p-4 min-h-[320px]">
            {!selected ? (
              <p className="text-xs text-gray-500">Select an incident to view risk, evidence, and explanation.</p>
            ) : (
              <div className="space-y-4">
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <h3 className="text-sm font-semibold text-gray-100">{selected.title}</h3>
                    <p className="text-[11px] text-gray-600 font-mono mt-1">{selected.id}</p>
                  </div>
                  <SeverityBadge severity={selected.severity} />
                </div>

                <div className="grid grid-cols-2 gap-3 text-xs">
                  <div>
                    <p className="text-gray-500">Risk score</p>
                    <p className="text-lg font-semibold text-gray-100">{riskScore != null ? riskScore.toFixed(1) : '—'}</p>
                  </div>
                  <div>
                    <p className="text-gray-500">Confidence</p>
                    <p className="text-lg font-semibold text-gray-100">{(selected.confidence * 100).toFixed(0)}%</p>
                  </div>
                  <div>
                    <p className="text-gray-500">Affected IPs</p>
                    <p className="text-gray-300 font-mono break-all">{selected.affected_ips?.join(', ') || '—'}</p>
                  </div>
                  <div>
                    <p className="text-gray-500">Threat types</p>
                    <p className="text-gray-300">{selected.threat_types?.join(', ') || '—'}</p>
                  </div>
                </div>

                <div>
                  <p className="text-xs font-semibold text-gray-300 mb-1">Why was this flagged?</p>
                  <p className="text-xs text-gray-400 leading-relaxed bg-gray-950/60 border border-gray-800 rounded p-3">
                    {whyFlagged}
                  </p>
                </div>

                <div>
                  <p className="text-xs font-semibold text-gray-300 mb-2">Status</p>
                  <div className="flex flex-wrap gap-2">
                    {STATUSES.map((s) => (
                      <button
                        key={s}
                        type="button"
                        onClick={() => handleStatus(s)}
                        className={`px-2.5 py-1 text-xs rounded border ${
                          selected.status === s
                            ? 'border-netguard-500 text-netguard-300 bg-netguard-900/30'
                            : 'border-gray-700 text-gray-400 hover:border-gray-500'
                        }`}
                      >
                        {s}
                      </button>
                    ))}
                  </div>
                </div>

                <div className="flex gap-2">
                  <button
                    type="button"
                    onClick={handleExport}
                    className="px-3 py-1.5 text-xs rounded bg-netguard-700 hover:bg-netguard-600 text-white"
                  >
                    Export Report (JSON)
                  </button>
                </div>

                {analyst && (
                  <div className="border-t border-gray-800 pt-3 space-y-2">
                    <p className="text-xs font-semibold text-gray-300">Analyst preview</p>
                    <p className="text-[11px] text-amber-400/90">{analyst.disclaimer}</p>
                    <p className="text-xs text-gray-400">{analyst.incident_summary}</p>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
