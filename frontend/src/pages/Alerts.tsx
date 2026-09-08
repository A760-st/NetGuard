import { useEffect, useState } from 'react';
import { getAlerts } from '../services/api';
import type { Alert, PaginatedResponse } from '../types';
import SeverityBadge from '../components/SeverityBadge';
import EmptyState from '../components/EmptyState';

function evidenceList(alert: Alert): Array<Record<string, unknown>> {
  const raw = alert.supporting_evidence as unknown;
  if (Array.isArray(raw)) return raw as Array<Record<string, unknown>>;
  if (raw && typeof raw === 'object') return [raw as Record<string, unknown>];
  return [];
}

export default function Alerts() {
  const [data, setData] = useState<PaginatedResponse<Alert> | null>(null);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState<Alert | null>(null);
  const [severity, setSeverity] = useState('');
  const [threatClass, setThreatClass] = useState('');
  const [sourceIp, setSourceIp] = useState('');

  useEffect(() => {
    setLoading(true);
    getAlerts(page, 50, {
      severity: severity || undefined,
      threat_class: threatClass || undefined,
      source_ip: sourceIp || undefined,
    })
      .then(setData)
      .catch(() => setData(null))
      .finally(() => setLoading(false));
  }, [page, severity, threatClass, sourceIp]);

  if (loading && !data) return <div className="text-gray-500 text-sm">Loading...</div>;
  if (!data || data.items.length === 0) {
    return (
      <div className="space-y-4">
        <FilterBar
          severity={severity} setSeverity={setSeverity}
          threatClass={threatClass} setThreatClass={setThreatClass}
          sourceIp={sourceIp} setSourceIp={setSourceIp}
          setPage={setPage}
        />
        <EmptyState message="No alerts found. Process recorded traffic to generate detections." />
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <FilterBar
          severity={severity} setSeverity={setSeverity}
          threatClass={threatClass} setThreatClass={setThreatClass}
          sourceIp={sourceIp} setSourceIp={setSourceIp}
          setPage={setPage}
        />
        <div className="flex gap-2 items-center">
          <p className="text-xs text-gray-500">{data.total} alerts</p>
          <button disabled={page <= 1} onClick={() => setPage((p) => p - 1)} className="px-3 py-1 text-xs bg-gray-800 rounded hover:bg-gray-700 disabled:opacity-40">Prev</button>
          <span className="text-xs text-gray-500 py-1">{data.page}/{data.pages || 1}</span>
          <button disabled={page >= data.pages} onClick={() => setPage((p) => p + 1)} className="px-3 py-1 text-xs bg-gray-800 rounded hover:bg-gray-700 disabled:opacity-40">Next</button>
        </div>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
        <div className="xl:col-span-2 overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-gray-800 text-gray-500">
                <th className="text-left p-2">Severity</th>
                <th className="text-left p-2">Threat Class</th>
                <th className="text-left p-2">Source</th>
                <th className="text-left p-2">Destination</th>
                <th className="text-right p-2">Confidence</th>
                <th className="text-right p-2">Risk</th>
                <th className="text-left p-2">Detector</th>
              </tr>
            </thead>
            <tbody>
              {data.items.map((a) => (
                <tr
                  key={a.id}
                  onClick={() => setSelected(a)}
                  className={`border-b border-gray-800/50 hover:bg-gray-900/50 cursor-pointer ${
                    selected?.id === a.id ? 'bg-netguard-950/40' : ''
                  }`}
                >
                  <td className="p-2"><SeverityBadge severity={a.severity} /></td>
                  <td className="p-2 font-medium">{a.threat_class}</td>
                  <td className="p-2 font-mono">{a.source_ip}</td>
                  <td className="p-2 font-mono">{a.destination_ip}</td>
                  <td className="p-2 text-right">{(a.confidence * 100).toFixed(1)}%</td>
                  <td className="p-2 text-right">{a.risk_score.toFixed(1)}</td>
                  <td className="p-2 text-gray-400">{a.detector_name}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div className="bg-gray-900 border border-gray-800 rounded-lg p-4">
          <h3 className="text-sm font-semibold text-gray-200 mb-3">Detection Evidence</h3>
          {!selected ? (
            <p className="text-xs text-gray-500">Select an alert to view why it was flagged.</p>
          ) : (
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-xs text-gray-300">{selected.threat_class}</span>
                <SeverityBadge severity={selected.severity} />
              </div>
              <p className="text-xs text-gray-500">
                Rule-based detector: <span className="text-gray-300">{selected.detector_name}</span>
              </p>
              <div>
                <p className="text-xs font-semibold text-gray-300 mb-1">Why was this flagged?</p>
                <ul className="space-y-2">
                  {evidenceList(selected).length === 0 && (
                    <li className="text-xs text-gray-500">No structured evidence payload stored.</li>
                  )}
                  {evidenceList(selected).map((ev, idx) => (
                    <li key={idx} className="text-xs text-gray-400 border border-gray-800 rounded p-2">
                      <div className="text-gray-300 font-mono">{String(ev.feature ?? 'signal')}</div>
                      <div className="mt-1">{String(ev.interpretation ?? 'Matched detection rule')}</div>
                      {'value' in ev && (
                        <div className="mt-1 text-gray-600">value={String(ev.value)} · baseline={String(ev.baseline ?? 'n/a')}</div>
                      )}
                    </li>
                  ))}
                </ul>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function FilterBar(props: {
  severity: string;
  setSeverity: (v: string) => void;
  threatClass: string;
  setThreatClass: (v: string) => void;
  sourceIp: string;
  setSourceIp: (v: string) => void;
  setPage: (updater: (p: number) => number) => void;
}) {
  const { severity, setSeverity, threatClass, setThreatClass, sourceIp, setSourceIp, setPage } = props;
  return (
    <div className="flex flex-wrap gap-2">
      <select
        value={severity}
        onChange={(e) => { setPage(() => 1); setSeverity(e.target.value); }}
        className="bg-gray-900 border border-gray-700 text-xs rounded px-2 py-1.5 text-gray-300"
      >
        <option value="">All severities</option>
        {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((s) => (
          <option key={s} value={s}>{s}</option>
        ))}
      </select>
      <input
        value={threatClass}
        onChange={(e) => { setPage(() => 1); setThreatClass(e.target.value); }}
        placeholder="Threat class"
        className="bg-gray-900 border border-gray-700 text-xs rounded px-2 py-1.5 text-gray-300 w-36"
      />
      <input
        value={sourceIp}
        onChange={(e) => { setPage(() => 1); setSourceIp(e.target.value); }}
        placeholder="Source IP"
        className="bg-gray-900 border border-gray-700 text-xs rounded px-2 py-1.5 text-gray-300 w-36"
      />
    </div>
  );
}
