import { useEffect, useMemo, useState } from 'react';
import { getFlows } from '../services/api';
import type { Flow, PaginatedResponse } from '../types';
import EmptyState from '../components/EmptyState';

const PROTO_NAMES: Record<number, string> = { 6: 'TCP', 17: 'UDP', 1: 'ICMP' };

function formatFeatureValue(value: unknown): string {
  if (value === null || value === undefined) return 'unavailable';
  if (typeof value === 'number') return Number.isInteger(value) ? String(value) : value.toFixed(3);
  if (Array.isArray(value)) return value.join(', ');
  if (typeof value === 'object') return JSON.stringify(value);
  return String(value);
}

function interpretFeature(key: string, value: unknown): string {
  if (value === null || value === undefined) return 'Not available from uploaded data';
  if (key.includes('asymmetry') && typeof value === 'number') {
    if (value > 0.7) return 'Strong outbound asymmetry — unusual for balanced sessions';
    if (value < -0.7) return 'Strong inbound asymmetry';
    return 'Within typical balanced range';
  }
  if (key.includes('duration') && typeof value === 'number') {
    if (value > 600) return 'Long-lived flow';
    if (value < 1) return 'Short-lived flow';
    return 'Moderate duration';
  }
  if (key.includes('bytes') && typeof value === 'number' && value > 100000) {
    return 'High byte volume';
  }
  return 'Observed value from processed traffic';
}

export default function Flows() {
  const [data, setData] = useState<PaginatedResponse<Flow> | null>(null);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState<Flow | null>(null);
  const [sourceFilter, setSourceFilter] = useState('');
  const [destFilter, setDestFilter] = useState('');

  useEffect(() => {
    setLoading(true);
    getFlows(page, 50, {
      source_ip: sourceFilter || undefined,
      destination_ip: destFilter || undefined,
    })
      .then(setData)
      .catch(() => setData(null))
      .finally(() => setLoading(false));
  }, [page, sourceFilter, destFilter]);

  const featureEntries = useMemo(() => {
    if (!selected?.features) return [];
    return Object.entries(selected.features);
  }, [selected]);

  if (loading && !data) return <div className="text-gray-500 text-sm">Loading...</div>;
  if (!data || data.items.length === 0) {
    return <EmptyState message="No flows found. Process a PCAP/CSV to extract flows." />;
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap gap-2 items-center justify-between">
        <div className="flex gap-2">
          <input
            value={sourceFilter}
            onChange={(e) => { setPage(1); setSourceFilter(e.target.value); }}
            placeholder="Filter source IP"
            className="bg-gray-900 border border-gray-700 text-xs rounded px-2 py-1.5 text-gray-300 w-40"
          />
          <input
            value={destFilter}
            onChange={(e) => { setPage(1); setDestFilter(e.target.value); }}
            placeholder="Filter destination IP"
            className="bg-gray-900 border border-gray-700 text-xs rounded px-2 py-1.5 text-gray-300 w-40"
          />
        </div>
        <div className="flex gap-2 items-center">
          <p className="text-xs text-gray-500">{data.total} flows</p>
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
                <th className="text-left p-2">Source</th>
                <th className="text-left p-2">Destination</th>
                <th className="text-left p-2">Proto</th>
                <th className="text-right p-2">Fwd Pkts</th>
                <th className="text-right p-2">Bwd Pkts</th>
                <th className="text-right p-2">Fwd Bytes</th>
                <th className="text-right p-2">Bwd Bytes</th>
                <th className="text-right p-2">Duration</th>
                <th className="text-right p-2">Anomaly</th>
              </tr>
            </thead>
            <tbody>
              {data.items.map((f) => (
                <tr
                  key={f.id}
                  onClick={() => setSelected(f)}
                  className={`border-b border-gray-800/50 hover:bg-gray-900/50 cursor-pointer ${
                    selected?.id === f.id ? 'bg-netguard-950/40' : ''
                  }`}
                >
                  <td className="p-2 font-mono">{f.source_ip}:{f.source_port ?? '*'}</td>
                  <td className="p-2 font-mono">{f.destination_ip}:{f.destination_port ?? '*'}</td>
                  <td className="p-2">{PROTO_NAMES[f.protocol] || f.protocol}</td>
                  <td className="p-2 text-right">{f.forward_packets}</td>
                  <td className="p-2 text-right">{f.backward_packets}</td>
                  <td className="p-2 text-right">{f.forward_bytes.toLocaleString()}</td>
                  <td className="p-2 text-right">{f.backward_bytes.toLocaleString()}</td>
                  <td className="p-2 text-right">{f.duration.toFixed(3)}s</td>
                  <td className="p-2 text-right">
                    {f.anomaly_score !== null ? f.anomaly_score.toFixed(3) : (
                      <span className="text-gray-600" title="ML model not loaded">unavailable</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div className="bg-gray-900 border border-gray-800 rounded-lg p-4">
          <h3 className="text-sm font-semibold text-gray-200 mb-3">Feature Explorer</h3>
          {!selected ? (
            <p className="text-xs text-gray-500">Select a flow to inspect extracted features.</p>
          ) : (
            <div className="space-y-3">
              <p className="text-xs text-gray-400 font-mono">
                {selected.source_ip}:{selected.source_port ?? '*'} → {selected.destination_ip}:{selected.destination_port ?? '*'}
              </p>
              {featureEntries.length === 0 ? (
                <p className="text-xs text-gray-500">No feature dictionary stored for this flow.</p>
              ) : (
                <div className="space-y-2 max-h-[28rem] overflow-y-auto">
                  {featureEntries.map(([key, value]) => (
                    <div key={key} className="border-b border-gray-800/60 pb-2">
                      <div className="flex justify-between gap-2 text-xs">
                        <span className="text-gray-400">{key}</span>
                        <span className="text-gray-200 font-mono text-right">{formatFeatureValue(value)}</span>
                      </div>
                      <p className="text-[11px] text-gray-600 mt-0.5">{interpretFeature(key, value)}</p>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
