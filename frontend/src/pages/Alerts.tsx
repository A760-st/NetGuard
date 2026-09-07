import { useEffect, useState } from 'react';
import { getAlerts } from '../services/api';
import type { Alert, PaginatedResponse } from '../types';
import SeverityBadge from '../components/SeverityBadge';
import EmptyState from '../components/EmptyState';

export default function Alerts() {
  const [data, setData] = useState<PaginatedResponse<Alert> | null>(null);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setLoading(true);
    getAlerts(page)
      .then(setData)
      .catch(() => {})
      .finally(() => setLoading(false));
  }, [page]);

  if (loading) return <div className="text-gray-500 text-sm">Loading...</div>;
  if (!data || data.items.length === 0) {
    return <EmptyState message="No alerts found. Process a PCAP to generate detections." />;
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <p className="text-xs text-gray-500">{data.total} alerts total</p>
        <div className="flex gap-2">
          <button
            disabled={page <= 1}
            onClick={() => setPage((p) => p - 1)}
            className="px-3 py-1 text-xs bg-gray-800 rounded hover:bg-gray-700 disabled:opacity-40"
          >
            Prev
          </button>
          <span className="text-xs text-gray-500 py-1">
            {data.page}/{data.pages}
          </span>
          <button
            disabled={page >= data.pages}
            onClick={() => setPage((p) => p + 1)}
            className="px-3 py-1 text-xs bg-gray-800 rounded hover:bg-gray-700 disabled:opacity-40"
          >
            Next
          </button>
        </div>
      </div>

      <div className="overflow-x-auto">
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
              <th className="text-left p-2">Status</th>
              <th className="text-right p-2">Count</th>
            </tr>
          </thead>
          <tbody>
            {data.items.map((a) => (
              <tr key={a.id} className="border-b border-gray-800/50 hover:bg-gray-900/50">
                <td className="p-2">
                  <SeverityBadge severity={a.severity} />
                </td>
                <td className="p-2 font-medium">{a.threat_class}</td>
                <td className="p-2 font-mono">{a.source_ip}</td>
                <td className="p-2 font-mono">{a.destination_ip}</td>
                <td className="p-2 text-right">{(a.confidence * 100).toFixed(1)}%</td>
                <td className="p-2 text-right">{a.risk_score.toFixed(1)}</td>
                <td className="p-2 text-gray-400">{a.detector_name}</td>
                <td className="p-2">
                  <span className="text-gray-500">{a.status}</span>
                </td>
                <td className="p-2 text-right">{a.occurrence_count}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
