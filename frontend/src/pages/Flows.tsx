import { useEffect, useState } from 'react';
import { getFlows } from '../services/api';
import type { Flow, PaginatedResponse } from '../types';
import EmptyState from '../components/EmptyState';

const PROTO_NAMES: Record<number, string> = { 6: 'TCP', 17: 'UDP', 1: 'ICMP' };

export default function Flows() {
  const [data, setData] = useState<PaginatedResponse<Flow> | null>(null);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setLoading(true);
    getFlows(page)
      .then(setData)
      .catch(() => {})
      .finally(() => setLoading(false));
  }, [page]);

  if (loading) return <div className="text-gray-500 text-sm">Loading...</div>;
  if (!data || data.items.length === 0) {
    return <EmptyState message="No flows found. Process a PCAP to extract flows." />;
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <p className="text-xs text-gray-500">{data.total} flows total</p>
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
              <tr key={f.id} className="border-b border-gray-800/50 hover:bg-gray-900/50">
                <td className="p-2 font-mono">
                  {f.source_ip}:{f.source_port ?? '*'}
                </td>
                <td className="p-2 font-mono">
                  {f.destination_ip}:{f.destination_port ?? '*'}
                </td>
                <td className="p-2">{PROTO_NAMES[f.protocol] || f.protocol}</td>
                <td className="p-2 text-right">{f.forward_packets}</td>
                <td className="p-2 text-right">{f.backward_packets}</td>
                <td className="p-2 text-right">{f.forward_bytes.toLocaleString()}</td>
                <td className="p-2 text-right">{f.backward_bytes.toLocaleString()}</td>
                <td className="p-2 text-right">{f.duration.toFixed(3)}s</td>
                <td className="p-2 text-right">
                  {f.anomaly_score !== null ? (
                    <span
                      className={
                        f.anomaly_score > 0.7
                          ? 'text-red-400'
                          : f.anomaly_score > 0.4
                          ? 'text-yellow-400'
                          : 'text-green-400'
                      }
                    >
                      {f.anomaly_score.toFixed(3)}
                    </span>
                  ) : (
                    '-'
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
