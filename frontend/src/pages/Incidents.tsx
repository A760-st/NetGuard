import { useEffect, useState } from 'react';
import { getIncidents } from '../services/api';
import type { Incident, PaginatedResponse } from '../types';
import SeverityBadge from '../components/SeverityBadge';
import EmptyState from '../components/EmptyState';

export default function Incidents() {
  const [data, setData] = useState<PaginatedResponse<Incident> | null>(null);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setLoading(true);
    getIncidents(page)
      .then(setData)
      .catch(() => {})
      .finally(() => setLoading(false));
  }, [page]);

  if (loading) return <div className="text-gray-500 text-sm">Loading...</div>;
  if (!data || data.items.length === 0) {
    return <EmptyState message="No incidents found. Process a PCAP to generate correlated incidents." />;
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <p className="text-xs text-gray-500">{data.total} incidents total</p>
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

      <div className="space-y-3">
        {data.items.map((inc) => (
          <div key={inc.id} className="bg-gray-900 border border-gray-800 rounded-lg p-4">
            <div className="flex items-start justify-between">
              <div>
                <h3 className="text-sm font-semibold text-gray-200">{inc.title}</h3>
                <p className="text-xs text-gray-500 mt-1">
                  {inc.threat_types?.join(', ') || 'Unknown threat type'}
                </p>
              </div>
              <SeverityBadge severity={inc.severity} />
            </div>
            <div className="mt-3 flex gap-6 text-xs text-gray-400">
              <span>Affected hosts: {inc.affected_ips?.length || 0}</span>
              <span>Confidence: {(inc.confidence * 100).toFixed(1)}%</span>
              <span>First seen: {new Date(inc.first_seen).toLocaleString()}</span>
              <span>Last seen: {new Date(inc.last_seen).toLocaleString()}</span>
              <span>Status: {inc.status}</span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
