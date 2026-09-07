import { useEffect, useState } from 'react';
import { getJobs } from '../services/api';
import type { AnalysisJob, PaginatedResponse } from '../types';
import EmptyState from '../components/EmptyState';

const STATUS_COLORS: Record<string, string> = {
  queued: 'text-gray-400',
  processing: 'text-blue-400',
  completed: 'text-green-400',
  failed: 'text-red-400',
  cancelled: 'text-yellow-400',
};

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${(bytes / Math.pow(k, i)).toFixed(1)} ${sizes[i]}`;
}

export default function Jobs() {
  const [data, setData] = useState<PaginatedResponse<AnalysisJob> | null>(null);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setLoading(true);
    getJobs(page)
      .then(setData)
      .catch(() => {})
      .finally(() => setLoading(false));
  }, [page]);

  if (loading) return <div className="text-gray-500 text-sm">Loading...</div>;
  if (!data || data.items.length === 0) {
    return <EmptyState message="No analysis jobs. Upload a PCAP to create one." />;
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <p className="text-xs text-gray-500">{data.total} jobs total</p>
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
        {data.items.map((job) => (
          <div key={job.id} className="bg-gray-900 border border-gray-800 rounded-lg p-4">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-sm font-medium text-gray-200">{job.filename}</h3>
                <p className="text-xs text-gray-500 mt-1">
                  {formatBytes(job.file_size)} · {job.packet_count?.toLocaleString() ?? '-'} packets ·{' '}
                  {job.flow_count?.toLocaleString() ?? '-'} flows
                </p>
              </div>
              <span className={`text-xs font-medium ${STATUS_COLORS[job.status] || 'text-gray-400'}`}>
                {job.status}
              </span>
            </div>
            {job.status === 'processing' && (
              <div className="mt-3">
                <div className="h-1.5 bg-gray-800 rounded-full overflow-hidden">
                  <div
                    className="h-full bg-netguard-600 rounded-full transition-all"
                    style={{ width: `${job.progress * 100}%` }}
                  />
                </div>
                <p className="text-xs text-gray-500 mt-1">{(job.progress * 100).toFixed(0)}%</p>
              </div>
            )}
            {job.error_message && (
              <p className="text-xs text-red-400 mt-2">{job.error_message}</p>
            )}
            <div className="flex gap-4 text-xs text-gray-500 mt-2">
              <span>{new Date(job.created_at).toLocaleString()}</span>
              {job.processing_duration && <span>{job.processing_duration.toFixed(1)}s</span>}
              {job.alert_count !== null && <span>{job.alert_count} alerts</span>}
            </div>
            {job.file_sha256 && (
              <div className="mt-3 text-xs text-gray-600 border-t border-gray-800 pt-2 leading-relaxed">
                <span className="text-gray-500">SHA-256: </span>
                <code className="text-gray-400">{job.file_sha256}</code>
                {job.parser_version && (
                  <span className="ml-3">
                    parser v{job.parser_version} · features v{job.feature_schema_version} · detectors v
                    {job.detector_config_version}
                  </span>
                )}
                {job.data_quality && (
                  <div className="mt-1 text-gray-600">
                    {job.data_quality.total_packets.toLocaleString()} packets ·{' '}
                    {job.data_quality.unique_source_ips} src IPs ·{' '}
                    {job.data_quality.unique_destination_ips} dst IPs ·{' '}
                    {job.data_quality.packets_without_ip} non-IP
                  </div>
                )}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
