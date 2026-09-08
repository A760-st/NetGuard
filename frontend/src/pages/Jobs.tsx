import { useCallback, useEffect, useRef, useState } from 'react';
import { getJobs, uploadTrafficFile, loadDemoDataset, getJob } from '../services/api';
import type { AnalysisJob, PaginatedResponse } from '../types';
import EmptyState from '../components/EmptyState';

const STATUS_COLORS: Record<string, string> = {
  queued: 'text-gray-400',
  processing: 'text-blue-400',
  completed: 'text-green-400',
  failed: 'text-red-400',
  cancelled: 'text-yellow-400',
};

const ALLOWED_EXT = ['.pcap', '.cap', '.csv'];

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${(bytes / Math.pow(k, i)).toFixed(1)} ${sizes[i]}`;
}

function fileExtension(name: string): string {
  const idx = name.lastIndexOf('.');
  return idx >= 0 ? name.slice(idx).toLowerCase() : '';
}

export default function Jobs() {
  const [data, setData] = useState<PaginatedResponse<AnalysisJob> | null>(null);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(true);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [uploadStatus, setUploadStatus] = useState<'idle' | 'uploading' | 'success' | 'error'>('idle');
  const [uploadMessage, setUploadMessage] = useState('');
  const [activeJobId, setActiveJobId] = useState<string | null>(null);
  const pollRef = useRef<number | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  const refresh = useCallback(() => {
    setLoading(true);
    getJobs(page)
      .then(setData)
      .catch(() => setData(null))
      .finally(() => setLoading(false));
  }, [page]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  useEffect(() => {
    if (!activeJobId) return;
    const tick = async () => {
      try {
        const job = await getJob(activeJobId);
        setData((prev) => {
          if (!prev) return prev;
          return {
            ...prev,
            items: prev.items.map((j) => (j.id === job.id ? job : j)),
          };
        });
        if (job.status === 'completed' || job.status === 'failed' || job.status === 'cancelled') {
          setActiveJobId(null);
          refresh();
        }
      } catch {
        /* ignore transient poll errors */
      }
    };
    pollRef.current = window.setInterval(tick, 1000);
    return () => {
      if (pollRef.current) window.clearInterval(pollRef.current);
    };
  }, [activeJobId, refresh]);

  const onFileChosen = (file: File | null) => {
    setUploadStatus('idle');
    setUploadMessage('');
    if (!file) {
      setSelectedFile(null);
      return;
    }
    const ext = fileExtension(file.name);
    if (!ALLOWED_EXT.includes(ext)) {
      setSelectedFile(null);
      setUploadStatus('error');
      setUploadMessage(`Unsupported file type (${ext || 'unknown'}). Allowed: ${ALLOWED_EXT.join(', ')}`);
      return;
    }
    if (file.size === 0) {
      setSelectedFile(null);
      setUploadStatus('error');
      setUploadMessage('File is empty.');
      return;
    }
    setSelectedFile(file);
  };

  const handleUpload = async () => {
    if (!selectedFile) return;
    setUploadStatus('uploading');
    setUploadMessage('Uploading and queuing analysis…');
    try {
      const job = await uploadTrafficFile(selectedFile);
      setUploadStatus('success');
      setUploadMessage(`Uploaded ${job.filename}. Processing started.`);
      setSelectedFile(null);
      if (inputRef.current) inputRef.current.value = '';
      setActiveJobId(job.id);
      setPage(1);
      refresh();
    } catch (err) {
      setUploadStatus('error');
      setUploadMessage(err instanceof Error ? err.message : 'Upload failed');
    }
  };

  const handleDemo = async () => {
    setUploadStatus('uploading');
    setUploadMessage('Loading DEMO/SAMPLE dataset…');
    try {
      const job = await loadDemoDataset();
      setUploadStatus('success');
      setUploadMessage(`Loaded ${job.filename} (DEMO/SAMPLE DATA). Processing started.`);
      setActiveJobId(job.id);
      setPage(1);
      refresh();
    } catch (err) {
      setUploadStatus('error');
      setUploadMessage(err instanceof Error ? err.message : 'Failed to load demo dataset');
    }
  };

  return (
    <div className="space-y-6">
      <div className="bg-gray-900 border border-gray-800 rounded-lg p-4 space-y-4">
        <div>
          <h3 className="text-sm font-semibold text-gray-200">Upload Recorded Traffic</h3>
          <p className="text-xs text-gray-500 mt-1">
            Offline analysis only — classic PCAP (.pcap/.cap) or flow CSV (.csv). No live capture.
          </p>
        </div>

        <div className="flex flex-col md:flex-row gap-3 items-start md:items-center">
          <input
            ref={inputRef}
            type="file"
            accept=".pcap,.cap,.csv"
            onChange={(e) => onFileChosen(e.target.files?.[0] ?? null)}
            className="text-xs text-gray-400 file:mr-3 file:py-1.5 file:px-3 file:rounded file:border-0 file:bg-gray-800 file:text-gray-200 file:text-xs"
          />
          <button
            type="button"
            disabled={!selectedFile || uploadStatus === 'uploading'}
            onClick={handleUpload}
            className="px-4 py-2 bg-netguard-700 hover:bg-netguard-600 disabled:opacity-40 text-white text-sm rounded transition-colors"
          >
            Process Upload
          </button>
          <button
            type="button"
            disabled={uploadStatus === 'uploading'}
            onClick={handleDemo}
            className="px-4 py-2 bg-gray-800 hover:bg-gray-700 disabled:opacity-40 text-gray-200 text-sm rounded border border-gray-700 transition-colors"
          >
            Load DEMO/SAMPLE Dataset
          </button>
        </div>

        {selectedFile && (
          <div className="text-xs text-gray-400">
            Selected: <span className="text-gray-200">{selectedFile.name}</span> · {formatBytes(selectedFile.size)}
          </div>
        )}

        {uploadMessage && (
          <div
            className={`text-xs rounded px-3 py-2 ${
              uploadStatus === 'error'
                ? 'bg-red-950/40 text-red-300 border border-red-900'
                : uploadStatus === 'success'
                ? 'bg-green-950/40 text-green-300 border border-green-900'
                : 'bg-blue-950/40 text-blue-300 border border-blue-900'
            }`}
          >
            {uploadMessage}
          </div>
        )}
      </div>

      {loading && !data ? (
        <div className="text-gray-500 text-sm">Loading...</div>
      ) : !data || data.items.length === 0 ? (
        <EmptyState message="No analysis jobs yet. Upload a PCAP/CSV or load the DEMO/SAMPLE dataset." />
      ) : (
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
                {data.page}/{data.pages || 1}
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
                    <h3 className="text-sm font-medium text-gray-200">
                      {job.filename}
                      {job.filename.includes('DEMO_SAMPLE') && (
                        <span className="ml-2 text-[10px] uppercase tracking-wide text-amber-400 border border-amber-700/50 px-1.5 py-0.5 rounded">
                          DEMO/SAMPLE
                        </span>
                      )}
                    </h3>
                    <p className="text-xs text-gray-500 mt-1">
                      {formatBytes(job.file_size)} · {job.packet_count?.toLocaleString() ?? '-'} packets ·{' '}
                      {job.flow_count?.toLocaleString() ?? '-'} flows
                    </p>
                  </div>
                  <span className={`text-xs font-medium ${STATUS_COLORS[job.status] || 'text-gray-400'}`}>
                    {job.status}
                  </span>
                </div>
                {(job.status === 'processing' || job.status === 'queued') && (
                  <div className="mt-3">
                    <div className="h-1.5 bg-gray-800 rounded-full overflow-hidden">
                      <div
                        className="h-full bg-netguard-600 rounded-full transition-all"
                        style={{ width: `${Math.min(100, job.progress * 100)}%` }}
                      />
                    </div>
                    <p className="text-xs text-gray-500 mt-1">{(job.progress * 100).toFixed(0)}%</p>
                  </div>
                )}
                {job.error_message && <p className="text-xs text-red-400 mt-2">{job.error_message}</p>}
                <div className="flex gap-4 text-xs text-gray-500 mt-2">
                  <span>{new Date(job.created_at).toLocaleString()}</span>
                  {job.processing_duration != null && <span>{job.processing_duration.toFixed(1)}s</span>}
                  {job.alert_count !== null && <span>{job.alert_count} alerts</span>}
                </div>
                {job.file_sha256 && (
                  <div className="mt-3 text-xs text-gray-600 border-t border-gray-800 pt-2 leading-relaxed">
                    <span className="text-gray-500">SHA-256: </span>
                    <code className="text-gray-400">{job.file_sha256}</code>
                    {job.data_quality && (
                      <div className="mt-1 text-gray-600">
                        {job.data_quality.total_packets.toLocaleString()} packets ·{' '}
                        {job.data_quality.unique_source_ips} src IPs ·{' '}
                        {job.data_quality.unique_destination_ips} dst IPs
                      </div>
                    )}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
