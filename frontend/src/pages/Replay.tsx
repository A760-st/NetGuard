import { useEffect, useMemo, useRef, useState } from 'react';
import { getFlows, getAlerts, getIncidents, getJobs } from '../services/api';
import type { Flow, Alert, Incident, AnalysisJob } from '../types';
import SeverityBadge from '../components/SeverityBadge';
import EmptyState from '../components/EmptyState';

const SPEEDS = [0.5, 1, 2, 4];

export default function Replay() {
  const [jobs, setJobs] = useState<AnalysisJob[]>([]);
  const [jobId, setJobId] = useState('');
  const [flows, setFlows] = useState<Flow[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [index, setIndex] = useState(0);
  const [playing, setPlaying] = useState(false);
  const [speed, setSpeed] = useState(1);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const timerRef = useRef<number | null>(null);

  useEffect(() => {
    getJobs(1, 50)
      .then((res) => {
        const completed = res.items.filter((j) => j.status === 'completed');
        setJobs(completed);
        if (completed[0]) setJobId(completed[0].id);
      })
      .catch((err) => setError(err instanceof Error ? err.message : 'Failed to load jobs'))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    if (!jobId) {
      setFlows([]);
      setAlerts([]);
      setIncidents([]);
      return;
    }
    setLoading(true);
    setPlaying(false);
    setIndex(0);
    Promise.all([
      getFlows(1, 200, { job_id: jobId }),
      getAlerts(1, 200, { job_id: jobId }),
      getIncidents(1, 100, { job_id: jobId }),
    ])
      .then(([f, a, i]) => {
        const sorted = [...f.items].sort(
          (x, y) => new Date(x.first_seen).getTime() - new Date(y.first_seen).getTime()
        );
        setFlows(sorted);
        setAlerts(a.items);
        setIncidents(i.items);
      })
      .catch((err) => setError(err instanceof Error ? err.message : 'Failed to load replay data'))
      .finally(() => setLoading(false));
  }, [jobId]);

  useEffect(() => {
    if (!playing || flows.length === 0) return;
    timerRef.current = window.setInterval(() => {
      setIndex((prev) => {
        if (prev >= flows.length - 1) {
          setPlaying(false);
          return prev;
        }
        return prev + 1;
      });
    }, Math.max(150, 800 / speed));
    return () => {
      if (timerRef.current) window.clearInterval(timerRef.current);
    };
  }, [playing, speed, flows.length]);

  const current = flows[index] || null;

  const revealedAlerts = useMemo(() => {
    if (!current) return [] as Alert[];
    const seenIps = new Set(
      flows.slice(0, index + 1).flatMap((f) => [f.source_ip, f.destination_ip])
    );
    return alerts.filter((a) => seenIps.has(a.source_ip) || seenIps.has(a.destination_ip));
  }, [alerts, current, flows, index]);

  const revealedIncidents = useMemo(() => {
    const ips = new Set(revealedAlerts.flatMap((a) => [a.source_ip, a.destination_ip]));
    return incidents.filter((inc) => (inc.affected_ips || []).some((ip) => ips.has(ip)));
  }, [incidents, revealedAlerts]);

  if (loading && jobs.length === 0) {
    return <div className="text-gray-500 text-sm">Loading...</div>;
  }

  if (jobs.length === 0) {
    return (
      <EmptyState message="No completed analysis jobs. Upload traffic or load the DEMO/SAMPLE dataset first." />
    );
  }

  return (
    <div className="space-y-4">
      <div className="bg-gray-900 border border-gray-800 rounded-lg p-4 space-y-3">
        <div className="flex flex-wrap gap-3 items-center justify-between">
          <div>
            <h3 className="text-sm font-semibold text-gray-200">Recorded Traffic Replay</h3>
            <p className="text-xs text-gray-500 mt-1">
              Replays previously processed flows only — not live packet capture.
            </p>
          </div>
          <select
            value={jobId}
            onChange={(e) => setJobId(e.target.value)}
            className="bg-gray-950 border border-gray-700 text-xs rounded px-2 py-1.5 text-gray-300 max-w-xs"
          >
            {jobs.map((j) => (
              <option key={j.id} value={j.id}>
                {j.filename} ({j.flow_count ?? 0} flows)
              </option>
            ))}
          </select>
        </div>

        <div className="flex flex-wrap gap-2 items-center">
          <button
            type="button"
            disabled={!flows.length || playing}
            onClick={() => setPlaying(true)}
            className="px-3 py-1.5 text-xs rounded bg-netguard-700 hover:bg-netguard-600 disabled:opacity-40 text-white"
          >
            Start
          </button>
          <button
            type="button"
            disabled={!playing}
            onClick={() => setPlaying(false)}
            className="px-3 py-1.5 text-xs rounded bg-gray-800 hover:bg-gray-700 disabled:opacity-40 text-gray-200"
          >
            Pause
          </button>
          <button
            type="button"
            onClick={() => {
              setPlaying(false);
              setIndex(0);
            }}
            className="px-3 py-1.5 text-xs rounded bg-gray-800 hover:bg-gray-700 text-gray-200"
          >
            Reset
          </button>
          <div className="flex gap-1 ml-2">
            {SPEEDS.map((s) => (
              <button
                key={s}
                type="button"
                onClick={() => setSpeed(s)}
                className={`px-2 py-1 text-xs rounded border ${
                  speed === s ? 'border-netguard-500 text-netguard-300' : 'border-gray-700 text-gray-400'
                }`}
              >
                {s}x
              </button>
            ))}
          </div>
          <span className="text-xs text-gray-500 ml-auto">
            Flow {flows.length ? index + 1 : 0} / {flows.length}
          </span>
        </div>

        <div className="h-1.5 bg-gray-800 rounded-full overflow-hidden">
          <div
            className="h-full bg-netguard-600 transition-all"
            style={{ width: `${flows.length ? ((index + 1) / flows.length) * 100 : 0}%` }}
          />
        </div>
      </div>

      {error && <p className="text-xs text-red-400">{error}</p>}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="bg-gray-900 border border-gray-800 rounded-lg p-4 space-y-2">
          <h4 className="text-xs font-semibold text-gray-300">Current Flow</h4>
          {!current ? (
            <p className="text-xs text-gray-500">No flow selected.</p>
          ) : (
            <>
              <p className="text-xs font-mono text-gray-200">
                {current.source_ip}:{current.source_port ?? '*'} → {current.destination_ip}:
                {current.destination_port ?? '*'}
              </p>
              <div className="grid grid-cols-2 gap-2 text-xs text-gray-400">
                <span>Fwd pkts: {current.forward_packets}</span>
                <span>Bwd pkts: {current.backward_packets}</span>
                <span>Fwd bytes: {current.forward_bytes}</span>
                <span>Bwd bytes: {current.backward_bytes}</span>
                <span>Duration: {current.duration.toFixed(3)}s</span>
                <span>Anomaly: {current.anomaly_score ?? 'unavailable'}</span>
              </div>
              {current.features && (
                <div className="max-h-40 overflow-y-auto text-[11px] text-gray-500 space-y-1 border-t border-gray-800 pt-2">
                  {Object.entries(current.features)
                    .slice(0, 12)
                    .map(([k, v]) => (
                      <div key={k} className="flex justify-between gap-2">
                        <span>{k}</span>
                        <span className="font-mono text-gray-400">
                          {typeof v === 'number' ? (Number.isInteger(v) ? v : v.toFixed(3)) : String(v)}
                        </span>
                      </div>
                    ))}
                </div>
              )}
            </>
          )}
        </div>

        <div className="bg-gray-900 border border-gray-800 rounded-lg p-4 space-y-2">
          <h4 className="text-xs font-semibold text-gray-300">
            Detections revealed ({revealedAlerts.length})
          </h4>
          <div className="space-y-2 max-h-64 overflow-y-auto">
            {revealedAlerts.length === 0 && (
              <p className="text-xs text-gray-500">No detections revealed yet for replayed flows.</p>
            )}
            {revealedAlerts.map((a) => (
              <div
                key={a.id}
                className="flex items-center justify-between gap-2 border-b border-gray-800/60 pb-2"
              >
                <div>
                  <p className="text-xs text-gray-300">{a.threat_class}</p>
                  <p className="text-[11px] text-gray-600 font-mono">
                    {a.source_ip} → {a.destination_ip}
                  </p>
                </div>
                <SeverityBadge severity={a.severity} />
              </div>
            ))}
          </div>
        </div>

        <div className="bg-gray-900 border border-gray-800 rounded-lg p-4 space-y-2">
          <h4 className="text-xs font-semibold text-gray-300">
            Incidents revealed ({revealedIncidents.length})
          </h4>
          <div className="space-y-2 max-h-64 overflow-y-auto">
            {revealedIncidents.length === 0 && (
              <p className="text-xs text-gray-500">Incidents appear as related hosts are replayed.</p>
            )}
            {revealedIncidents.map((inc) => (
              <div key={inc.id} className="border-b border-gray-800/60 pb-2">
                <div className="flex justify-between gap-2">
                  <p className="text-xs text-gray-300">{inc.title}</p>
                  <SeverityBadge severity={inc.severity} />
                </div>
                <p className="text-[11px] text-gray-600 mt-1">{inc.threat_types?.join(', ')}</p>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
