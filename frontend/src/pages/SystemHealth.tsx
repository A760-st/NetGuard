import { useEffect, useState } from 'react';
import { getSystemStatus } from '../services/api';
import type { SystemStatus } from '../types';
import StatCard from '../components/StatCard';

export default function SystemHealth() {
  const [status, setStatus] = useState<SystemStatus | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    getSystemStatus()
      .then(setStatus)
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);

  if (loading) return <div className="text-gray-500 text-sm">Loading...</div>;
  if (!status) return <div className="text-gray-500 text-sm">Failed to load system status.</div>;

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard label="Version" value={status.version} />
        <StatCard label="Environment" value={status.environment} />
        <StatCard label="Database" value={status.database} color={status.database === 'healthy' ? 'text-green-400' : 'text-red-400'} />
        <StatCard label="Redis" value={status.redis} color={status.redis === 'healthy' ? 'text-green-400' : 'text-red-400'} />
      </div>

      <div className="bg-gray-900 border border-gray-800 rounded-lg p-6">
        <h3 className="text-sm font-semibold text-gray-300 mb-4">Services</h3>
        <div className="space-y-3">
          <div className="flex items-center justify-between py-2 border-b border-gray-800/50">
            <span className="text-sm text-gray-300">Backend API</span>
            <span className="text-xs text-green-400">Running</span>
          </div>
          <div className="flex items-center justify-between py-2 border-b border-gray-800/50">
            <span className="text-sm text-gray-300">Packet Engine</span>
            <span className={`text-xs ${status.packet_engine === 'healthy' ? 'text-green-400' : 'text-gray-500'}`}>
              {status.packet_engine}
            </span>
          </div>
          <div className="flex items-center justify-between py-2 border-b border-gray-800/50">
            <span className="text-sm text-gray-300">PostgreSQL</span>
            <span className={`text-xs ${status.database === 'healthy' ? 'text-green-400' : 'text-red-400'}`}>
              {status.database}
            </span>
          </div>
          <div className="flex items-center justify-between py-2">
            <span className="text-sm text-gray-300">Redis</span>
            <span className={`text-xs ${status.redis === 'healthy' ? 'text-green-400' : 'text-red-400'}`}>
              {status.redis}
            </span>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard label="Active Jobs" value={status.active_jobs} />
        <StatCard label="Total Flows" value={status.total_flows} />
        <StatCard label="Total Alerts" value={status.total_alerts} />
        <StatCard label="Total Incidents" value={status.total_incidents} />
      </div>
    </div>
  );
}
