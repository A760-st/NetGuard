import { useEffect, useState } from 'react';
import { getOverview, getThreats } from '../services/api';
import type { OverviewData, ThreatData } from '../types';
import StatCard from '../components/StatCard';
import EmptyState from '../components/EmptyState';
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from 'recharts';

const PIE_COLORS = ['#ff0039', '#ff6b35', '#fcc419', '#51cf66', '#748ffc', '#cc5de8'];

export default function Overview() {
  const [data, setData] = useState<OverviewData | null>(null);
  const [threats, setThreats] = useState<ThreatData[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.all([getOverview(), getThreats()])
      .then(([ov, th]) => {
        setData(ov);
        setThreats(th.threats);
      })
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);

  if (loading) {
    return <div className="text-gray-500 text-sm">Loading...</div>;
  }

  if (!data || (data.total_flows === 0 && data.total_alerts === 0)) {
    return <EmptyState message="No traffic data available. Upload a PCAP to begin analysis." />;
  }

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard label="Total Flows" value={data.total_flows} />
        <StatCard label="Total Alerts" value={data.total_alerts} />
        <StatCard label="Critical Alerts" value={data.critical_alerts} color="text-red-400" />
        <StatCard label="High Alerts" value={data.high_alerts} color="text-orange-400" />
        <StatCard label="Incidents" value={data.total_incidents} />
        <StatCard label="Completed Jobs" value={data.completed_jobs} />
        <StatCard label="Medium Alerts" value={data.medium_alerts} color="text-yellow-400" />
        <StatCard label="Low Alerts" value={data.low_alerts} color="text-green-400" />
      </div>

      {threats.length > 0 && (
        <div className="bg-gray-900 border border-gray-800 rounded-lg p-6">
          <h3 className="text-sm font-semibold text-gray-300 mb-4">Threat Distribution</h3>
          <ResponsiveContainer width="100%" height={250}>
            <PieChart>
              <Pie
                data={threats}
                dataKey="count"
                nameKey="threat_class"
                cx="50%"
                cy="50%"
                outerRadius={90}
                label={({ threat_class, count }) => `${threat_class}: ${count}`}
              >
                {threats.map((_, i) => (
                  <Cell key={i} fill={PIE_COLORS[i % PIE_COLORS.length]} />
                ))}
              </Pie>
              <Tooltip />
            </PieChart>
          </ResponsiveContainer>
        </div>
      )}
    </div>
  );
}
