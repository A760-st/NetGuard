import { useEffect, useState } from 'react';
import { getOverview, getThreats, getTopTalkers } from '../services/api';
import type { OverviewData, ThreatData, TopTalker } from '../types';
import StatCard from '../components/StatCard';
import EmptyState from '../components/EmptyState';
import {
  PieChart, Pie, Cell, ResponsiveContainer, Tooltip,
  BarChart, Bar, XAxis, YAxis, CartesianGrid,
} from 'recharts';

const COLORS = ['#ff0039', '#ff6b35', '#fcc419', '#51cf66', '#748ffc', '#cc5de8', '#20c997'];

export default function ThreatAnalytics() {
  const [overview, setOverview] = useState<OverviewData | null>(null);
  const [threats, setThreats] = useState<ThreatData[]>([]);
  const [talkers, setTalkers] = useState<TopTalker[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.all([getOverview(), getThreats(), getTopTalkers()])
      .then(([ov, th, tt]) => {
        setOverview(ov);
        setThreats(th.threats);
        setTalkers(tt.top_talkers);
      })
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);

  if (loading) return <div className="text-gray-500 text-sm">Loading...</div>;
  if (!overview || (overview.total_flows === 0 && overview.total_alerts === 0)) {
    return <EmptyState message="No analytics data. Process a PCAP to view threat analytics." />;
  }

  return (
    <div className="space-y-6">
      <h2 className="text-sm font-semibold text-gray-300">Threat Analytics</h2>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard label="Total Alerts" value={overview.total_alerts} />
        <StatCard label="Critical" value={overview.critical_alerts} color="text-red-400" />
        <StatCard label="High" value={overview.high_alerts} color="text-orange-400" />
        <StatCard label="Incidents" value={overview.total_incidents} />
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
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
                  outerRadius={85}
                  label={({ threat_class, count }: { threat_class: string; count: number }) => `${threat_class}: ${count}`}
                >
                  {threats.map((_, i) => (
                    <Cell key={i} fill={COLORS[i % COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip />
              </PieChart>
            </ResponsiveContainer>
          </div>
        )}

        {talkers.length > 0 && (
          <div className="bg-gray-900 border border-gray-800 rounded-lg p-6">
            <h3 className="text-sm font-semibold text-gray-300 mb-4">Top Talkers</h3>
            <ResponsiveContainer width="100%" height={250}>
              <BarChart data={talkers.slice(0, 10)}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" />
                <XAxis dataKey="ip" tick={{ fontSize: 10, fill: '#6b7280' }} />
                <YAxis tick={{ fontSize: 10, fill: '#6b7280' }} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#111827', border: '1px solid #374151' }}
                />
                <Bar dataKey="flow_count" fill="#4c6ef5" name="Flows" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        )}
      </div>
    </div>
  );
}
