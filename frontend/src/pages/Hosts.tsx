import { useEffect, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { getFlows, getAlerts, getHostRisk } from '../services/api';
import type { Flow, Alert, PaginatedResponse } from '../types';
import SeverityBadge from '../components/SeverityBadge';
import EmptyState from '../components/EmptyState';

export default function Hosts() {
  const [searchParams, setSearchParams] = useSearchParams();
  const ip = searchParams.get('ip') || '';
  const [inputIp, setInputIp] = useState(ip);
  const [flows, setFlows] = useState<Flow[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [risk, setRisk] = useState<{ risk_score: number; severity: string; flow_count: number; alert_count: number; anomaly_score: number } | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!ip) {
      setFlows([]);
      setAlerts([]);
      setRisk(null);
      return;
    }

    setLoading(true);
    Promise.all([
      getFlows(1, 200),
      getAlerts(1, 200),
      getHostRisk(ip).catch(() => null),
    ])
      .then(([flowData, alertData, riskData]) => {
        setFlows(
          flowData.items.filter(
            (f) => f.source_ip === ip || f.destination_ip === ip
          )
        );
        setAlerts(
          alertData.items.filter(
            (a) => a.source_ip === ip || a.destination_ip === ip
          )
        );
        setRisk(riskData);
      })
      .catch(() => {})
      .finally(() => setLoading(false));
  }, [ip]);

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    setSearchParams(inputIp ? { ip: inputIp } : {});
  };

  if (!ip) {
    return (
      <div className="space-y-6">
        <form onSubmit={handleSearch} className="flex gap-3">
          <input
            type="text"
            value={inputIp}
            onChange={(e) => setInputIp(e.target.value)}
            placeholder="Enter IP address to investigate (e.g. 192.168.1.1)"
            className="flex-1 px-4 py-2 bg-gray-900 border border-gray-700 rounded text-sm text-gray-200 placeholder-gray-500 focus:outline-none focus:border-netguard-500"
          />
          <button
            type="submit"
            className="px-4 py-2 bg-netguard-700 hover:bg-netguard-600 text-white text-sm rounded transition-colors"
          >
            Investigate
          </button>
        </form>
        <EmptyState message="Enter a host IP address to begin investigation." />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-4">
        <form onSubmit={handleSearch} className="flex gap-3 flex-1">
          <input
            type="text"
            value={inputIp}
            onChange={(e) => setInputIp(e.target.value)}
            placeholder="IP address"
            className="flex-1 px-4 py-2 bg-gray-900 border border-gray-700 rounded text-sm text-gray-200 placeholder-gray-500 focus:outline-none focus:border-netguard-500"
          />
          <button
            type="submit"
            className="px-4 py-2 bg-netguard-700 hover:bg-netguard-600 text-white text-sm rounded transition-colors"
          >
            Search
          </button>
        </form>
      </div>

      {loading ? (
        <div className="text-gray-500 text-sm">Loading...</div>
      ) : (
        <>
          {risk && (
            <div className="bg-gray-900 border border-gray-800 rounded-lg p-6">
              <h3 className="text-sm font-semibold text-gray-300 mb-3">
                Risk Assessment: <span className="text-netguard-400 font-mono">{ip}</span>
              </h3>
              <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
                <div>
                  <p className="text-xs text-gray-500">Risk Score</p>
                  <p className={`text-xl font-bold ${risk.risk_score >= 75 ? 'text-red-400' : risk.risk_score >= 50 ? 'text-orange-400' : risk.risk_score >= 25 ? 'text-yellow-400' : 'text-green-400'}`}>
                    {risk.risk_score.toFixed(1)}
                  </p>
                </div>
                <div>
                  <p className="text-xs text-gray-500">Severity</p>
                  <SeverityBadge severity={risk.severity} />
                </div>
                <div>
                  <p className="text-xs text-gray-500">Flows</p>
                  <p className="text-xl font-bold text-gray-200">{risk.flow_count}</p>
                </div>
                <div>
                  <p className="text-xs text-gray-500">Alerts</p>
                  <p className="text-xl font-bold text-gray-200">{risk.alert_count}</p>
                </div>
                <div>
                  <p className="text-xs text-gray-500">Anomaly Score</p>
                  <p className="text-xl font-bold text-gray-200">{risk.anomaly_score.toFixed(3)}</p>
                </div>
              </div>
            </div>
          )}

          <div className="bg-gray-900 border border-gray-800 rounded-lg p-6">
            <h3 className="text-sm font-semibold text-gray-300 mb-3">
              Flows ({flows.length})
            </h3>
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-gray-800 text-gray-500">
                    <th className="text-left p-2">Source</th>
                    <th className="text-left p-2">Destination</th>
                    <th className="text-right p-2">Fwd Pkts</th>
                    <th className="text-right p-2">Bwd Pkts</th>
                    <th className="text-right p-2">Fwd Bytes</th>
                    <th className="text-right p-2">Duration</th>
                  </tr>
                </thead>
                <tbody>
                  {flows.slice(0, 50).map((f) => (
                    <tr key={f.id} className="border-b border-gray-800/50 hover:bg-gray-900/50">
                      <td className="p-2 font-mono">{f.source_ip}:{f.source_port ?? '*'}</td>
                      <td className="p-2 font-mono">{f.destination_ip}:{f.destination_port ?? '*'}</td>
                      <td className="p-2 text-right">{f.forward_packets}</td>
                      <td className="p-2 text-right">{f.backward_packets}</td>
                      <td className="p-2 text-right">{f.forward_bytes.toLocaleString()}</td>
                      <td className="p-2 text-right">{f.duration.toFixed(3)}s</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {flows.length === 0 && (
                <p className="text-xs text-gray-500 text-center py-4">No flows found for this host</p>
              )}
            </div>
          </div>

          <div className="bg-gray-900 border border-gray-800 rounded-lg p-6">
            <h3 className="text-sm font-semibold text-gray-300 mb-3">
              Alerts ({alerts.length})
            </h3>
            <div className="space-y-2">
              {alerts.slice(0, 20).map((a) => (
                <div key={a.id} className="flex items-center justify-between py-2 border-b border-gray-800/50">
                  <div className="flex items-center gap-3">
                    <SeverityBadge severity={a.severity} />
                    <span className="text-xs text-gray-300">{a.threat_class}</span>
                    <span className="text-xs text-gray-500">{a.detector_name}</span>
                  </div>
                  <span className="text-xs text-gray-500">{(a.confidence * 100).toFixed(1)}%</span>
                </div>
              ))}
              {alerts.length === 0 && (
                <p className="text-xs text-gray-500 text-center py-4">No alerts for this host</p>
              )}
            </div>
          </div>
        </>
      )}
    </div>
  );
}
