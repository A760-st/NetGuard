import { useLocation } from 'react-router-dom';

const titles: Record<string, string> = {
  '/': 'Overview',
  '/flows': 'Traffic Analysis',
  '/alerts': 'Alerts',
  '/incidents': 'Incidents',
  '/jobs': 'PCAP Jobs',
  '/hosts': 'Host Investigation',
  '/system': 'System Health',
};

export default function Header() {
  const location = useLocation();
  const title = titles[location.pathname] || 'NETGUARD';

  return (
    <header className="h-14 border-b border-gray-800 bg-gray-900/50 backdrop-blur flex items-center px-6">
      <h2 className="text-sm font-semibold text-gray-200">{title}</h2>
      <div className="ml-auto flex items-center gap-4">
        <span className="text-xs text-gray-500">Passive Traffic Analysis</span>
        <div className="w-2 h-2 rounded-full bg-green-500" title="System online" />
      </div>
    </header>
  );
}
