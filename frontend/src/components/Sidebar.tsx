import { NavLink } from 'react-router-dom';

const links = [
  { to: '/', label: 'Overview', icon: '⊞' },
  { to: '/flows', label: 'Flows', icon: '⇋' },
  { to: '/alerts', label: 'Alerts', icon: '⚠' },
  { to: '/incidents', label: 'Incidents', icon: '◉' },
  { to: '/jobs', label: 'PCAP Jobs', icon: '▶' },
  { to: '/hosts', label: 'Hosts', icon: '⊙' },
  { to: '/analytics', label: 'Analytics', icon: '◈' },
  { to: '/models', label: 'Models', icon: '⬡' },
  { to: '/system', label: 'System Health', icon: '⊞' },
];

export default function Sidebar() {
  return (
    <aside className="w-60 bg-gray-900 border-r border-gray-800 flex flex-col">
      <div className="p-4 border-b border-gray-800">
        <h1 className="text-lg font-bold text-netguard-400 tracking-wider">
          NETGUARD
        </h1>
        <p className="text-xs text-gray-500 mt-1">Traffic Intelligence</p>
      </div>
      <nav className="flex-1 p-2 space-y-1">
        {links.map((link) => (
          <NavLink
            key={link.to}
            to={link.to}
            end={link.to === '/'}
            className={({ isActive }) =>
              `flex items-center gap-3 px-3 py-2 rounded text-sm transition-colors ${
                isActive
                  ? 'bg-netguard-700/20 text-netguard-400'
                  : 'text-gray-400 hover:bg-gray-800 hover:text-gray-200'
              }`
            }
          >
            <span className="text-base">{link.icon}</span>
            {link.label}
          </NavLink>
        ))}
      </nav>
      <div className="p-4 border-t border-gray-800 text-xs text-gray-600">
        v0.1.0
      </div>
    </aside>
  );
}
