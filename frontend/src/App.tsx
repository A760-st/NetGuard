import { BrowserRouter, Routes, Route } from 'react-router-dom';
import Sidebar from './components/Sidebar';
import Header from './components/Header';
import Overview from './pages/Overview';
import Flows from './pages/Flows';
import Alerts from './pages/Alerts';
import Incidents from './pages/Incidents';
import Jobs from './pages/Jobs';
import Hosts from './pages/Hosts';
import SystemHealth from './pages/SystemHealth';
import ThreatAnalytics from './pages/ThreatAnalytics';
import ModelsPage from './pages/ModelsPage';
import Replay from './pages/Replay';
import Analyst from './pages/Analyst';

export default function App() {
  return (
    <BrowserRouter>
      <div className="flex h-screen bg-gray-950 text-gray-100">
        <Sidebar />
        <div className="flex flex-col flex-1 overflow-hidden">
          <Header />
          <main className="flex-1 overflow-y-auto p-6">
            <Routes>
              <Route path="/" element={<Overview />} />
              <Route path="/jobs" element={<Jobs />} />
              <Route path="/replay" element={<Replay />} />
              <Route path="/flows" element={<Flows />} />
              <Route path="/alerts" element={<Alerts />} />
              <Route path="/incidents" element={<Incidents />} />
              <Route path="/analyst" element={<Analyst />} />
              <Route path="/hosts" element={<Hosts />} />
              <Route path="/analytics" element={<ThreatAnalytics />} />
              <Route path="/models" element={<ModelsPage />} />
              <Route path="/system" element={<SystemHealth />} />
            </Routes>
          </main>
        </div>
      </div>
    </BrowserRouter>
  );
}
