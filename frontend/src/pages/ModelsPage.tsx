import EmptyState from '../components/EmptyState';

export default function ModelsPage() {
  return (
    <div className="space-y-6">
      <h2 className="text-sm font-semibold text-gray-300">ML Models</h2>

      <div className="bg-gray-900 border border-gray-800 rounded-lg p-6">
        <h3 className="text-sm font-semibold text-gray-200">Flow Anomaly Autoencoder</h3>
        <div className="mt-3 grid grid-cols-2 md:grid-cols-4 gap-4 text-xs">
          <div>
            <p className="text-gray-500">Architecture</p>
            <p className="text-gray-200 font-mono">12 → 8 → 4 → 8 → 12</p>
          </div>
          <div>
            <p className="text-gray-500">Input Features</p>
            <p className="text-gray-200">12 flow features</p>
          </div>
          <div>
            <p className="text-gray-500">Activation</p>
            <p className="text-gray-200">ReLU</p>
          </div>
          <div>
            <p className="text-gray-500">Loss Function</p>
            <p className="text-gray-200">MSE Reconstruction</p>
          </div>
        </div>
      </div>

      <div className="bg-gray-900 border border-gray-800 rounded-lg p-6">
        <h3 className="text-sm font-semibold text-gray-200">Threat Detectors</h3>
        <div className="mt-3 space-y-2">
          {[
            'DDoS Detector',
            'Reconnaissance / Port Scan Detector',
            'C2 Beacon Detector',
            'DGA Domain Detector',
            'DNS Tunnel Detector',
            'Encrypted Threat Detector',
            'Exfiltration Detector',
          ].map((name) => (
            <div key={name} className="flex items-center justify-between py-2 border-b border-gray-800/50">
              <span className="text-sm text-gray-300">{name}</span>
              <span className="text-xs text-green-400">Available</span>
            </div>
          ))}
        </div>
      </div>

      <EmptyState message="Upload a trained model artifact to enable anomaly detection scoring." />
    </div>
  );
}
