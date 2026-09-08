import EmptyState from '../components/EmptyState';

export default function ModelsPage() {
  return (
    <div className="space-y-6">
      <h2 className="text-sm font-semibold text-gray-300">Detectors & Models</h2>

      <div className="bg-amber-950/20 border border-amber-800/40 rounded-lg p-4 text-xs text-amber-200/90">
        Threat detections in this demo are produced by <strong>explainable rule-based detectors</strong>.
        They are not claimed as trained ML classifier outputs. Optional autoencoder anomaly scores appear
        only when a trained model artifact is present under <code className="text-amber-100">ml/artifacts</code>.
      </div>

      <div className="bg-gray-900 border border-gray-800 rounded-lg p-6">
        <h3 className="text-sm font-semibold text-gray-200">Flow Anomaly Autoencoder (optional)</h3>
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
            <p className="text-gray-500">Status</p>
            <p className="text-gray-200">Loads if artifacts exist; otherwise scores are unavailable</p>
          </div>
        </div>
      </div>

      <div className="bg-gray-900 border border-gray-800 rounded-lg p-6">
        <h3 className="text-sm font-semibold text-gray-200">Rule-based Threat Detectors</h3>
        <div className="mt-3 space-y-2">
          {[
            ['Exfiltration Detector', 'Outbound volume ratio, large transfers, long duration'],
            ['C2 Beacon Detector', 'Inter-arrival periodicity, repeated pairs, size consistency'],
            ['Reconnaissance Detector', 'Port/host fan-out, short-lived probes'],
            ['DNS Tunnel Detector', 'Query size, rate, long labels, entropy'],
            ['DDoS Detector', 'Flow rate, SYN patterns, source/destination concentration'],
            ['DGA Detector', 'Domain entropy and label structure heuristics'],
            ['Encrypted Threat Detector', 'TLS-port asymmetry and long transfers'],
          ].map(([name, desc]) => (
            <div key={name} className="flex items-start justify-between py-2 border-b border-gray-800/50 gap-4">
              <div>
                <span className="text-sm text-gray-300">{name}</span>
                <p className="text-xs text-gray-600 mt-0.5">{desc}</p>
              </div>
              <span className="text-xs text-green-400 shrink-0">Available</span>
            </div>
          ))}
        </div>
      </div>

      <EmptyState message="Evaluation accuracy numbers are not fabricated here. Train and evaluate models separately under ml/." />
    </div>
  );
}
