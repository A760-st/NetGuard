import { useEffect, useState } from 'react';
import { getIncidents, getIncidentAnalyst } from '../services/api';
import type { Incident } from '../types';
import type { AnalystSummary } from '../services/api';
import SeverityBadge from '../components/SeverityBadge';
import EmptyState from '../components/EmptyState';

export default function Analyst() {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [selectedId, setSelectedId] = useState('');
  const [summary, setSummary] = useState<AnalystSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [analyzing, setAnalyzing] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    getIncidents(1, 50)
      .then((res) => {
        setIncidents(res.items);
        if (res.items[0]) setSelectedId(res.items[0].id);
      })
      .catch((err) => setError(err instanceof Error ? err.message : 'Failed to load incidents'))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    if (!selectedId) {
      setSummary(null);
      return;
    }
    setAnalyzing(true);
    setError('');
    getIncidentAnalyst(selectedId)
      .then(setSummary)
      .catch((err) => {
        setSummary(null);
        setError(err instanceof Error ? err.message : 'Analyst summary failed');
      })
      .finally(() => setAnalyzing(false));
  }, [selectedId]);

  if (loading) return <div className="text-gray-500 text-sm">Loading...</div>;
  if (incidents.length === 0) {
    return <EmptyState message="No incidents available. Process recorded traffic first, then return for analysis." />;
  }

  const selected = incidents.find((i) => i.id === selectedId) || null;

  return (
    <div className="space-y-4">
      <div className="bg-gray-900 border border-gray-800 rounded-lg p-4 space-y-3">
        <div>
          <h3 className="text-sm font-semibold text-gray-200">AI Analyst</h3>
          <p className="text-xs text-gray-500 mt-1">
            Evidence-grounded analysis for a selected incident. Uses a deterministic fallback summary unless an external AI API is configured.
          </p>
        </div>
        <select
          value={selectedId}
          onChange={(e) => setSelectedId(e.target.value)}
          className="w-full bg-gray-950 border border-gray-700 text-xs rounded px-2 py-2 text-gray-300"
        >
          {incidents.map((inc) => (
            <option key={inc.id} value={inc.id}>
              [{inc.severity}] {inc.title}
            </option>
          ))}
        </select>
      </div>

      {error && <p className="text-xs text-red-400">{error}</p>}
      {analyzing && <p className="text-xs text-gray-500">Building analysis from detection evidence…</p>}

      {summary && selected && (
        <div className="space-y-4">
          <div className="bg-amber-950/30 border border-amber-800/50 rounded-lg p-3 text-xs text-amber-200/90">
            {summary.disclaimer}
            {summary.source === 'deterministic_fallback' && (
              <span className="block mt-1 text-amber-400/80">Source: deterministic fallback (not an LLM response).</span>
            )}
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="bg-gray-900 border border-gray-800 rounded-lg p-4">
              <p className="text-xs text-gray-500 mb-1">Severity assessment</p>
              <div className="flex items-center gap-2">
                <SeverityBadge severity={summary.severity_assessment.severity} />
                <span className="text-sm text-gray-200">
                  {(summary.severity_assessment.confidence * 100).toFixed(0)}% confidence
                </span>
              </div>
              {summary.severity_assessment.risk_score != null && (
                <p className="text-xs text-gray-400 mt-2">
                  Risk score: {Number(summary.severity_assessment.risk_score).toFixed(1)}
                </p>
              )}
            </div>
            <div className="bg-gray-900 border border-gray-800 rounded-lg p-4 md:col-span-2">
              <p className="text-xs text-gray-500 mb-1">Incident summary</p>
              <p className="text-sm text-gray-200 leading-relaxed">{summary.incident_summary}</p>
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <section className="bg-gray-900 border border-gray-800 rounded-lg p-4 space-y-2">
              <h4 className="text-xs font-semibold text-gray-300">Why it matters</h4>
              <p className="text-xs text-gray-400 leading-relaxed">{summary.why_it_matters}</p>
              <h4 className="text-xs font-semibold text-gray-300 pt-2">Why flagged</h4>
              <p className="text-xs text-gray-400 leading-relaxed">{summary.why_flagged}</p>
            </section>

            <section className="bg-gray-900 border border-gray-800 rounded-lg p-4 space-y-2">
              <h4 className="text-xs font-semibold text-gray-300">Suspicious indicators</h4>
              <ul className="space-y-1">
                {summary.suspicious_indicators.map((item, idx) => (
                  <li key={idx} className="text-xs text-gray-400 border-b border-gray-800/50 pb-1">{item}</li>
                ))}
              </ul>
            </section>
          </div>

          <section className="bg-gray-900 border border-gray-800 rounded-lg p-4 space-y-2">
            <h4 className="text-xs font-semibold text-gray-300">Evidence</h4>
            {summary.evidence.length === 0 ? (
              <p className="text-xs text-gray-500">No structured evidence items available.</p>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                {summary.evidence.map((ev, idx) => (
                  <div key={idx} className="border border-gray-800 rounded p-2 text-xs text-gray-400">
                    <div className="font-mono text-gray-300">{String(ev.feature ?? 'feature')}</div>
                    <div className="mt-1">{String(ev.interpretation ?? '')}</div>
                  </div>
                ))}
              </div>
            )}
          </section>

          <section className="bg-gray-900 border border-gray-800 rounded-lg p-4 space-y-2">
            <h4 className="text-xs font-semibold text-gray-300">Recommended investigation steps</h4>
            <ol className="list-decimal list-inside space-y-1">
              {summary.recommended_investigation_steps.map((step, idx) => (
                <li key={idx} className="text-xs text-gray-400">{step}</li>
              ))}
            </ol>
          </section>
        </div>
      )}
    </div>
  );
}
