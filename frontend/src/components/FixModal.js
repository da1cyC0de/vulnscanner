'use client';

import { useEffect, useState, useRef, useCallback } from 'react';

const AI_STEPS = [
  { label: 'Menganalisis vulnerability...', icon: '🔍', duration: 2000 },
  { label: 'Memeriksa evidence & payload...', icon: '🧪', duration: 2500 },
  { label: 'Generating fix guide...', icon: '🤖', duration: 3000 },
  { label: 'Membuat code example...', icon: '💻', duration: 2000 },
  { label: 'Finalisasi rekomendasi...', icon: '✅', duration: 1500 },
];

export default function FixModal({ vuln, onClose }) {
  const [aiData, setAiData] = useState(null);
  const [aiLoading, setAiLoading] = useState(false);
  const [aiError, setAiError] = useState(null);
  const [aiStep, setAiStep] = useState(0);
  const [elapsed, setElapsed] = useState(0);
  const timerRef = useRef(null);
  const stepTimerRef = useRef(null);
  const hasStarted = useRef(false);

  useEffect(() => {
    const handleEsc = (e) => { if (e.key === 'Escape') onClose(); };
    document.addEventListener('keydown', handleEsc);
    return () => document.removeEventListener('keydown', handleEsc);
  }, [onClose]);

  const askAI = useCallback(async () => {
    setAiLoading(true);
    setAiError(null);
    setAiData(null);
    setAiStep(0);
    setElapsed(0);

    // Start elapsed timer
    const start = Date.now();
    timerRef.current = setInterval(() => {
      setElapsed(Math.floor((Date.now() - start) / 1000));
    }, 1000);

    // Animate steps
    let step = 0;
    const advanceStep = () => {
      step++;
      if (step < AI_STEPS.length) {
        setAiStep(step);
        stepTimerRef.current = setTimeout(advanceStep, AI_STEPS[step].duration);
      }
    };
    stepTimerRef.current = setTimeout(advanceStep, AI_STEPS[0].duration);

    try {
      const resp = await fetch(`${process.env.NEXT_PUBLIC_API_URL || 'http://127.0.0.1:6969'}/api/ai-fix`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          bug_id: vuln.bug_id,
          name: vuln.name || vuln.title || '',
          severity: vuln.severity || '',
          category: vuln.category || '',
          description: vuln.description || '',
          evidence: vuln.evidence || '',
          target_url: vuln.target_url || '',
        }),
      });
      const data = await resp.json();
      // Jump to last step briefly before showing result
      setAiStep(AI_STEPS.length - 1);
      await new Promise(r => setTimeout(r, 600));
      if (data.ai_generated) {
        setAiData(data);
      } else {
        setAiError(data.error || 'AI tidak bisa generate fix guide');
      }
    } catch (e) {
      setAiError('Gagal connect ke server: ' + e.message);
    } finally {
      setAiLoading(false);
      clearInterval(timerRef.current);
      clearTimeout(stepTimerRef.current);
    }
  }, [vuln]);

  // Auto-trigger AI on mount
  useEffect(() => {
    if (!hasStarted.current) {
      hasStarted.current = true;
      askAI();
    }
    return () => {
      clearInterval(timerRef.current);
      clearTimeout(stepTimerRef.current);
    };
  }, [askAI]);

  const severityColor = {
    critical: 'text-red-400 bg-red-900/20 border-red-800',
    high: 'text-orange-400 bg-orange-900/20 border-orange-800',
    medium: 'text-yellow-400 bg-yellow-900/20 border-yellow-800',
    low: 'text-green-400 bg-green-900/20 border-green-800',
    info: 'text-blue-400 bg-blue-900/20 border-blue-800',
  };

  const sev = (vuln.severity || 'info').toLowerCase();

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-black/70 backdrop-blur-sm" onClick={onClose} />

      <div className="relative bg-gray-900 border border-gray-700 rounded-2xl max-w-3xl w-full max-h-[85vh] overflow-y-auto shadow-2xl">
        {/* Header */}
        <div className="sticky top-0 bg-gray-900 border-b border-gray-800 p-6 flex items-start justify-between z-10">
          <div className="flex-1 pr-4">
            <div className="flex items-center gap-3 mb-2">
              <span className={`px-2.5 py-1 rounded-md text-xs font-bold border ${severityColor[sev]}`}>
                {sev.toUpperCase()}
              </span>
              <span className="text-xs text-gray-500 font-mono">{vuln.bug_id}</span>
            </div>
            <h2 className="text-xl font-bold text-white">{vuln.name || vuln.title}</h2>
          </div>
          <button onClick={onClose} className="p-2 hover:bg-gray-800 rounded-lg transition-colors text-gray-400 hover:text-white">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" />
            </svg>
          </button>
        </div>

        <div className="p-6 space-y-6">
          {/* Description */}
          <Section title="Deskripsi">
            <p className="text-gray-300">{vuln.description}</p>
          </Section>

          {/* Evidence */}
          {vuln.evidence && (
            <Section title="Evidence">
              <pre className="bg-gray-950 border border-gray-800 rounded-lg p-4 overflow-x-auto">
                <code className="text-gray-300 text-sm">{vuln.evidence}</code>
              </pre>
            </Section>
          )}

          {/* AI Section */}
          <div className="border-t border-gray-800 pt-6">
            {aiLoading && (
              <div className="bg-gray-950/50 border border-purple-900/50 rounded-xl p-6">
                {/* Header */}
                <div className="flex items-center gap-3 mb-5">
                  <div className="relative">
                    <div className="w-10 h-10 rounded-full bg-purple-600/20 flex items-center justify-center">
                      <span className="text-xl">🤖</span>
                    </div>
                    <div className="absolute -top-1 -right-1 w-3 h-3 bg-purple-500 rounded-full animate-ping"></div>
                    <div className="absolute -top-1 -right-1 w-3 h-3 bg-purple-400 rounded-full"></div>
                  </div>
                  <div>
                    <h3 className="text-purple-300 font-bold">AI sedang bekerja...</h3>
                    <p className="text-gray-500 text-xs">{elapsed}s elapsed</p>
                  </div>
                </div>

                {/* Steps */}
                <div className="space-y-3 mb-5">
                  {AI_STEPS.map((s, i) => (
                    <div key={i} className={`flex items-center gap-3 transition-all duration-500 ${i <= aiStep ? 'opacity-100' : 'opacity-30'}`}>
                      <div className={`w-7 h-7 rounded-full flex items-center justify-center text-sm flex-shrink-0 transition-all duration-500 ${
                        i < aiStep ? 'bg-green-600/20 border border-green-700' :
                        i === aiStep ? 'bg-purple-600/30 border border-purple-500 animate-pulse' :
                        'bg-gray-800 border border-gray-700'
                      }`}>
                        {i < aiStep ? '✓' : s.icon}
                      </div>
                      <span className={`text-sm transition-colors duration-500 ${
                        i < aiStep ? 'text-green-400 line-through' :
                        i === aiStep ? 'text-purple-300 font-medium' :
                        'text-gray-600'
                      }`}>{s.label}</span>
                      {i === aiStep && <div className="w-4 h-4 border-2 border-purple-500 border-t-transparent rounded-full animate-spin ml-auto"></div>}
                    </div>
                  ))}
                </div>

                {/* Progress bar */}
                <div className="h-1.5 bg-gray-800 rounded-full overflow-hidden">
                  <div
                    className="h-full bg-gradient-to-r from-purple-600 to-blue-500 rounded-full transition-all duration-700 ease-out"
                    style={{ width: `${Math.min(((aiStep + 1) / AI_STEPS.length) * 100, 95)}%` }}
                  />
                </div>
              </div>
            )}

            {aiError && (
              <div className="bg-red-950/30 border border-red-900/50 rounded-xl p-4">
                <p className="text-red-400 text-sm">{aiError}</p>
                <button onClick={askAI} className="mt-2 text-sm text-red-300 underline hover:text-red-200">Coba lagi</button>
              </div>
            )}

            {aiData && (
              <div className="space-y-5">
                <div className="flex items-center gap-2 mb-2">
                  <span className="text-purple-400 text-lg">🤖</span>
                  <h3 className="text-purple-400 font-bold text-lg">AI Fix Guide</h3>
                  <span className="text-xs bg-purple-900/30 text-purple-300 px-2 py-0.5 rounded-full">AI Generated</span>
                </div>

                {aiData.title && (
                  <Section title="Fix">
                    <p className="text-white font-semibold">{aiData.title}</p>
                  </Section>
                )}

                {aiData.risk_explanation && (
                  <Section title="🔴 Risiko Spesifik">
                    <p className="text-gray-300">{aiData.risk_explanation}</p>
                  </Section>
                )}

                {aiData.fix_steps && aiData.fix_steps.length > 0 && (
                  <Section title="🔧 Langkah Fix">
                    <ol className="list-decimal list-inside space-y-2">
                      {aiData.fix_steps.map((step, i) => (
                        <li key={i} className="text-gray-300">{step}</li>
                      ))}
                    </ol>
                  </Section>
                )}

                {aiData.code_before && (
                  <Section title="❌ Kode Rentan">
                    <pre className="bg-red-950/30 border border-red-900/50 rounded-lg p-4 overflow-x-auto">
                      <code className="text-red-300 text-sm whitespace-pre-wrap">{aiData.code_before}</code>
                    </pre>
                  </Section>
                )}

                {aiData.code_after && (
                  <Section title="✅ Kode Fixed">
                    <pre className="bg-green-950/30 border border-green-900/50 rounded-lg p-4 overflow-x-auto">
                      <code className="text-green-300 text-sm whitespace-pre-wrap">{aiData.code_after}</code>
                    </pre>
                  </Section>
                )}

                {aiData.server_config && (
                  <Section title="⚙️ Server Config">
                    <pre className="bg-blue-950/30 border border-blue-900/50 rounded-lg p-4 overflow-x-auto">
                      <code className="text-blue-300 text-sm whitespace-pre-wrap">{aiData.server_config}</code>
                    </pre>
                  </Section>
                )}

                {aiData.references && aiData.references.length > 0 && (
                  <Section title="📚 References">
                    <ul className="space-y-1">
                      {aiData.references.map((ref, i) => (
                        <li key={i}>
                          <a href={ref.startsWith('http') ? ref : '#'} target="_blank" rel="noopener noreferrer"
                            className="text-blue-400 hover:text-blue-300 text-sm underline break-all">{ref}</a>
                        </li>
                      ))}
                    </ul>
                  </Section>
                )}

                <button onClick={askAI} className="text-sm text-purple-400 hover:text-purple-300 underline">
                  🔄 Generate ulang
                </button>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

function Section({ title, children }) {
  return (
    <div>
      <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-2">{title}</h3>
      {children}
    </div>
  );
}
