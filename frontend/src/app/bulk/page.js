'use client';

import { useState, useEffect, useCallback } from 'react';
import Link from 'next/link';
import ProgressBar from '../../components/ProgressBar';
import ResultsTable from '../../components/ResultsTable';
import FixModal from '../../components/FixModal';
import StatsCards from '../../components/StatsCards';

export default function BulkScanPage() {
  const [scanState, setScanState] = useState('idle'); // idle, scanning, completed, error, mass-result
  const [progress, setProgress] = useState(null);
  const [results, setResults] = useState([]);
  const [scanId, setScanId] = useState(null);
  const [selectedVuln, setSelectedVuln] = useState(null);
  const [errorMsg, setErrorMsg] = useState('');
  const [massResults, setMassResults] = useState(null);

  // Form state
  const [mode, setMode] = useState('single'); // single (1 URL + pick modules), mass (multi URL + pick modules)
  const [url, setUrl] = useState('');
  const [massUrls, setMassUrls] = useState('');
  const [modules, setModules] = useState([]);
  const [selectedModules, setSelectedModules] = useState([]);
  const [loadingModules, setLoadingModules] = useState(true);

  const wsRef = { current: null };

  // Load modules on mount
  useEffect(() => {
    fetch(`${process.env.NEXT_PUBLIC_API_URL || 'http://127.0.0.1:6969'}/api/modules`)
      .then(r => r.json())
      .then(data => { setModules(data.modules || []); setLoadingModules(false); })
      .catch(() => setLoadingModules(false));
  }, []);

  const toggleModule = (id) => {
    setSelectedModules(prev => prev.includes(id) ? prev.filter(m => m !== id) : [...prev, id]);
  };

  const normalizeUrl = (raw) => {
    let u = raw.trim();
    if (!u) return '';
    if (!u.startsWith('http://') && !u.startsWith('https://')) u = 'https://' + u;
    return u;
  };

  // Single URL scan with selected modules (via WebSocket)
  const startSingleScan = useCallback((targetUrl, mods) => {
    setScanState('scanning');
    setResults([]);
    setProgress(null);
    setErrorMsg('');
    setMassResults(null);

    const ws = new WebSocket(`${process.env.NEXT_PUBLIC_WS_URL || 'ws://127.0.0.1:6969'}/ws/scan`);
    wsRef.current = ws;

    ws.onopen = () => {
      const payload = { url: targetUrl };
      if (mods && mods.length > 0) payload.modules = mods;
      ws.send(JSON.stringify(payload));
    };

    ws.onmessage = (event) => {
      const data = JSON.parse(event.data);
      if (data.error) { setErrorMsg(data.error); setScanState('error'); return; }
      if (data.scan_id) setScanId(data.scan_id);
      if (data.results) setResults(data.results);
      setProgress({
        total: data.total_modules || 0,
        completed: data.completed_modules || 0,
        current: data.current_module || '',
        percent: data.progress_percent || 0,
        elapsed: data.elapsed_time || 0,
        status: data.status || 'scanning',
        summary: data.summary || {},
      });
      if (data.status === 'completed') setScanState('completed');
    };

    ws.onerror = () => {
      setErrorMsg('Connection error. Make sure backend is running on port 6969.');
      setScanState('error');
    };

    ws.onclose = () => {
      setScanState((prev) => (prev === 'scanning' ? 'completed' : prev));
    };
  }, []);

  // Mass scan (multiple URLs)
  const startMassScan = useCallback(async (urls, mods) => {
    setScanState('scanning');
    setResults([]);
    setMassResults(null);
    setErrorMsg('');
    setProgress({ total: urls.length, completed: 0, current: 'Mass Scan in progress...', percent: 5, elapsed: 0, status: 'scanning', summary: {} });

    try {
      const resp = await fetch(`${process.env.NEXT_PUBLIC_API_URL || 'http://127.0.0.1:6969'}/api/mass-scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ urls, modules: mods && mods.length > 0 ? mods : null }),
      });
      const data = await resp.json();
      setMassResults(data);
      setScanState('mass-result');
    } catch {
      setErrorMsg('Backend connection error');
      setScanState('error');
    }
  }, []);

  const exportReport = (sid, fmt) => {
    window.open(`${process.env.NEXT_PUBLIC_API_URL || 'http://127.0.0.1:6969'}/api/export/${sid}/${fmt}`, '_blank');
  };

  const resetScan = () => {
    if (wsRef.current) wsRef.current.close();
    setScanState('idle');
    setResults([]);
    setProgress(null);
    setScanId(null);
    setErrorMsg('');
    setMassResults(null);
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    if (mode === 'mass') {
      const urls = massUrls.split('\n').map(normalizeUrl).filter(Boolean);
      if (urls.length === 0) return;
      startMassScan(urls, selectedModules);
    } else {
      const finalUrl = normalizeUrl(url);
      if (!finalUrl) return;
      startSingleScan(finalUrl, selectedModules);
    }
  };

  return (
    <main className="min-h-screen">
      {/* Header */}
      <header className="border-b border-gray-800 bg-gray-900/50 backdrop-blur-sm sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Link href="/" className="w-10 h-10 rounded-lg bg-blue-600 flex items-center justify-center font-bold text-lg hover:bg-blue-700 transition-colors">VS</Link>
            <div>
              <h1 className="text-xl font-bold text-white">VulnScanner</h1>
              <p className="text-xs text-gray-400">Bulk Scan</p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <Link href="/" className="px-3 py-1.5 text-sm text-gray-400 hover:text-white rounded-lg transition-colors">Home</Link>
            <Link href="/scan" className="px-3 py-1.5 text-sm text-gray-400 hover:text-white rounded-lg transition-colors">Scan All</Link>
            <Link href="/bulk" className="px-4 py-2 text-sm bg-blue-600 text-white rounded-lg font-medium">Bulk Scan</Link>
            <Link href="/dorking" className="px-3 py-1.5 text-sm text-gray-400 hover:text-white rounded-lg transition-colors">Dorking</Link>
            <Link href="/modules" className="px-3 py-1.5 text-sm text-gray-400 hover:text-white rounded-lg transition-colors">Modules</Link>
            {scanState !== 'idle' && (
              <button onClick={resetScan} className="px-4 py-2 text-sm bg-gray-800 hover:bg-gray-700 rounded-lg transition-colors">
                New Scan
              </button>
            )}
          </div>
        </div>
      </header>

      <div className="max-w-7xl mx-auto px-4 py-8">
        {/* Idle - Bulk Form */}
        {scanState === 'idle' && (
          <div>
            <div className="text-center mb-8">
              <h2 className="text-3xl font-bold text-white mb-2">Bulk Scan</h2>
              <p className="text-gray-400">Scan satu atau banyak URL dengan pilihan module spesifik</p>
            </div>

            <form onSubmit={handleSubmit} className="max-w-4xl mx-auto">
              {/* Mode Toggle */}
              <div className="flex gap-2 mb-6 justify-center">
                <button type="button" onClick={() => setMode('single')}
                  className={`px-5 py-2.5 rounded-lg text-sm font-medium transition-all ${mode === 'single' ? 'bg-blue-600 text-white shadow-lg shadow-blue-600/25' : 'bg-gray-800 text-gray-400 hover:bg-gray-700'}`}>
                  🎯 Single URL + Pilih Module
                </button>
                <button type="button" onClick={() => setMode('mass')}
                  className={`px-5 py-2.5 rounded-lg text-sm font-medium transition-all ${mode === 'mass' ? 'bg-blue-600 text-white shadow-lg shadow-blue-600/25' : 'bg-gray-800 text-gray-400 hover:bg-gray-700'}`}>
                  🚀 Mass Scan (Multi URL)
                </button>
              </div>

              {/* Single URL Input */}
              {mode === 'single' && (
                <div className="mb-6">
                  <label className="block text-sm text-gray-400 mb-2">Target URL</label>
                  <input type="text" value={url} onChange={(e) => setUrl(e.target.value)}
                    placeholder="https://example.com"
                    className="w-full px-4 py-3 bg-gray-800 border border-gray-700 rounded-xl text-white placeholder-gray-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 transition-all text-lg"
                  />
                </div>
              )}

              {/* Mass URL Input */}
              {mode === 'mass' && (
                <div className="mb-6">
                  <label className="block text-sm text-gray-400 mb-2">Target URLs (satu per baris, max 10)</label>
                  <textarea value={massUrls} onChange={(e) => setMassUrls(e.target.value)}
                    placeholder={"https://example1.com\nhttps://example2.com\nhttps://example3.com"}
                    rows={5}
                    className="w-full px-4 py-3 bg-gray-800 border border-gray-700 rounded-xl text-white placeholder-gray-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 transition-all font-mono text-sm"
                  />
                  <p className="text-xs text-gray-500 mt-1">
                    {massUrls.split('\n').filter(l => l.trim()).length} URL(s) entered
                  </p>
                </div>
              )}

              {/* Module Selection */}
              <div className="mb-6">
                <div className="flex items-center justify-between mb-3">
                  <label className="text-sm text-gray-400">
                    Pilih Module Scanner ({selectedModules.length}/{modules.length} selected)
                  </label>
                  <div className="flex gap-3">
                    <button type="button" onClick={() => setSelectedModules(modules.map(m => m.id))}
                      className="text-xs text-blue-400 hover:text-blue-300 transition-colors">Select All</button>
                    <button type="button" onClick={() => setSelectedModules([])}
                      className="text-xs text-gray-400 hover:text-gray-300 transition-colors">Clear All</button>
                  </div>
                </div>

                {loadingModules ? (
                  <div className="text-center py-8 text-gray-500">Loading modules...</div>
                ) : (
                  <div className="bg-gray-800/50 border border-gray-700 rounded-xl p-4">
                    <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-2">
                      {modules.map(m => (
                        <label key={m.id}
                          className={`flex items-center gap-2.5 px-3 py-2.5 rounded-lg cursor-pointer text-sm transition-all ${
                            selectedModules.includes(m.id)
                              ? 'bg-blue-900/40 border border-blue-700 text-blue-300'
                              : 'bg-gray-800 border border-gray-700 text-gray-400 hover:border-gray-600 hover:text-gray-300'
                          }`}>
                          <div className={`w-4 h-4 rounded border flex items-center justify-center text-xs flex-shrink-0 ${
                            selectedModules.includes(m.id)
                              ? 'bg-blue-600 border-blue-600 text-white'
                              : 'border-gray-600'
                          }`}>
                            {selectedModules.includes(m.id) && '✓'}
                          </div>
                          <input type="checkbox" checked={selectedModules.includes(m.id)}
                            onChange={() => toggleModule(m.id)} className="sr-only" />
                          {m.name}
                        </label>
                      ))}
                    </div>
                  </div>
                )}

                {selectedModules.length === 0 && (
                  <p className="text-xs text-yellow-500/70 mt-2">
                    ⚠ Belum ada module dipilih — akan menjalankan semua 29 module
                  </p>
                )}
              </div>

              {/* Submit */}
              <button type="submit"
                className="w-full py-4 bg-blue-600 hover:bg-blue-700 text-white font-semibold rounded-xl transition-all hover:shadow-lg hover:shadow-blue-600/25 active:scale-[0.99] text-lg">
                {mode === 'mass'
                  ? `🚀 Start Mass Scan (${massUrls.split('\n').filter(l => l.trim()).length} URLs)`
                  : `🎯 Start Scan${selectedModules.length > 0 ? ` (${selectedModules.length} modules)` : ' (All modules)'}`
                }
              </button>
            </form>

            {/* Link back */}
            <div className="mt-8 text-center">
              <Link href="/" className="text-sm text-gray-500 hover:text-blue-400 transition-colors">
                ← Kembali ke Scan All (simple mode)
              </Link>
            </div>
          </div>
        )}

        {/* Error */}
        {scanState === 'error' && (
          <div className="max-w-2xl mx-auto mt-12">
            <div className="bg-red-900/20 border border-red-800 rounded-xl p-6 text-center">
              <div className="text-red-400 text-lg font-semibold mb-2">Scan Error</div>
              <p className="text-red-300">{errorMsg}</p>
              <button onClick={resetScan} className="mt-4 px-6 py-2 bg-red-600 hover:bg-red-700 rounded-lg transition-colors">Try Again</button>
            </div>
          </div>
        )}

        {/* Mass Scan Results */}
        {scanState === 'mass-result' && massResults && (
          <div>
            <h3 className="text-white font-semibold text-lg mb-4">
              Mass Scan Results — {massResults.total_urls} target(s)
            </h3>
            <div className="grid gap-3">
              {Object.entries(massResults.scans || {}).map(([sid, data]) => (
                <div key={sid} className="bg-gray-900 border border-gray-800 rounded-xl p-5">
                  <div className="flex items-center justify-between mb-3">
                    <div className="flex items-center gap-3">
                      <span className="text-white font-mono text-sm">{data.url}</span>
                      <span className="px-2 py-0.5 bg-gray-800 rounded text-xs text-gray-400">ID: {sid}</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="text-2xl font-bold text-white">{data.total_vulns}</span>
                      <span className="text-xs text-gray-400">vulns</span>
                    </div>
                  </div>
                  {/* Summary badges */}
                  <div className="flex gap-2 flex-wrap mb-3">
                    {Object.entries(data.summary || {}).map(([sev, count]) => (
                      count > 0 && (
                        <span key={sev} className={`px-2 py-0.5 rounded text-xs font-medium ${
                          sev === 'critical' ? 'bg-red-900/30 text-red-400' :
                          sev === 'high' ? 'bg-orange-900/30 text-orange-400' :
                          sev === 'medium' ? 'bg-yellow-900/30 text-yellow-400' :
                          sev === 'low' ? 'bg-blue-900/30 text-blue-400' :
                          'bg-gray-800 text-gray-400'
                        }`}>
                          {sev}: {count}
                        </span>
                      )
                    ))}
                  </div>
                  {/* Export buttons per scan */}
                  <div className="flex gap-2">
                    <button onClick={() => exportReport(sid, 'html')} className="px-2.5 py-1 bg-orange-900/20 border border-orange-800/50 text-orange-400 rounded text-xs hover:bg-orange-900/40">HTML</button>
                    <button onClick={() => exportReport(sid, 'json')} className="px-2.5 py-1 bg-green-900/20 border border-green-800/50 text-green-400 rounded text-xs hover:bg-green-900/40">JSON</button>
                    <button onClick={() => exportReport(sid, 'csv')} className="px-2.5 py-1 bg-blue-900/20 border border-blue-800/50 text-blue-400 rounded text-xs hover:bg-blue-900/40">CSV</button>
                    <button onClick={() => exportReport(sid, 'md')} className="px-2.5 py-1 bg-purple-900/20 border border-purple-800/50 text-purple-400 rounded text-xs hover:bg-purple-900/40">MD</button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Scanning / Completed (single bulk scan) */}
        {(scanState === 'scanning' || scanState === 'completed') && (
          <div>
            <div className="mb-6 flex items-center gap-3 flex-wrap">
              <span className="text-sm text-gray-400">Target:</span>
              <span className="px-3 py-1 bg-blue-900/30 border border-blue-800 rounded-full text-blue-300 text-sm font-mono truncate max-w-md">{url}</span>
              {scanId && <span className="px-3 py-1 bg-gray-800 rounded-full text-gray-400 text-xs">ID: {scanId}</span>}
              {selectedModules.length > 0 && (
                <span className="px-3 py-1 bg-purple-900/30 border border-purple-800 rounded-full text-purple-300 text-xs">
                  {selectedModules.length} modules selected
                </span>
              )}

              {/* Export */}
              {scanState === 'completed' && scanId && (
                <div className="flex gap-2 ml-auto">
                  <button onClick={() => exportReport(scanId, 'html')} className="px-3 py-1.5 bg-orange-900/30 border border-orange-800 text-orange-400 rounded-lg text-xs font-medium hover:bg-orange-900/50">Export HTML</button>
                  <button onClick={() => exportReport(scanId, 'json')} className="px-3 py-1.5 bg-green-900/30 border border-green-800 text-green-400 rounded-lg text-xs font-medium hover:bg-green-900/50">Export JSON</button>
                  <button onClick={() => exportReport(scanId, 'csv')} className="px-3 py-1.5 bg-blue-900/30 border border-blue-800 text-blue-400 rounded-lg text-xs font-medium hover:bg-blue-900/50">Export CSV</button>
                  <button onClick={() => exportReport(scanId, 'md')} className="px-3 py-1.5 bg-purple-900/30 border border-purple-800 text-purple-400 rounded-lg text-xs font-medium hover:bg-purple-900/50">Export MD</button>
                </div>
              )}
            </div>

            <ProgressBar progress={progress} scanning={scanState === 'scanning'} />
            {results.length > 0 && <StatsCards results={results} />}
            <ResultsTable results={results} onSelectVuln={setSelectedVuln} scanning={scanState === 'scanning'} />
          </div>
        )}
      </div>

      {/* Fix Modal */}
      {selectedVuln && <FixModal vuln={selectedVuln} onClose={() => setSelectedVuln(null)} />}
    </main>
  );
}
