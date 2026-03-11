'use client';

import { useState, useRef, useCallback, useEffect, Suspense } from 'react';
import { useSearchParams } from 'next/navigation';
import Link from 'next/link';
import ProgressBar from '../../components/ProgressBar';
import ResultsTable from '../../components/ResultsTable';
import FixModal from '../../components/FixModal';
import StatsCards from '../../components/StatsCards';

export default function ScanAllPage() {
  return (
    <Suspense fallback={<div className="min-h-screen bg-gray-950 flex items-center justify-center text-gray-400">Loading...</div>}>
      <ScanAllContent />
    </Suspense>
  );
}

function ScanAllContent() {
  const searchParams = useSearchParams();
  const [scanState, setScanState] = useState('idle');
  const [progress, setProgress] = useState(null);
  const [results, setResults] = useState([]);
  const [scanId, setScanId] = useState(null);
  const [targetUrl, setTargetUrl] = useState('');
  const [url, setUrl] = useState('');
  const [selectedVuln, setSelectedVuln] = useState(null);
  const [errorMsg, setErrorMsg] = useState('');
  const wsRef = useRef(null);

  // Pre-fill URL from query param (e.g., from Dorking page "Scan This")
  useEffect(() => {
    const paramUrl = searchParams.get('url');
    if (paramUrl) setUrl(paramUrl);
  }, [searchParams]);

  const normalizeUrl = (raw) => {
    let u = raw.trim();
    if (!u) return '';
    if (!u.startsWith('http://') && !u.startsWith('https://')) u = 'https://' + u;
    return u;
  };

  const startScan = useCallback((target) => {
    setTargetUrl(target);
    setScanState('scanning');
    setResults([]);
    setProgress(null);
    setErrorMsg('');

    const ws = new WebSocket(`${process.env.NEXT_PUBLIC_WS_URL || 'ws://127.0.0.1:6969'}/ws/scan`);
    wsRef.current = ws;

    ws.onopen = () => {
      ws.send(JSON.stringify({ url: target }));
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

  const exportReport = (fmt) => {
    if (!scanId) return;
    window.open(`${process.env.NEXT_PUBLIC_API_URL || 'http://127.0.0.1:6969'}/api/export/${scanId}/${fmt}`, '_blank');
  };

  const resetScan = () => {
    if (wsRef.current) wsRef.current.close();
    setScanState('idle');
    setResults([]);
    setProgress(null);
    setScanId(null);
    setErrorMsg('');
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    const finalUrl = normalizeUrl(url);
    if (!finalUrl) return;
    startScan(finalUrl);
  };

  return (
    <main className="min-h-screen">
      <header className="border-b border-gray-800 bg-gray-900/50 backdrop-blur-sm sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Link href="/" className="w-10 h-10 rounded-lg bg-blue-600 flex items-center justify-center font-bold text-lg hover:bg-blue-700 transition-colors">VS</Link>
            <div>
              <h1 className="text-xl font-bold text-white">VulnScanner</h1>
              <p className="text-xs text-gray-400">Scan All</p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <Link href="/" className="px-3 py-1.5 text-sm text-gray-400 hover:text-white rounded-lg transition-colors">Home</Link>
            <Link href="/scan" className="px-4 py-2 text-sm bg-blue-600 text-white rounded-lg font-medium">Scan All</Link>
            <Link href="/bulk" className="px-3 py-1.5 text-sm text-gray-400 hover:text-white rounded-lg transition-colors">Bulk Scan</Link>
            <Link href="/dorking" className="px-3 py-1.5 text-sm text-gray-400 hover:text-white rounded-lg transition-colors">Dorking</Link>
            <Link href="/modules" className="px-3 py-1.5 text-sm text-gray-400 hover:text-white rounded-lg transition-colors">Modules</Link>
            {scanState !== 'idle' && (
              <button onClick={resetScan} className="px-4 py-2 text-sm bg-gray-800 hover:bg-gray-700 rounded-lg transition-colors">New Scan</button>
            )}
          </div>
        </div>
      </header>

      <div className="max-w-7xl mx-auto px-4 py-8">
        {/* Idle */}
        {scanState === 'idle' && (
          <div className="flex flex-col items-center justify-center min-h-[60vh]">
            <div className="text-center mb-8">
              <h2 className="text-4xl font-bold text-white mb-3">Scan All Vulnerabilities</h2>
              <p className="text-gray-400 text-lg">Enter a single URL — runs all 29 scanner modules</p>
            </div>
            <form onSubmit={handleSubmit} className="w-full max-w-2xl">
              <div className="flex gap-3">
                <div className="flex-1 relative">
                  <div className="absolute left-4 top-1/2 -translate-y-1/2 text-gray-500">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <circle cx="12" cy="12" r="10" />
                      <path d="M2 12h20M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" />
                    </svg>
                  </div>
                  <input type="text" value={url} onChange={(e) => setUrl(e.target.value)}
                    placeholder="Enter target URL (e.g., https://example.com)"
                    className="w-full pl-12 pr-4 py-4 bg-gray-800 border border-gray-700 rounded-xl text-white placeholder-gray-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 transition-all text-lg"
                  />
                </div>
                <button type="submit"
                  className="px-8 py-4 bg-blue-600 hover:bg-blue-700 text-white font-semibold rounded-xl transition-all hover:shadow-lg hover:shadow-blue-600/25 active:scale-95">
                  Scan All
                </button>
              </div>
            </form>
            <div className="mt-12 grid grid-cols-4 gap-8 text-center text-gray-400">
              <div><div className="text-3xl font-bold text-blue-400">180+</div><div className="text-sm mt-1">Vulnerability Checks</div></div>
              <div><div className="text-3xl font-bold text-green-400">29</div><div className="text-sm mt-1">Scanner Modules</div></div>
              <div><div className="text-3xl font-bold text-purple-400">Export</div><div className="text-sm mt-1">HTML/JSON/CSV/MD</div></div>
              <div><div className="text-3xl font-bold text-orange-400">AI</div><div className="text-sm mt-1">Fix Guides</div></div>
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

        {/* Scanning / Completed */}
        {(scanState === 'scanning' || scanState === 'completed') && (
          <div>
            <div className="mb-6 flex items-center gap-3 flex-wrap">
              <span className="text-sm text-gray-400">Target:</span>
              <span className="px-3 py-1 bg-blue-900/30 border border-blue-800 rounded-full text-blue-300 text-sm font-mono">{targetUrl}</span>
              {scanId && <span className="px-3 py-1 bg-gray-800 rounded-full text-gray-400 text-xs">ID: {scanId}</span>}
              {scanState === 'completed' && scanId && (
                <div className="flex gap-2 ml-auto">
                  <button onClick={() => exportReport('html')} className="px-3 py-1.5 bg-orange-900/30 border border-orange-800 text-orange-400 rounded-lg text-xs font-medium hover:bg-orange-900/50 transition-colors">Export HTML</button>
                  <button onClick={() => exportReport('json')} className="px-3 py-1.5 bg-green-900/30 border border-green-800 text-green-400 rounded-lg text-xs font-medium hover:bg-green-900/50 transition-colors">Export JSON</button>
                  <button onClick={() => exportReport('csv')} className="px-3 py-1.5 bg-blue-900/30 border border-blue-800 text-blue-400 rounded-lg text-xs font-medium hover:bg-blue-900/50 transition-colors">Export CSV</button>
                  <button onClick={() => exportReport('md')} className="px-3 py-1.5 bg-purple-900/30 border border-purple-800 text-purple-400 rounded-lg text-xs font-medium hover:bg-purple-900/50 transition-colors">Export MD</button>
                </div>
              )}
            </div>
            <ProgressBar progress={progress} scanning={scanState === 'scanning'} />
            {results.length > 0 && <StatsCards results={results} />}
            <ResultsTable results={results} onSelectVuln={setSelectedVuln} scanning={scanState === 'scanning'} />
          </div>
        )}
      </div>

      {selectedVuln && <FixModal vuln={selectedVuln} onClose={() => setSelectedVuln(null)} />}
    </main>
  );
}
