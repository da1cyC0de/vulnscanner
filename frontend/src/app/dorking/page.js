'use client';

import { useState, useCallback } from 'react';
import Link from 'next/link';

export default function DorkingPage() {
  const [state, setState] = useState('idle'); // idle, loading, results, error
  const [domain, setDomain] = useState('');
  const [subdomains, setSubdomains] = useState(null);
  const [errorMsg, setErrorMsg] = useState('');

  const normalizeDomain = (raw) => {
    let d = raw.trim();
    d = d.replace(/^https?:\/\//, '');
    d = d.replace(/\/.*$/, '');
    return d;
  };

  const startDiscovery = useCallback(async () => {
    const d = normalizeDomain(domain);
    if (!d) return;
    setState('loading');
    setSubdomains(null);
    setErrorMsg('');
    try {
      const resp = await fetch(`${process.env.NEXT_PUBLIC_API_URL || 'http://127.0.0.1:8000'}/api/subdomain`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: d }),
      });
      const data = await resp.json();
      setSubdomains(data);
      setState('results');
    } catch {
      setErrorMsg('Backend connection error. Make sure backend is running on port 8000.');
      setState('error');
    }
  }, [domain]);

  const handleSubmit = (e) => {
    e.preventDefault();
    startDiscovery();
  };

  const reset = () => {
    setState('idle');
    setSubdomains(null);
    setErrorMsg('');
  };

  return (
    <main className="min-h-screen">
      <header className="border-b border-gray-800 bg-gray-900/50 backdrop-blur-sm sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Link href="/" className="w-10 h-10 rounded-lg bg-blue-600 flex items-center justify-center font-bold text-lg hover:bg-blue-700 transition-colors">VS</Link>
            <div>
              <h1 className="text-xl font-bold text-white">VulnScanner</h1>
              <p className="text-xs text-gray-400">Dorking & Subdomain</p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <Link href="/" className="px-3 py-1.5 text-sm text-gray-400 hover:text-white rounded-lg transition-colors">Home</Link>
            <Link href="/scan" className="px-3 py-1.5 text-sm text-gray-400 hover:text-white rounded-lg transition-colors">Scan All</Link>
            <Link href="/bulk" className="px-3 py-1.5 text-sm text-gray-400 hover:text-white rounded-lg transition-colors">Bulk Scan</Link>
            <Link href="/dorking" className="px-4 py-2 text-sm bg-blue-600 text-white rounded-lg font-medium">Dorking</Link>
            {state !== 'idle' && (
              <button onClick={reset} className="px-4 py-2 text-sm bg-gray-800 hover:bg-gray-700 rounded-lg transition-colors">New Search</button>
            )}
          </div>
        </div>
      </header>

      <div className="max-w-7xl mx-auto px-4 py-8">
        {/* Idle */}
        {state === 'idle' && (
          <div className="flex flex-col items-center justify-center min-h-[60vh]">
            <div className="text-center mb-8">
              <div className="text-5xl mb-4">🌐</div>
              <h2 className="text-4xl font-bold text-white mb-3">Subdomain Discovery</h2>
              <p className="text-gray-400 text-lg">Discover subdomains via Certificate Transparency logs (crt.sh)</p>
            </div>
            <form onSubmit={handleSubmit} className="w-full max-w-2xl">
              <div className="flex gap-3">
                <div className="flex-1 relative">
                  <div className="absolute left-4 top-1/2 -translate-y-1/2 text-gray-500">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <circle cx="11" cy="11" r="8" /><path d="m21 21-4.35-4.35" />
                    </svg>
                  </div>
                  <input type="text" value={domain} onChange={(e) => setDomain(e.target.value)}
                    placeholder="Enter domain (e.g., example.com)"
                    className="w-full pl-12 pr-4 py-4 bg-gray-800 border border-gray-700 rounded-xl text-white placeholder-gray-500 focus:outline-none focus:border-green-500 focus:ring-1 focus:ring-green-500 transition-all text-lg"
                  />
                </div>
                <button type="submit"
                  className="px-8 py-4 bg-green-600 hover:bg-green-700 text-white font-semibold rounded-xl transition-all hover:shadow-lg hover:shadow-green-600/25 active:scale-95">
                  Discover
                </button>
              </div>
            </form>
            <div className="mt-12 grid grid-cols-3 gap-8 text-center text-gray-400">
              <div><div className="text-3xl font-bold text-green-400">crt.sh</div><div className="text-sm mt-1">Certificate Transparency</div></div>
              <div><div className="text-3xl font-bold text-blue-400">Live</div><div className="text-sm mt-1">HTTP/HTTPS Check</div></div>
              <div><div className="text-3xl font-bold text-purple-400">Scan</div><div className="text-sm mt-1">Direct to VulnScan</div></div>
            </div>
          </div>
        )}

        {/* Loading */}
        {state === 'loading' && (
          <div className="text-center py-24">
            <div className="inline-block animate-spin rounded-full h-12 w-12 border-b-2 border-green-500 mb-6"></div>
            <p className="text-gray-400 text-lg">Discovering subdomains via Certificate Transparency...</p>
            <p className="text-gray-600 text-sm mt-2">Domain: {normalizeDomain(domain)}</p>
          </div>
        )}

        {/* Error */}
        {state === 'error' && (
          <div className="max-w-2xl mx-auto mt-12">
            <div className="bg-red-900/20 border border-red-800 rounded-xl p-6 text-center">
              <div className="text-red-400 text-lg font-semibold mb-2">Error</div>
              <p className="text-red-300">{errorMsg}</p>
              <button onClick={reset} className="mt-4 px-6 py-2 bg-red-600 hover:bg-red-700 rounded-lg transition-colors">Try Again</button>
            </div>
          </div>
        )}

        {/* Results */}
        {state === 'results' && subdomains && (
          <div>
            <div className="mb-6 flex items-center gap-3 flex-wrap">
              <span className="text-sm text-gray-400">Domain:</span>
              <span className="px-3 py-1 bg-green-900/30 border border-green-800 rounded-full text-green-300 text-sm font-mono">{subdomains.domain}</span>
              <button onClick={reset} className="ml-auto px-4 py-2 text-sm bg-gray-800 hover:bg-gray-700 rounded-lg transition-colors">New Search</button>
            </div>

            {/* Stats */}
            <div className="grid grid-cols-3 gap-4 mb-6">
              <div className="bg-gray-900/50 border border-gray-800 rounded-xl p-4 text-center">
                <div className="text-2xl font-bold text-white">{subdomains.total_found}</div>
                <div className="text-sm text-gray-400">Total Found</div>
              </div>
              <div className="bg-gray-900/50 border border-green-900 rounded-xl p-4 text-center">
                <div className="text-2xl font-bold text-green-400">{subdomains.live_count}</div>
                <div className="text-sm text-gray-400">Live</div>
              </div>
              <div className="bg-gray-900/50 border border-gray-800 rounded-xl p-4 text-center">
                <div className="text-2xl font-bold text-gray-400">{subdomains.total_found - subdomains.live_count}</div>
                <div className="text-sm text-gray-400">Offline / Unreachable</div>
              </div>
            </div>

            {/* Subdomain List */}
            <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
              <div className="p-4 border-b border-gray-800 flex items-center justify-between">
                <h3 className="text-white font-semibold">Subdomains</h3>
                <span className="text-sm text-gray-400">{subdomains.total_found} results</span>
              </div>
              <div className="divide-y divide-gray-800/50 max-h-[60vh] overflow-y-auto">
                {(subdomains.subdomains || []).map((s, i) => (
                  <div key={i} className="p-3 px-4 flex items-center gap-3 hover:bg-gray-800/50 transition-colors">
                    <span className={`w-2.5 h-2.5 rounded-full flex-shrink-0 ${s.live ? 'bg-green-400' : 'bg-gray-600'}`} />
                    <span className="text-white font-mono text-sm flex-1">{s.subdomain}</span>
                    {s.live ? (
                      <>
                        <span className="text-xs text-gray-400 bg-gray-800 px-2 py-0.5 rounded">HTTP {s.status}</span>
                        <Link href={`/scan?url=https://${s.subdomain}`}
                          className="px-3 py-1.5 bg-blue-900/30 border border-blue-800 text-blue-400 rounded-lg text-xs hover:bg-blue-900/50 transition-colors font-medium">
                          🔍 Scan This
                        </Link>
                      </>
                    ) : (
                      <span className="text-xs text-gray-600">offline</span>
                    )}
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}
      </div>
    </main>
  );
}
