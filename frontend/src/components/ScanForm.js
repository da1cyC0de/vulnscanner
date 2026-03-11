'use client';

import { useState, useEffect } from 'react';

export default function ScanForm({ onSubmit, onSubdomainScan, onMassScan }) {
  const [url, setUrl] = useState('');
  const [mode, setMode] = useState('all'); // all, select, mass, subdomain
  const [modules, setModules] = useState([]);
  const [selectedModules, setSelectedModules] = useState([]);
  const [massUrls, setMassUrls] = useState('');
  const [loadingModules, setLoadingModules] = useState(false);

  useEffect(() => {
    if (mode === 'select' && modules.length === 0) {
      setLoadingModules(true);
      fetch(`${process.env.NEXT_PUBLIC_API_URL || 'http://127.0.0.1:6969'}/api/modules`)
        .then(r => r.json())
        .then(data => {
          setModules(data.modules || []);
          setLoadingModules(false);
        })
        .catch(() => setLoadingModules(false));
    }
  }, [mode, modules.length]);

  const toggleModule = (id) => {
    setSelectedModules(prev =>
      prev.includes(id) ? prev.filter(m => m !== id) : [...prev, id]
    );
  };

  const normalizeUrl = (raw) => {
    let u = raw.trim();
    if (!u) return '';
    if (!u.startsWith('http://') && !u.startsWith('https://')) u = 'https://' + u;
    return u;
  };

  const handleSubmit = (e) => {
    e.preventDefault();

    if (mode === 'mass') {
      const urls = massUrls.split('\n').map(normalizeUrl).filter(Boolean);
      if (urls.length === 0) return;
      if (onMassScan) onMassScan(urls, selectedModules.length > 0 ? selectedModules : null);
      return;
    }

    if (mode === 'subdomain') {
      const finalUrl = normalizeUrl(url);
      if (!finalUrl) return;
      if (onSubdomainScan) onSubdomainScan(finalUrl);
      return;
    }

    const finalUrl = normalizeUrl(url);
    if (!finalUrl) return;

    if (mode === 'select' && selectedModules.length > 0) {
      onSubmit(finalUrl, selectedModules);
    } else {
      onSubmit(finalUrl, null);
    }
  };

  return (
    <form onSubmit={handleSubmit} className="w-full max-w-3xl">
      {/* Mode Tabs */}
      <div className="flex gap-2 mb-4 justify-center flex-wrap">
        {[
          { id: 'all', label: 'Scan All', icon: '🔍' },
          { id: 'select', label: 'Pilih Module', icon: '🎯' },
          { id: 'mass', label: 'Mass Scan', icon: '🚀' },
          { id: 'subdomain', label: 'Subdomain', icon: '🌐' },
        ].map(tab => (
          <button
            key={tab.id}
            type="button"
            onClick={() => setMode(tab.id)}
            className={`px-4 py-2 rounded-lg text-sm font-medium transition-all ${
              mode === tab.id
                ? 'bg-blue-600 text-white shadow-lg shadow-blue-600/25'
                : 'bg-gray-800 text-gray-400 hover:bg-gray-700 hover:text-white'
            }`}
          >
            {tab.icon} {tab.label}
          </button>
        ))}
      </div>

      {/* URL Input (for all, select, subdomain) */}
      {mode !== 'mass' && (
        <div className="flex gap-3 mb-4">
          <div className="flex-1 relative">
            <div className="absolute left-4 top-1/2 -translate-y-1/2 text-gray-500">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <circle cx="12" cy="12" r="10" />
                <path d="M2 12h20M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" />
              </svg>
            </div>
            <input
              type="text"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder={mode === 'subdomain' ? 'Enter domain (e.g., example.com)' : 'Enter target URL (e.g., https://example.com)'}
              className="w-full pl-12 pr-4 py-4 bg-gray-800 border border-gray-700 rounded-xl text-white placeholder-gray-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 transition-all text-lg"
            />
          </div>
          <button
            type="submit"
            className="px-8 py-4 bg-blue-600 hover:bg-blue-700 text-white font-semibold rounded-xl transition-all hover:shadow-lg hover:shadow-blue-600/25 active:scale-95"
          >
            {mode === 'subdomain' ? 'Discover' : mode === 'select' ? 'Scan Selected' : 'Scan All'}
          </button>
        </div>
      )}

      {/* Mass Scan Input */}
      {mode === 'mass' && (
        <div className="mb-4">
          <textarea
            value={massUrls}
            onChange={(e) => setMassUrls(e.target.value)}
            placeholder="Paste URLs (one per line, max 10)&#10;https://example1.com&#10;https://example2.com&#10;https://example3.com"
            rows={5}
            className="w-full px-4 py-3 bg-gray-800 border border-gray-700 rounded-xl text-white placeholder-gray-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 transition-all font-mono text-sm"
          />
          <button
            type="submit"
            className="mt-3 w-full px-8 py-4 bg-blue-600 hover:bg-blue-700 text-white font-semibold rounded-xl transition-all hover:shadow-lg hover:shadow-blue-600/25 active:scale-95"
          >
            🚀 Mass Scan ({massUrls.split('\n').filter(l => l.trim()).length} URLs)
          </button>
        </div>
      )}

      {/* Module Selection Grid */}
      {mode === 'select' && (
        <div className="bg-gray-800/50 border border-gray-700 rounded-xl p-4">
          <div className="flex items-center justify-between mb-3">
            <span className="text-sm text-gray-400">
              Pilih module ({selectedModules.length} selected)
            </span>
            <div className="flex gap-2">
              <button type="button" onClick={() => setSelectedModules(modules.map(m => m.id))}
                className="text-xs text-blue-400 hover:text-blue-300">Select All</button>
              <button type="button" onClick={() => setSelectedModules([])}
                className="text-xs text-gray-400 hover:text-gray-300">Clear All</button>
            </div>
          </div>
          {loadingModules ? (
            <div className="text-center py-4 text-gray-500">Loading modules...</div>
          ) : (
            <div className="grid grid-cols-2 md:grid-cols-3 gap-2 max-h-60 overflow-y-auto">
              {modules.map(m => (
                <label
                  key={m.id}
                  className={`flex items-center gap-2 px-3 py-2 rounded-lg cursor-pointer text-sm transition-all ${
                    selectedModules.includes(m.id)
                      ? 'bg-blue-900/40 border border-blue-700 text-blue-300'
                      : 'bg-gray-800 border border-gray-700 text-gray-400 hover:border-gray-600'
                  }`}
                >
                  <input
                    type="checkbox"
                    checked={selectedModules.includes(m.id)}
                    onChange={() => toggleModule(m.id)}
                    className="sr-only"
                  />
                  <div className={`w-4 h-4 rounded border flex items-center justify-center text-xs ${
                    selectedModules.includes(m.id)
                      ? 'bg-blue-600 border-blue-600 text-white'
                      : 'border-gray-600'
                  }`}>
                    {selectedModules.includes(m.id) && '✓'}
                  </div>
                  {m.name}
                </label>
              ))}
            </div>
          )}
        </div>
      )}
    </form>
  );
}
