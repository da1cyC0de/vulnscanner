'use client';

import { useState } from 'react';

const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const severityBadge = {
  critical: 'severity-critical',
  high: 'severity-high',
  medium: 'severity-medium',
  low: 'severity-low',
  info: 'severity-info',
};

export default function ResultsTable({ results, onSelectVuln, scanning }) {
  const [filter, setFilter] = useState('all');
  const [search, setSearch] = useState('');

  const filtered = results
    .filter((r) => {
      if (filter !== 'all' && (r.severity || '').toLowerCase() !== filter) return false;
      const name = (r.title || r.name || '').toLowerCase();
      const desc = (r.description || '').toLowerCase();
      if (search && !name.includes(search.toLowerCase()) && !desc.includes(search.toLowerCase())) return false;
      return true;
    })
    .sort((a, b) => {
      const aOrd = severityOrder[(a.severity || 'info').toLowerCase()] ?? 5;
      const bOrd = severityOrder[(b.severity || 'info').toLowerCase()] ?? 5;
      return aOrd - bOrd;
    });

  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
      {/* Header */}
      <div className="p-4 border-b border-gray-800 flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <h3 className="text-white font-semibold">
            Vulnerabilities Found
          </h3>
          <span className="px-2 py-0.5 bg-gray-800 rounded-full text-sm text-gray-400">
            {filtered.length}
          </span>
          {scanning && (
            <span className="px-2 py-0.5 bg-blue-900/30 border border-blue-800 rounded-full text-xs text-blue-400 animate-pulse">
              Live
            </span>
          )}
        </div>

        <div className="flex items-center gap-3">
          {/* Search */}
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search..."
            className="px-3 py-1.5 bg-gray-800 border border-gray-700 rounded-lg text-sm text-white placeholder-gray-500 focus:outline-none focus:border-blue-500 w-48"
          />
          {/* Filter */}
          <select
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            className="px-3 py-1.5 bg-gray-800 border border-gray-700 rounded-lg text-sm text-white focus:outline-none focus:border-blue-500"
          >
            <option value="all">All Severity</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
            <option value="info">Info</option>
          </select>
        </div>
      </div>

      {/* Table */}
      {filtered.length === 0 ? (
        <div className="p-12 text-center text-gray-500">
          {scanning ? 'Scanning in progress... vulnerabilities will appear here' : 'No vulnerabilities found'}
        </div>
      ) : (
        <div className="divide-y divide-gray-800/50">
          {filtered.map((vuln, idx) => (
            <div
              key={idx}
              className="p-4 hover:bg-gray-800/50 transition-colors cursor-pointer flex items-start gap-4"
              onClick={() => onSelectVuln(vuln)}
            >
              {/* Severity Badge */}
              <span
                className={`px-2.5 py-1 rounded-md text-xs font-semibold border whitespace-nowrap ${severityBadge[(vuln.severity || 'info').toLowerCase()] || 'severity-info'}`}
              >
                {(vuln.severity || 'INFO').toUpperCase()}
              </span>

              {/* Info */}
              <div className="flex-1 min-w-0">
                <div className="text-white font-medium">{vuln.title || vuln.name}</div>
                <div className="text-sm text-gray-400 mt-1 line-clamp-2">
                  {vuln.description}
                </div>
                {vuln.url && (
                  <div className="text-xs text-gray-600 mt-1 font-mono truncate">
                    {vuln.url}
                  </div>
                )}
              </div>

              {/* Fix button */}
              <button
                className="px-3 py-1.5 bg-emerald-900/30 border border-emerald-800 text-emerald-400 rounded-lg text-xs font-medium hover:bg-emerald-900/50 transition-colors whitespace-nowrap"
                onClick={(e) => {
                  e.stopPropagation();
                  onSelectVuln(vuln);
                }}
              >
                Fix Bug
              </button>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
