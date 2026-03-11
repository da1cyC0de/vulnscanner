'use client';

import Link from 'next/link';

export default function Home() {
  const features = [
    {
      href: '/scan',
      icon: '🔍',
      title: 'Scan All',
      desc: 'Scan satu URL dengan semua 29 module scanner sekaligus.',
      badge: '180+ Checks',
      color: 'blue',
      gradient: 'from-blue-600/20 to-blue-900/10',
      border: 'border-blue-800/50 hover:border-blue-600',
    },
    {
      href: '/bulk',
      icon: '🚀',
      title: 'Bulk Scan',
      desc: 'Scan satu atau banyak URL, pilih module mana yang mau dijalankan.',
      badge: 'Multi URL + Module Select',
      color: 'purple',
      gradient: 'from-purple-600/20 to-purple-900/10',
      border: 'border-purple-800/50 hover:border-purple-600',
    },
    {
      href: '/dorking',
      icon: '🌐',
      title: 'Dorking & Subdomain',
      desc: 'Discover subdomain target via Certificate Transparency logs. Cari semua aset tersembunyi.',
      badge: 'Subdomain Discovery',
      color: 'green',
      gradient: 'from-green-600/20 to-green-900/10',
      border: 'border-green-800/50 hover:border-green-600',
    },
  ];

  return (
    <main className="min-h-screen">
      {/* Header */}
      <header className="border-b border-gray-800 bg-gray-900/50 backdrop-blur-sm sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-blue-600 flex items-center justify-center font-bold text-lg">VS</div>
            <div>
              <h1 className="text-xl font-bold text-white">VulnScanner</h1>
              <p className="text-xs text-gray-400">Web Vulnerability Scanner</p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <Link href="/scan" className="px-3 py-1.5 text-sm text-gray-400 hover:text-white rounded-lg transition-colors">Scan All</Link>
            <Link href="/bulk" className="px-3 py-1.5 text-sm text-gray-400 hover:text-white rounded-lg transition-colors">Bulk Scan</Link>
            <Link href="/dorking" className="px-3 py-1.5 text-sm text-gray-400 hover:text-white rounded-lg transition-colors">Dorking</Link>
          </div>
        </div>
      </header>

      <div className="max-w-5xl mx-auto px-4 py-16">
        {/* Hero */}
        <div className="text-center mb-16">
          <div className="text-6xl mb-4">🛡️</div>
          <h2 className="text-5xl font-bold text-white mb-4">VulnScanner</h2>
          <p className="text-xl text-gray-400 max-w-2xl mx-auto">
            All-in-one web vulnerability scanner — 180+ security checks, 29 scanner modules, AI-powered fix guides, dan export report lengkap.
          </p>
        </div>

        {/* Feature Cards */}
        <div className="grid md:grid-cols-3 gap-6 mb-16">
          {features.map((f) => (
            <Link key={f.href} href={f.href}
              className={`group block bg-gradient-to-br ${f.gradient} border ${f.border} rounded-2xl p-6 transition-all hover:scale-[1.02] hover:shadow-xl`}>
              <div className="text-4xl mb-4">{f.icon}</div>
              <h3 className="text-xl font-bold text-white mb-2 group-hover:text-blue-300 transition-colors">{f.title}</h3>
              <p className="text-gray-400 text-sm mb-4 leading-relaxed">{f.desc}</p>
              <span className="inline-block px-3 py-1 bg-gray-800/80 rounded-full text-xs text-gray-300">{f.badge}</span>
            </Link>
          ))}
        </div>

        {/* Stats */}
        <div className="grid grid-cols-4 gap-6 mb-16">
          {[
            { value: '180+', label: 'Vulnerability Checks', color: 'text-blue-400' },
            { value: '29', label: 'Scanner Modules', color: 'text-green-400' },
            { value: '4', label: 'Export Formats', color: 'text-purple-400' },
            { value: 'AI', label: 'Fix Guides', color: 'text-orange-400' },
          ].map((s, i) => (
            <div key={i} className="text-center bg-gray-900/50 border border-gray-800 rounded-xl p-5">
              <div className={`text-3xl font-bold ${s.color}`}>{s.value}</div>
              <div className="text-sm text-gray-500 mt-1">{s.label}</div>
            </div>
          ))}
        </div>

        {/* Quick Actions */}
        <div className="text-center">
          <p className="text-gray-500 text-sm mb-4">Quick Start</p>
          <div className="flex gap-4 justify-center">
            <Link href="/scan"
              className="px-8 py-3 bg-blue-600 hover:bg-blue-700 text-white font-semibold rounded-xl transition-all hover:shadow-lg hover:shadow-blue-600/25 active:scale-95">
              🔍 Start Scanning
            </Link>
            <Link href="/bulk"
              className="px-8 py-3 bg-gray-800 hover:bg-gray-700 text-white font-semibold rounded-xl transition-all border border-gray-700 hover:border-gray-600">
              🚀 Bulk Scan
            </Link>
          </div>
        </div>
      </div>

      {/* Footer */}
      <footer className="border-t border-gray-800 mt-16 py-6 text-center text-gray-600 text-sm">
        VulnScanner v1.0 — For educational purposes only
      </footer>
    </main>
  );
}
