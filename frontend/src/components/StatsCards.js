'use client';

export default function StatsCards({ results }) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  results.forEach((r) => {
    const sev = (r.severity || '').toLowerCase();
    if (counts[sev] !== undefined) counts[sev]++;
  });

  const cards = [
    { label: 'Critical', count: counts.critical, color: 'text-red-400', bg: 'bg-red-900/20', border: 'border-red-800/50', icon: '🔴' },
    { label: 'High', count: counts.high, color: 'text-orange-400', bg: 'bg-orange-900/20', border: 'border-orange-800/50', icon: '🟠' },
    { label: 'Medium', count: counts.medium, color: 'text-yellow-400', bg: 'bg-yellow-900/20', border: 'border-yellow-800/50', icon: '🟡' },
    { label: 'Low', count: counts.low, color: 'text-green-400', bg: 'bg-green-900/20', border: 'border-green-800/50', icon: '🟢' },
    { label: 'Info', count: counts.info, color: 'text-blue-400', bg: 'bg-blue-900/20', border: 'border-blue-800/50', icon: '🔵' },
  ];

  return (
    <div className="grid grid-cols-5 gap-4 mb-6">
      {cards.map((c) => (
        <div key={c.label} className={`p-4 rounded-xl border ${c.bg} ${c.border}`}>
          <div className="flex items-center justify-between">
            <span className="text-2xl">{c.icon}</span>
            <span className={`text-3xl font-bold ${c.color}`}>{c.count}</span>
          </div>
          <div className="text-sm text-gray-400 mt-1">{c.label}</div>
        </div>
      ))}
    </div>
  );
}
