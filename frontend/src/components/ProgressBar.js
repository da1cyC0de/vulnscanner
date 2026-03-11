'use client';

import { useState, useEffect } from 'react';

const INIT_STEPS = [
  'Connecting to scanner engine...',
  'Resolving target hostname...',
  'Checking target availability...',
  'Initializing 29 scanner modules...',
  'Starting vulnerability scan...',
];

export default function ProgressBar({ progress, scanning }) {
  const [initStep, setInitStep] = useState(0);

  useEffect(() => {
    if (!progress && scanning) {
      const interval = setInterval(() => {
        setInitStep((prev) => (prev < INIT_STEPS.length - 1 ? prev + 1 : prev));
      }, 1200);
      return () => clearInterval(interval);
    }
    if (progress) setInitStep(0);
  }, [progress, scanning]);

  // Initial connecting state - shown when scan just started, no data yet
  if (!progress && scanning) {
    return (
      <div className="mb-6 p-6 bg-gray-900 border border-blue-800 rounded-xl glow-border">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-3">
            <div className="w-5 h-5 border-2 border-blue-500 border-t-transparent rounded-full animate-spin" />
            <span className="text-white font-medium">Initializing Scan...</span>
          </div>
          <span className="text-xs text-gray-500">Please wait</span>
        </div>

        {/* Init steps */}
        <div className="space-y-2 mb-4">
          {INIT_STEPS.map((step, i) => (
            <div key={i} className="flex items-center gap-2 text-sm">
              {i < initStep ? (
                <span className="text-green-400">✓</span>
              ) : i === initStep ? (
                <div className="w-3.5 h-3.5 border-2 border-blue-500 border-t-transparent rounded-full animate-spin" />
              ) : (
                <span className="text-gray-600">○</span>
              )}
              <span className={i <= initStep ? 'text-gray-300' : 'text-gray-600'}>
                {step}
              </span>
            </div>
          ))}
        </div>

        {/* Indeterminate progress bar */}
        <div className="w-full bg-gray-800 rounded-full h-2 overflow-hidden">
          <div className="h-full rounded-full bg-blue-500 animate-pulse" style={{ width: '30%' }} />
        </div>
      </div>
    );
  }

  if (!progress) return null;

  const percent = Math.round(progress.percent || 0);

  return (
    <div className={`mb-6 p-6 bg-gray-900 border rounded-xl ${scanning ? 'border-blue-800 glow-border' : 'border-gray-800'}`}>
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-3">
          {scanning && (
            <div className="w-5 h-5 border-2 border-blue-500 border-t-transparent rounded-full animate-spin" />
          )}
          {!scanning && (
            <div className="w-5 h-5 bg-green-500 rounded-full flex items-center justify-center">
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="white" strokeWidth="3">
                <polyline points="20 6 9 17 4 12" />
              </svg>
            </div>
          )}
          <span className="text-white font-medium">
            {scanning ? 'Scanning...' : 'Scan Complete'}
          </span>
        </div>
        <div className="text-sm text-gray-400">
          {progress.completed}/{progress.total} modules &bull; {Math.round(progress.elapsed || 0)}s
        </div>
      </div>

      {/* Progress bar */}
      <div className="w-full bg-gray-800 rounded-full h-3 overflow-hidden">
        <div
          className="h-full rounded-full transition-all duration-500 ease-out"
          style={{
            width: `${percent}%`,
            background: scanning
              ? 'linear-gradient(90deg, #3b82f6, #60a5fa)'
              : 'linear-gradient(90deg, #22c55e, #4ade80)',
          }}
        />
      </div>

      {/* Current module */}
      {scanning && progress.current && (
        <div className="mt-2 text-sm text-gray-500">
          Scanning: <span className="text-blue-400 font-medium">{progress.current}</span>
        </div>
      )}
    </div>
  );
}
