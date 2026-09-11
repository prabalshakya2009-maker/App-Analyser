export default function AnalysisProgress({ progress }) {
  const { step, percent, logs } = progress

  return (
    <div className="max-w-lg mx-auto space-y-8 text-center">
      {/* Animated icon */}
      <div className="text-6xl animate-pulse">🔬</div>

      <div className="space-y-2">
        <h3 className="text-xl font-semibold text-white">Analyzing your app…</h3>
        <p className="text-gray-400 text-sm">{step}</p>
      </div>

      {/* Progress bar */}
      <div className="w-full bg-gray-800 rounded-full h-3 overflow-hidden">
        <div
          className="h-full bg-gradient-to-r from-brand-500 to-purple-500 rounded-full transition-all duration-500"
          style={{ width: `${percent}%` }}
        />
      </div>
      <p className="text-gray-500 text-sm">{percent}%</p>

      {/* Live logs */}
      {logs && logs.length > 0 && (
        <div className="card text-left font-mono text-xs text-gray-400 space-y-1 max-h-48 overflow-y-auto">
          {logs.map((log, i) => (
            <div key={i} className="flex gap-2">
              <span className="text-gray-600">{String(i + 1).padStart(2, '0')}</span>
              <span>{log}</span>
            </div>
          ))}
        </div>
      )}

      <p className="text-gray-600 text-xs">This may take 1–3 minutes for sandbox analysis</p>
    </div>
  )
}
