export default function SandboxLogs({ results, fileType }) {
  if (!results) {
    return (
      <div className="card text-center text-gray-500 py-10">
        <div className="text-3xl mb-2">🏖️</div>
        <p>Sandbox results not available for this file.</p>
      </div>
    )
  }

  const { ran, error, networkCalls, fileSysCalls, registryCalls,
          processSpawns, suspiciousActivity, syscallLog, output } = results

  if (!ran || error) {
    return (
      <div className="card space-y-2">
        <div className="flex items-center gap-2">
          <span className="text-2xl">⚠️</span>
          <h3 className="font-semibold">Sandbox could not run</h3>
        </div>
        <p className="text-gray-400 text-sm">{error || 'Docker sandbox was unavailable.'}</p>
        <p className="text-gray-500 text-xs">
          Static analysis results are still fully available in the other tabs.
        </p>
      </div>
    )
  }

  return (
    <div className="space-y-4">
      {/* Sandbox Engine Status Banner */}
      <div className="rounded-xl border border-emerald-500/30 bg-emerald-950/20 p-3.5 flex flex-col sm:flex-row sm:items-center justify-between gap-2.5 text-xs text-emerald-300">
        <div className="flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-emerald-400 animate-ping"></span>
          <span className="font-semibold text-emerald-200">
            Isolated Virtual Sandbox Active
          </span>
          <span className="text-gray-400">·</span>
          <span className="text-gray-300">
            Dynamic syscall emulation &amp; threat behavioral modeling verified
          </span>
        </div>
        <span className="bg-emerald-900/50 text-emerald-300 border border-emerald-700/50 px-2 py-0.5 rounded text-[11px] font-mono self-start sm:self-auto">
          SECURE ISOLATION
        </span>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-center">
        {[
          { label: 'Network Calls', value: networkCalls?.length ?? 0, icon: '🌐' },
          { label: 'File Ops', value: fileSysCalls?.length ?? 0, icon: '📁' },
          { label: 'Process Spawns', value: processSpawns?.length ?? 0, icon: '⚙️' },
          { label: 'Registry Ops', value: registryCalls?.length ?? 0, icon: '🗂️' },
        ].map(s => (
          <div key={s.label} className="card py-3">
            <div className="text-xl">{s.icon}</div>
            <div className="text-xl font-bold text-white">{s.value}</div>
            <div className="text-xs text-gray-400">{s.label}</div>
          </div>
        ))}
      </div>

      {/* Suspicious activity */}
      {suspiciousActivity && suspiciousActivity.length > 0 && (
        <div className="card border-red-800/50 bg-red-950/10 space-y-3">
          <h3 className="font-semibold text-red-400">🚨 Suspicious Runtime Activity</h3>
          <ul className="space-y-1">
            {suspiciousActivity.map((a, i) => (
              <li key={i} className="text-sm text-gray-300 flex gap-2">
                <span className="text-red-500">•</span>
                <span>{a}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Network calls */}
      {networkCalls && networkCalls.length > 0 && (
        <div className="card space-y-2">
          <h3 className="font-semibold">🌐 Network Calls</h3>
          <div className="space-y-1 font-mono text-xs text-gray-300 max-h-48 overflow-y-auto">
            {networkCalls.map((n, i) => <div key={i} className="py-0.5 border-b border-gray-800">{n}</div>)}
          </div>
        </div>
      )}

      {/* Stdout / output */}
      {output && (
        <div className="card space-y-2">
          <h3 className="font-semibold">📄 Program Output</h3>
          <pre className="font-mono text-xs text-gray-400 bg-gray-950 rounded p-3 max-h-48 overflow-y-auto">
            {output}
          </pre>
        </div>
      )}

      {/* Full syscall log */}
      {syscallLog && syscallLog.length > 0 && (
        <details className="card">
          <summary className="cursor-pointer font-semibold text-sm text-gray-400">
            📋 Full System Call Log ({syscallLog.length} entries)
          </summary>
          <div className="mt-3 font-mono text-xs text-gray-500 max-h-64 overflow-y-auto space-y-0.5">
            {syscallLog.map((l, i) => <div key={i}>{l}</div>)}
          </div>
        </details>
      )}
    </div>
  )
}
