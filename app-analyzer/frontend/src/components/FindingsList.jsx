import { useState } from 'react'

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }

export default function FindingsList({ findings, emptyText, icon }) {
  const [expanded, setExpanded] = useState(null)

  if (!findings || findings.length === 0) {
    return (
      <div className="card text-center text-gray-500 py-10">
        <div className="text-3xl mb-2">✅</div>
        <p>{emptyText}</p>
      </div>
    )
  }

  const sorted = [...findings].sort(
    (a, b) => (SEVERITY_ORDER[a.severity] ?? 5) - (SEVERITY_ORDER[b.severity] ?? 5)
  )

  return (
    <div className="space-y-3">
      <p className="text-sm text-gray-400">{findings.length} finding{findings.length !== 1 ? 's' : ''} found</p>
      {sorted.map((f, i) => (
        <div key={i}
          className="card hover:border-gray-700 transition cursor-pointer"
          onClick={() => setExpanded(expanded === i ? null : i)}>
          <div className="flex items-start gap-3">
            <span className="text-xl mt-0.5">{icon}</span>
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 flex-wrap">
                <span className={`badge-${f.severity}`}>{f.severity?.toUpperCase()}</span>
                <span className="font-medium text-sm text-gray-200">{f.title}</span>
              </div>
              <p className="text-gray-400 text-xs mt-1 truncate">{f.description}</p>
            </div>
            <span className="text-gray-600 text-xs mt-1">{expanded === i ? '▲' : '▼'}</span>
          </div>

          {expanded === i && (
            <div className="mt-4 border-t border-gray-800 pt-4 space-y-3">
              <p className="text-gray-300 text-sm">{f.description}</p>
              {f.location && (
                <p className="text-xs text-gray-500">
                  <span className="text-gray-400 font-medium">Location: </span>
                  <code className="font-mono">{f.location}</code>
                </p>
              )}
              {f.cve && (
                <p className="text-xs">
                  <span className="text-gray-400 font-medium">CVE: </span>
                  <a href={`https://nvd.nist.gov/vuln/detail/${f.cve}`}
                    target="_blank" rel="noopener noreferrer"
                    className="text-blue-400 hover:underline font-mono">
                    {f.cve}
                  </a>
                </p>
              )}
              {f.recommendation && (
                <div className="bg-gray-800/50 rounded-lg p-3 text-sm">
                  <p className="text-gray-400 font-medium text-xs mb-1">💡 Recommendation</p>
                  <p className="text-gray-300">{f.recommendation}</p>
                </div>
              )}
            </div>
          )}
        </div>
      ))}
    </div>
  )
}
