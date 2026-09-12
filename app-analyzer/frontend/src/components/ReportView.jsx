import { useState } from 'react'
import ScoreCard from './ScoreCard'
import FindingsList from './FindingsList'
import AiPromptBox from './AiPromptBox'
import SandboxLogs from './SandboxLogs'

const TABS = ['Overview', 'Bugs & Errors', 'Security', 'Sandbox', 'AI Prompt']

export default function ReportView({ report, onReset }) {
  const [tab, setTab] = useState('Overview')

  const {
    fileName, fileType, fileSize,
    hackabilityScore, bugCount, criticalCount,
    bugs, securityFindings, sandboxResults,
    aiSummary, improvements, fixPrompt,
    staticInfo
  } = report

  return (
    <div className="space-y-6">
      {/* Top bar */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold">Analysis Report</h2>
          <p className="text-gray-400 text-sm mt-1">
            <span className="font-mono text-gray-300">{fileName}</span>
            {' · '}
            <span className="uppercase text-xs font-semibold px-1.5 py-0.5 rounded bg-gray-800">
              {fileType}
            </span>
            {' · '}
            {(fileSize / 1024 / 1024).toFixed(2)} MB
          </p>
        </div>
        <div className="flex items-center gap-2">
          <a
            href={`/api/reports/${report.reportId || ''}/markdown`}
            target="_blank"
            rel="noreferrer"
            className="text-sm text-brand-400 hover:text-white border border-brand-800/60 bg-brand-950/40 hover:bg-brand-900/60 px-3 py-1.5 rounded-lg transition">
            📥 Export Report
          </a>
          <button onClick={onReset}
            className="text-sm text-gray-400 hover:text-white border border-gray-700 hover:border-gray-500 px-4 py-1.5 rounded-lg transition">
            ← New Analysis
          </button>
        </div>
      </div>

      {/* Score cards */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <ScoreCard label="Hackability" value={`${hackabilityScore}/10`}
          color={hackabilityScore >= 7 ? 'red' : hackabilityScore >= 4 ? 'yellow' : 'green'}
          icon="🎯" />
        <ScoreCard label="Total Issues" value={bugCount + securityFindings.length}
          color="orange" icon="🐛" />
        <ScoreCard label="Critical" value={criticalCount}
          color={criticalCount > 0 ? 'red' : 'green'} icon="🚨" />
        <ScoreCard label="Improvements" value={improvements.length}
          color="blue" icon="💡" />
      </div>

      {/* Tabs */}
      <div className="flex gap-1 border-b border-gray-800 overflow-x-auto">
        {TABS.map(t => (
          <button key={t}
            onClick={() => setTab(t)}
            className={`px-4 py-2 text-sm font-medium whitespace-nowrap transition border-b-2 -mb-px
              ${tab === t
                ? 'border-brand-500 text-brand-400'
                : 'border-transparent text-gray-500 hover:text-gray-300'}`}>
            {t}
          </button>
        ))}
      </div>

      {/* Tab content */}
      <div>
        {tab === 'Overview' && (
          <div className="space-y-5">
            <div className="card space-y-3">
              <h3 className="font-semibold text-lg">📋 AI Summary</h3>
              <p className="text-gray-300 leading-relaxed whitespace-pre-wrap">{aiSummary}</p>
            </div>

            {staticInfo && (
              <div className="card space-y-3">
                <h3 className="font-semibold text-lg">📦 File Info</h3>
                <div className="grid grid-cols-2 gap-2 text-sm">
                  {Object.entries(staticInfo).map(([k, v]) => (
                    <div key={k} className="flex gap-2">
                      <span className="text-gray-500 capitalize">{k.replace(/_/g, ' ')}:</span>
                      <span className="text-gray-300 font-mono break-all">{String(v)}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            <div className="card space-y-3">
              <h3 className="font-semibold text-lg">💡 Recommended Improvements</h3>
              <ul className="space-y-2">
                {improvements.map((imp, i) => (
                  <li key={i} className="flex gap-3 text-sm text-gray-300">
                    <span className="text-brand-400 font-bold mt-0.5">{i + 1}.</span>
                    <span>{imp}</span>
                  </li>
                ))}
              </ul>
            </div>
          </div>
        )}

        {tab === 'Bugs & Errors' && (
          <FindingsList findings={bugs} emptyText="No bugs detected" icon="🐛" />
        )}

        {tab === 'Security' && (
          <FindingsList findings={securityFindings} emptyText="No security issues detected" icon="🔒" />
        )}

        {tab === 'Sandbox' && (
          <SandboxLogs results={sandboxResults} fileType={fileType} />
        )}

        {tab === 'AI Prompt' && (
          <AiPromptBox prompt={fixPrompt} />
        )}
      </div>
    </div>
  )
}
