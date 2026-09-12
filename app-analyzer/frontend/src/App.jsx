import { useState, useCallback } from 'react'
import axios from 'axios'
import UploadZone from './components/UploadZone'
import AnalysisProgress from './components/AnalysisProgress'
import ReportView from './components/ReportView'
import Header from './components/Header'
import { analyzeBinaryLocally } from './services/clientAnalyzer'

const BACKEND_URL = import.meta.env.VITE_BACKEND_URL || ''

export default function App() {
  const [stage, setStage] = useState('upload')
  const [progress, setProgress] = useState({ step: '', percent: 0, logs: [] })
  const [report, setReport] = useState(null)
  const [errorMsg, setErrorMsg] = useState('')
  const [reportId, setReportId] = useState(null)

  const handleUpload = useCallback(async (file) => {
    setStage('analyzing')
    setProgress({ step: 'Reading and inspecting artifact…', percent: 25, logs: [] })

    try {
      let reportData = null

      const isGitHubPages = typeof window !== 'undefined' && window.location.hostname.endsWith('github.io')
      const hasRemoteBackend = Boolean(BACKEND_URL && BACKEND_URL.trim() !== '')

      if (!isGitHubPages && hasRemoteBackend) {
        try {
          const formData = new FormData()
          formData.append('file', file)
          const { data } = await axios.post(`${BACKEND_URL}/api/analyze`, formData, {
            headers: { 'Content-Type': 'multipart/form-data' },
            timeout: 8000
          })
          if (data && data.report) {
            reportData = data.report
          }
        } catch {
          // fallback to client-side analyzer
        }
      }

      if (!reportData) {
        setProgress({
          step: 'Running client-side security sandbox & threat emulation…',
          percent: 65,
          logs: [
            'Executing in-browser privacy-preserving binary analysis.',
            'Simulating virtual sandbox execution & system calls.'
          ]
        })
        reportData = await analyzeBinaryLocally(file)
      }

      if (!reportData) {
        throw new Error('Unable to generate security report.')
      }

      setReportId(reportData.reportId)
      setProgress({ step: 'Complete!', percent: 100, logs: reportData.sandboxResults?.logs || [] })
      setTimeout(() => {
        setReport(reportData)
        setStage('done')
      }, 400)
    } catch (err) {
      setStage('error')
      setErrorMsg(err.response?.data?.detail || err.message)
    }
  }, [])

  const pollStatus = async (id) => {
    const steps = [
      { label: 'Static analysis…', percent: 30 },
      { label: 'Sandbox execution…', percent: 55 },
      { label: 'Security checks…', percent: 70 },
      { label: 'AI analysis with Gemini…', percent: 85 },
      { label: 'Generating report…', percent: 95 },
    ]

    return new Promise((resolve, reject) => {
      let attempt = 0
      const MAX = 120 // 2 min timeout

      const interval = setInterval(async () => {
        attempt++
        if (attempt > MAX) {
          clearInterval(interval)
          setStage('error')
          setErrorMsg('Analysis timed out. Please try again.')
          reject(new Error('timeout'))
          return
        }

        try {
          const { data } = await axios.get(`${BACKEND_URL}/api/report/${id}`)

          // Update progress based on status
          if (data.status === 'pending' || data.status === 'queued') {
            setProgress({ step: steps[0].label, percent: steps[0].percent, logs: data.logs || [] })
          } else if (data.status === 'static_done') {
            setProgress({ step: steps[1].label, percent: steps[1].percent, logs: data.logs || [] })
          } else if (data.status === 'sandbox_done') {
            setProgress({ step: steps[2].label, percent: steps[2].percent, logs: data.logs || [] })
          } else if (data.status === 'ai_running') {
            setProgress({ step: steps[3].label, percent: steps[3].percent, logs: data.logs || [] })
          } else if (data.status === 'done') {
            clearInterval(interval)
            setProgress({ step: 'Complete!', percent: 100, logs: data.logs || [] })
            setTimeout(() => {
              setReport(data.report)
              setStage('done')
            }, 600)
            resolve(data)
          } else if (data.status === 'error') {
            clearInterval(interval)
            setStage('error')
            setErrorMsg(data.error || 'Analysis failed.')
            reject(new Error(data.error))
          }
        } catch (_) {
          // ignore transient poll errors
        }
      }, 1000)
    })
  }

  const reset = () => {
    setStage('upload')
    setProgress({ step: '', percent: 0, logs: [] })
    setReport(null)
    setErrorMsg('')
    setReportId(null)
  }

  return (
    <div className="min-h-screen flex flex-col">
      <Header />

      <main className="flex-1 max-w-5xl mx-auto w-full px-4 py-10">
        {stage === 'upload' && (
          <div className="space-y-8">
            {/* Hero */}
            <div className="text-center space-y-3">
              <h2 className="text-4xl font-bold bg-gradient-to-r from-brand-500 to-purple-400 bg-clip-text text-transparent">
                Analyze Your App
              </h2>
              <p className="text-gray-400 max-w-xl mx-auto">
                Upload your <span className="text-white font-medium">.apk</span> or{' '}
                <span className="text-white font-medium">.exe</span> file. We'll run static &amp;
                dynamic sandbox analysis, detect vulnerabilities, and generate a full AI report.
              </p>
            </div>

            <UploadZone onUpload={handleUpload} />

            {/* Feature chips */}
            <div className="flex flex-wrap justify-center gap-3 text-sm text-gray-400">
              {['🔍 Static Analysis', '📦 Sandbox Execution', '🔒 Security Scan',
                '🤖 Gemini AI Report', '💡 Fix Prompts', '📊 Hackability Score'].map(f => (
                <span key={f} className="bg-gray-800 px-3 py-1.5 rounded-full border border-gray-700">{f}</span>
              ))}
            </div>

            <p className="text-center text-xs text-gray-600">
              By uploading, you confirm you own this file or have permission to analyze it.
              Files are deleted after 24 hours.
            </p>
          </div>
        )}

        {stage === 'analyzing' && (
          <AnalysisProgress progress={progress} />
        )}

        {stage === 'done' && report && (
          <ReportView report={report} onReset={reset} />
        )}

        {stage === 'error' && (
          <div className="card text-center space-y-4 max-w-md mx-auto">
            <div className="text-4xl">⚠️</div>
            <h3 className="text-xl font-semibold text-red-400">Analysis Failed</h3>
            <p className="text-gray-400 text-sm">{errorMsg}</p>
            <button onClick={reset}
              className="bg-brand-600 hover:bg-brand-700 text-white px-6 py-2 rounded-lg transition">
              Try Again
            </button>
          </div>
        )}
      </main>
    </div>
  )
}
