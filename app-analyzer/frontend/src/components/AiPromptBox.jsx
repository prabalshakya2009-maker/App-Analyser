import { useState } from 'react'

export default function AiPromptBox({ prompt }) {
  const [copied, setCopied] = useState(false)

  const copy = () => {
    navigator.clipboard.writeText(prompt)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <div className="space-y-4">
      <div className="card space-y-3">
        <div className="flex items-center justify-between">
          <h3 className="font-semibold text-lg">🤖 AI Fix Prompt</h3>
          <button onClick={copy}
            className="text-xs bg-brand-600 hover:bg-brand-700 text-white px-3 py-1.5 rounded-lg transition">
            {copied ? '✓ Copied!' : 'Copy Prompt'}
          </button>
        </div>
        <p className="text-gray-400 text-sm">
          Paste this prompt into any AI coding assistant (Gemini, ChatGPT, Copilot, etc.) to get
          targeted code fixes for all detected issues.
        </p>
        <div className="bg-gray-950 border border-gray-800 rounded-lg p-4 font-mono text-sm
          text-gray-300 whitespace-pre-wrap leading-relaxed max-h-[500px] overflow-y-auto">
          {prompt}
        </div>
      </div>
    </div>
  )
}
