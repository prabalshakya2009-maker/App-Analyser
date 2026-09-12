export default function Header() {
  return (
    <header className="border-b border-gray-800 bg-gray-950/80 backdrop-blur sticky top-0 z-10">
      <div className="max-w-5xl mx-auto px-4 h-14 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <span className="text-2xl">🛡️</span>
          <span className="font-bold text-lg tracking-tight">AppGuard</span>
          <span className="text-xs bg-brand-600 text-white px-2 py-0.5 rounded ml-1">BETA</span>
        </div>
        <div className="flex items-center gap-4 text-sm text-gray-400">
          <a href="./AppGuard_Security_Guide.pdf" target="_blank" rel="noopener noreferrer"
            className="text-xs font-medium text-brand-400 hover:text-white border border-brand-800/60 bg-brand-950/40 hover:bg-brand-900/60 px-2.5 py-1 rounded-lg transition flex items-center gap-1.5">
            <span>📄</span>
            <span>Security Guide (PDF)</span>
          </a>
          <a href="https://github.com/prabalshakya2009-maker/App-Analyser" target="_blank" rel="noopener noreferrer"
            className="hover:text-white transition flex items-center gap-1">
            <span>GitHub</span>
          </a>
        </div>
      </div>
    </header>
  )
}
