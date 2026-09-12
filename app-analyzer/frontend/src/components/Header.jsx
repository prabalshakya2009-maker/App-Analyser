import AppGuardLogo from './AppGuardLogo'

export default function Header() {
  return (
    <header className="border-b border-gray-800 bg-gray-950/80 backdrop-blur sticky top-0 z-10">
      <div className="max-w-5xl mx-auto px-4 h-14 flex items-center justify-between">
        <div className="flex items-center gap-2.5">
          <AppGuardLogo className="w-8 h-8" />
          <span className="font-bold text-lg tracking-tight text-white">AppGuard</span>
          <span className="text-[11px] font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 px-2 py-0.5 rounded-full flex items-center gap-1.5 ml-1">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
            PRODUCTION v1.0
          </span>
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
