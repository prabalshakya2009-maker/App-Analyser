import { useCallback } from 'react'
import { useDropzone } from 'react-dropzone'

const MAX_SIZE = 1024 * 1024 * 1024 // 1 GB (1024 MB)

export default function UploadZone({ onUpload }) {
  const onDrop = useCallback((accepted) => {
    if (accepted.length > 0) onUpload(accepted[0])
  }, [onUpload])

  const { getRootProps, getInputProps, isDragActive, fileRejections } = useDropzone({
    onDrop,
    accept: {
      'application/vnd.android.package-archive': ['.apk'],
      'application/x-msdownload': ['.exe'],
      'application/octet-stream': ['.apk', '.exe'],
    },
    maxFiles: 1,
    maxSize: MAX_SIZE,
  })

  const error = fileRejections[0]?.errors[0]?.message

  return (
    <div className="space-y-4">
      <div
        {...getRootProps()}
        className={`border-2 border-dashed rounded-2xl p-12 text-center cursor-pointer transition-all
          ${isDragActive
            ? 'border-brand-500 bg-brand-50/5 scale-[1.01]'
            : 'border-gray-700 hover:border-gray-500 hover:bg-gray-900/50'}`}
      >
        <input {...getInputProps()} />
        <div className="space-y-4">
          <div className="text-5xl">📂</div>
          {isDragActive ? (
            <p className="text-brand-400 font-medium text-lg">Drop it here to analyze!</p>
          ) : (
            <>
              <p className="text-gray-200 text-xl font-semibold">
                Drag &amp; drop your application binary here
              </p>
              <p className="text-gray-400 text-sm">or click to browse from your device</p>
              <div className="flex justify-center gap-3 pt-1">
                <span className="bg-emerald-950/40 text-emerald-400 border border-emerald-800/60 px-3.5 py-1 rounded-full text-xs font-mono font-medium">
                  .apk (Android Package)
                </span>
                <span className="bg-cyan-950/40 text-cyan-400 border border-cyan-800/60 px-3.5 py-1 rounded-full text-xs font-mono font-medium">
                  .exe (Windows PE32/PE64)
                </span>
              </div>
              <p className="text-gray-400 text-xs font-medium">
                Max file size: <span className="text-gray-200 font-bold">1 GB</span>
              </p>
            </>
          )}
        </div>
      </div>

      {/* Trust & Zero-Knowledge Privacy Guarantee Card */}
      <div className="rounded-xl border border-gray-800/80 bg-gray-950/60 p-4 flex flex-col sm:flex-row items-center justify-between gap-3 text-xs text-gray-400">
        <div className="flex items-center gap-2">
          <span className="text-base text-emerald-400">🔒</span>
          <span>
            <strong className="text-gray-200">100% Client-Side Privacy:</strong> Binaries are analyzed locally in your browser memory via Web Crypto. Zero data leaves your machine.
          </span>
        </div>
        <div className="flex items-center gap-3 flex-shrink-0 text-gray-500 font-mono text-[11px]">
          <span>OWASP MASVS</span>
          <span>•</span>
          <span>NIST SP 800-218</span>
        </div>
      </div>

      {error && (
        <p className="text-red-400 text-sm text-center">{error}</p>
      )}
    </div>
  )
}
