import { useCallback } from 'react'
import { useDropzone } from 'react-dropzone'

const MAX_SIZE = 100 * 1024 * 1024 // 100 MB

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
    <div className="space-y-3">
      <div
        {...getRootProps()}
        className={`border-2 border-dashed rounded-2xl p-14 text-center cursor-pointer transition-all
          ${isDragActive
            ? 'border-brand-500 bg-brand-50/5 scale-[1.01]'
            : 'border-gray-700 hover:border-gray-500 hover:bg-gray-900/50'}`}
      >
        <input {...getInputProps()} />
        <div className="space-y-4">
          <div className="text-5xl">📂</div>
          {isDragActive ? (
            <p className="text-brand-400 font-medium text-lg">Drop it here!</p>
          ) : (
            <>
              <p className="text-gray-300 text-lg font-medium">
                Drag &amp; drop your file here
              </p>
              <p className="text-gray-500 text-sm">or click to browse</p>
              <div className="flex justify-center gap-3">
                <span className="bg-green-900/30 text-green-400 border border-green-800/50 px-3 py-1 rounded-full text-sm font-mono">
                  .apk
                </span>
                <span className="bg-blue-900/30 text-blue-400 border border-blue-800/50 px-3 py-1 rounded-full text-sm font-mono">
                  .exe
                </span>
              </div>
              <p className="text-gray-600 text-xs">Max file size: 100 MB</p>
            </>
          )}
        </div>
      </div>

      {error && (
        <p className="text-red-400 text-sm text-center">{error}</p>
      )}
    </div>
  )
}
