export default function ScoreCard({ label, value, color, icon }) {
  const colorMap = {
    red:    'border-red-800/50 bg-red-950/30 text-red-400',
    orange: 'border-orange-800/50 bg-orange-950/30 text-orange-400',
    yellow: 'border-yellow-800/50 bg-yellow-950/30 text-yellow-400',
    green:  'border-green-800/50 bg-green-950/30 text-green-400',
    blue:   'border-blue-800/50 bg-blue-950/30 text-blue-400',
  }

  return (
    <div className={`border rounded-xl p-4 text-center ${colorMap[color] || 'border-gray-700 bg-gray-900'}`}>
      <div className="text-2xl mb-1">{icon}</div>
      <div className="text-2xl font-bold">{value}</div>
      <div className="text-xs text-gray-400 mt-1">{label}</div>
    </div>
  )
}
