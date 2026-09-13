const SEVERITY_STYLES = {
  Critical: 'bg-critical text-white',
  High: 'bg-high text-white',
  Medium: 'bg-medium text-black',
  Low: 'bg-low text-black',
  Informational: 'bg-info text-black',
}

export default function SeverityBadge({ severity }) {
  const style = SEVERITY_STYLES[severity] || 'bg-slate-500 text-white'
  return (
    <span className={`px-2 py-1 rounded text-xs font-semibold ${style}`}>
      {severity}
    </span>
  )
}
