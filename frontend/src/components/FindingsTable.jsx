import { useState } from 'react'
import SeverityBadge from './SeverityBadge'

const SEVERITY_ORDER = ['Critical', 'High', 'Medium', 'Low', 'Informational']

export default function FindingsTable({ findings }) {
  const [filter, setFilter] = useState('All')

  const filtered = filter === 'All'
    ? findings
    : findings.filter((f) => f.severity === filter)

  const sorted = [...filtered].sort((a, b) => b.risk_score - a.risk_score)

  return (
    <div>
      <div className="flex gap-2 mb-3">
        {['All', ...SEVERITY_ORDER].map((s) => (
          <button
            key={s}
            onClick={() => setFilter(s)}
            className={`px-3 py-1 rounded text-sm border ${
              filter === s
                ? 'bg-blue-600 border-blue-600 text-white'
                : 'border-slate-600 text-slate-300 hover:bg-slate-800'
            }`}
          >
            {s}
          </button>
        ))}
      </div>

      <div className="overflow-x-auto rounded border border-slate-700">
        <table className="w-full text-sm">
          <thead className="bg-slate-800 text-slate-300">
            <tr>
              <th className="p-2 text-left">Severity</th>
              <th className="p-2 text-left">Check</th>
              <th className="p-2 text-left">Title</th>
              <th className="p-2 text-left">Component</th>
              <th className="p-2 text-left">Risk Score</th>
            </tr>
          </thead>
          <tbody>
            {sorted.length === 0 && (
              <tr>
                <td colSpan={5} className="p-4 text-center text-slate-500">
                  No findings for this filter.
                </td>
              </tr>
            )}
            {sorted.map((f) => (
              <tr key={f.id} className="border-t border-slate-700 hover:bg-slate-800/50">
                <td className="p-2"><SeverityBadge severity={f.severity} /></td>
                <td className="p-2 text-slate-400">{f.check_id}</td>
                <td className="p-2">{f.title}</td>
                <td className="p-2 text-slate-400 break-all">{f.affected_component}</td>
                <td className="p-2">{f.risk_score.toFixed(1)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
