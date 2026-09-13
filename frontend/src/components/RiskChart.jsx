import { PieChart, Pie, Cell, Tooltip, Legend, ResponsiveContainer } from 'recharts'

const COLORS = {
  Critical: '#7f1d1d',
  High: '#dc2626',
  Medium: '#f59e0b',
  Low: '#22c55e',
  Informational: '#94a3b8',
}

export default function RiskChart({ findings }) {
  const counts = { Critical: 0, High: 0, Medium: 0, Low: 0, Informational: 0 }
  findings.forEach((f) => {
    if (counts[f.severity] !== undefined) counts[f.severity] += 1
  })

  const data = Object.entries(counts)
    .filter(([, value]) => value > 0)
    .map(([name, value]) => ({ name, value }))

  if (data.length === 0) {
    return <div className="text-slate-500 text-sm">No findings to visualize yet.</div>
  }

  return (
    <ResponsiveContainer width="100%" height={260}>
      <PieChart>
        <Pie
          data={data}
          dataKey="value"
          nameKey="name"
          cx="50%"
          cy="50%"
          outerRadius={90}
          label={(entry) => `${entry.name}: ${entry.value}`}
        >
          {data.map((entry) => (
            <Cell key={entry.name} fill={COLORS[entry.name]} />
          ))}
        </Pie>
        <Tooltip />
        <Legend />
      </PieChart>
    </ResponsiveContainer>
  )
}
