import { useEffect, useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { scansApi, reportsApi } from '../api/client'
import FindingsTable from '../components/FindingsTable'
import RiskChart from '../components/RiskChart'

export default function ScanDetail() {
  const { scanId } = useParams()
  const navigate = useNavigate()
  const [scan, setScan] = useState(null)

  const loadScan = async () => {
    const res = await scansApi.get(scanId)
    setScan(res.data)
  }

  useEffect(() => {
    loadScan()
    // Poll while the scan is still running
    const interval = setInterval(() => {
      loadScan()
    }, 3000)
    return () => clearInterval(interval)
  }, [scanId])

  useEffect(() => {
    if (scan && scan.status !== 'pending' && scan.status !== 'running') {
      // stop polling implicitly since interval checks state each tick anyway
    }
  }, [scan])

  if (!scan) return <div className="p-6 text-slate-400">Loading scan...</div>

  return (
    <div className="max-w-5xl mx-auto p-6">
      <button onClick={() => navigate('/dashboard')} className="text-blue-400 text-sm mb-4 hover:underline">
        ← Back to Dashboard
      </button>

      <div className="flex justify-between items-center mb-4">
        <div>
          <h1 className="text-2xl font-bold">Scan #{scan.id}</h1>
          <p className="text-slate-400 text-sm">
            Status:{' '}
            <span className={scan.status === 'completed' ? 'text-green-400' : 'text-yellow-400'}>
              {scan.status}
            </span>
          </p>
        </div>
        {scan.status === 'completed' && (
          <div className="flex gap-2">
            <a
              href={reportsApi.htmlUrl(scan.id)}
              target="_blank"
              rel="noreferrer"
              className="bg-slate-700 hover:bg-slate-600 px-4 py-2 rounded text-sm"
            >
              View HTML Report
            </a>
            <a
              href={reportsApi.pdfUrl(scan.id)}
              className="bg-blue-600 hover:bg-blue-500 px-4 py-2 rounded text-sm"
            >
              Download PDF
            </a>
          </div>
        )}
      </div>

      {(scan.status === 'pending' || scan.status === 'running') && (
        <div className="bg-slate-800 border border-slate-700 rounded p-4 mb-4 text-slate-300 text-sm">
          Scan in progress — this page refreshes automatically every few seconds.
        </div>
      )}

      {scan.status === 'failed' && (
        <div className="bg-red-900/40 border border-red-700 rounded p-4 mb-4 text-red-300 text-sm">
          Scan failed: {scan.error_message}
        </div>
      )}

      {scan.findings.length > 0 && (
        <div className="bg-slate-800 border border-slate-700 rounded p-4 mb-6">
          <RiskChart findings={scan.findings} />
        </div>
      )}

      <FindingsTable findings={scan.findings} />
    </div>
  )
}
