import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { projectsApi, scansApi } from '../api/client'

const CATEGORIES = [
  'auth_session', 'access_control', 'input_validation',
  'api_security', 'client_side', 'transport_security', 'data_storage',
]

export default function Dashboard() {
  const [projects, setProjects] = useState([])
  const [showForm, setShowForm] = useState(false)
  const [form, setForm] = useState({
    name: '', target_base_url: '', description: '',
    is_authorized: false, authorization_note: '',
  })
  const [scansByProject, setScansByProject] = useState({})
  const navigate = useNavigate()

  const loadProjects = async () => {
    const res = await projectsApi.list()
    setProjects(res.data)
    res.data.forEach(async (p) => {
      const scanRes = await scansApi.listForProject(p.id)
      setScansByProject((prev) => ({ ...prev, [p.id]: scanRes.data }))
    })
  }

  useEffect(() => {
    loadProjects()
  }, [])

  const handleCreateProject = async (e) => {
    e.preventDefault()
    await projectsApi.create(form)
    setShowForm(false)
    setForm({ name: '', target_base_url: '', description: '', is_authorized: false, authorization_note: '' })
    loadProjects()
  }

  const handleRunScan = async (projectId) => {
    const scan = await scansApi.create(projectId, [])
    navigate(`/scans/${scan.data.id}`)
  }

  const handleLogout = () => {
    localStorage.removeItem('access_token')
    navigate('/')
  }

  return (
    <div className="max-w-5xl mx-auto p-6">
      <div className="flex justify-between items-center mb-6">
        <h1 className="text-2xl font-bold">Projects</h1>
        <div className="flex gap-2">
          <button
            onClick={() => setShowForm(!showForm)}
            className="bg-blue-600 hover:bg-blue-500 px-4 py-2 rounded"
          >
            {showForm ? 'Cancel' : '+ New Project'}
          </button>
          <button onClick={handleLogout} className="text-slate-400 hover:text-white px-4 py-2">
            Log out
          </button>
        </div>
      </div>

      {showForm && (
        <form onSubmit={handleCreateProject} className="bg-slate-800 p-4 rounded mb-6 space-y-3 border border-slate-700">
          <input
            placeholder="Project name"
            required
            className="w-full p-2 rounded bg-slate-900 border border-slate-600"
            value={form.name}
            onChange={(e) => setForm({ ...form, name: e.target.value })}
          />
          <input
            placeholder="Target base URL (e.g. https://staging.example.com)"
            required
            className="w-full p-2 rounded bg-slate-900 border border-slate-600"
            value={form.target_base_url}
            onChange={(e) => setForm({ ...form, target_base_url: e.target.value })}
          />
          <textarea
            placeholder="Description"
            className="w-full p-2 rounded bg-slate-900 border border-slate-600"
            value={form.description}
            onChange={(e) => setForm({ ...form, description: e.target.value })}
          />
          <textarea
            placeholder="Authorization note (who approved testing, scope, date)"
            className="w-full p-2 rounded bg-slate-900 border border-slate-600"
            value={form.authorization_note}
            onChange={(e) => setForm({ ...form, authorization_note: e.target.value })}
          />
          <label className="flex items-center gap-2 text-sm">
            <input
              type="checkbox"
              checked={form.is_authorized}
              onChange={(e) => setForm({ ...form, is_authorized: e.target.checked })}
            />
            I confirm written authorization has been obtained to test this target.
          </label>
          <button type="submit" className="bg-green-600 hover:bg-green-500 px-4 py-2 rounded">
            Create Project
          </button>
        </form>
      )}

      <div className="space-y-4">
        {projects.map((p) => (
          <div key={p.id} className="bg-slate-800 p-4 rounded border border-slate-700">
            <div className="flex justify-between items-start">
              <div>
                <h2 className="font-semibold text-lg">{p.name}</h2>
                <p className="text-slate-400 text-sm">{p.target_base_url}</p>
                {!p.is_authorized && (
                  <p className="text-red-400 text-xs mt-1">⚠ Not marked authorized — scans are blocked.</p>
                )}
              </div>
              <button
                onClick={() => handleRunScan(p.id)}
                disabled={!p.is_authorized}
                className="bg-blue-600 hover:bg-blue-500 disabled:opacity-40 px-4 py-2 rounded text-sm"
              >
                Run Scan
              </button>
            </div>

            {scansByProject[p.id]?.length > 0 && (
              <div className="mt-3 space-y-1">
                {scansByProject[p.id].map((s) => (
                  <div
                    key={s.id}
                    onClick={() => navigate(`/scans/${s.id}`)}
                    className="flex justify-between text-sm bg-slate-900 p-2 rounded cursor-pointer hover:bg-slate-700"
                  >
                    <span>Scan #{s.id} — {s.status}</span>
                    <span className="text-slate-400">
                      {s.total_findings} findings ({s.critical}C / {s.high}H / {s.medium}M / {s.low}L)
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>
        ))}

        {projects.length === 0 && (
          <p className="text-slate-500">No projects yet. Create one to get started.</p>
        )}
      </div>
    </div>
  )
}
