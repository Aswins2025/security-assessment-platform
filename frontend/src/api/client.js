import axios from 'axios'

const API_BASE_URL = 'http://localhost:8000'

const client = axios.create({
  baseURL: API_BASE_URL,
})

// Attach the JWT token (if present) to every request
client.interceptors.request.use((config) => {
  const token = localStorage.getItem('access_token')
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

export const authApi = {
  register: (data) => client.post('/auth/register', data),
  login: (email, password) => {
    const form = new URLSearchParams()
    form.append('username', email)
    form.append('password', password)
    return client.post('/auth/login', form, {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    })
  },
}

export const projectsApi = {
  list: () => client.get('/projects'),
  create: (data) => client.post('/projects', data),
}

export const scansApi = {
  create: (projectId, categories = []) =>
    client.post('/scans', { project_id: projectId, categories }),
  get: (scanId) => client.get(`/scans/${scanId}`),
  listForProject: (projectId) => client.get(`/projects/${projectId}/scans`),
}

export const reportsApi = {
  htmlUrl: (scanId) => `${API_BASE_URL}/reports/${scanId}/html`,
  pdfUrl: (scanId) => `${API_BASE_URL}/reports/${scanId}/pdf`,
}

export default client
