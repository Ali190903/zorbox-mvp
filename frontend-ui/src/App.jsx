import React, { useEffect, useState } from 'react'
import './App.css'

const API_BASE = import.meta.env.VITE_API_BASE || 'http://localhost:8080'
const REPORTER_BASE = import.meta.env.VITE_REPORTER_BASE || 'http://localhost:8090'

export default function App() {
  const [file, setFile] = useState(null)
  const [url, setUrl] = useState('')
  const [password, setPassword] = useState('')
  const [adapters, setAdapters] = useState('')
  const [jobId, setJobId] = useState('')
  const [status, setStatus] = useState(null)
  const [report, setReport] = useState(null)
  const [error, setError] = useState('')
  const [jobs, setJobs] = useState([])
  const [audit, setAudit] = useState([])
  const [activeTab, setActiveTab] = useState('analyze')
  const [loading, setLoading] = useState(false)

  // Auto-poll job status
  useEffect(() => {
    if (!jobId || !status || status.state === 'done' || status.state === 'failed') return

    const timer = setInterval(() => {
      refreshStatus().catch(() => {})
    }, 2000)

    return () => clearInterval(timer)
  }, [jobId, status?.state])

  async function submitAnalyze(e) {
    e.preventDefault()
    setError('')
    setLoading(true)

    const form = new FormData()
    if (file) form.append('file', file)
    if (url) form.append('url', url)
    if (password) form.append('password', password)
    if (adapters) form.append('adapters', adapters)

    try {
      const res = await fetch(`${API_BASE}/analyze`, {
        method: 'POST',
        body: form
      })
      const data = await res.json()

      if (!res.ok) {
        setError(data.detail || 'Request failed')
        return
      }

      setJobId(data.job_id)
      setStatus(null)
      setReport(null)
      setActiveTab('status')
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  async function refreshStatus() {
    if (!jobId) return

    try {
      const res = await fetch(`${API_BASE}/result/${jobId}`)
      if (res.ok) {
        const js = await res.json()
        setStatus(js)

        // Fetch report if available
        if (js?.exports?.json) {
          try {
            const r = await fetch(`${REPORTER_BASE}/exports/${jobId}/report.json`)
            if (r.ok) {
              setReport(await r.json())
            }
          } catch {}
        }
      }
    } catch {}
  }

  async function refreshJobs() {
    try {
      const r = await fetch(`${API_BASE}/jobs`)
      if (r.ok) {
        const d = await r.json()
        setJobs(d || [])
      }
    } catch {}
  }

  async function refreshAudit() {
    try {
      const r = await fetch(`${API_BASE}/audit?limit=50`)
      if (r.ok) {
        const d = await r.json()
        setAudit(d || [])
      }
    } catch {}
  }

  async function providePassword(pw) {
    try {
      const res = await fetch(`${API_BASE}/provide-password`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ job_id: jobId, password: pw })
      })
      if (res.ok) {
        setPassword('')
        refreshStatus()
      } else {
        setError('Invalid password')
      }
    } catch (err) {
      setError(err.message)
    }
  }

  async function sendFeedback(kind) {
    const comment = prompt(`Feedback (${kind}):`)
    if (!comment) return

    try {
      await fetch(`${API_BASE}/feedback`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ job_id: jobId, kind, comment })
      })
      alert('Feedback sent!')
    } catch (err) {
      alert('Failed: ' + err.message)
    }
  }

  const getRiskColor = (score) => {
    if (score < 30) return 'success'
    if (score < 70) return 'warning'
    return 'danger'
  }

  const progressPercent = {
    'queued': 10,
    'running': 40,
    'enriching': 70,
    'reporting': 90,
    'done': 100,
    'failed': 100
  }[status?.state] || 0

  return (
    <div className="app">
      {/* Header */}
      <header className="header">
        <div className="container">
          <h1>🔍 ZORBOX</h1>
          <p>Enterprise Malware Analysis Platform</p>
        </div>
      </header>

      {/* Tabs */}
      <nav className="tabs">
        <div className="container">
          <button
            className={`tab ${activeTab === 'analyze' ? 'active' : ''}`}
            onClick={() => setActiveTab('analyze')}
          >
            📤 Analyze
          </button>
          <button
            className={`tab ${activeTab === 'status' ? 'active' : ''}`}
            onClick={() => { setActiveTab('status'); refreshStatus() }}
          >
            📊 Job Status
          </button>
          <button
            className={`tab ${activeTab === 'jobs' ? 'active' : ''}`}
            onClick={() => { setActiveTab('jobs'); refreshJobs() }}
          >
            📋 All Jobs
          </button>
          <button
            className={`tab ${activeTab === 'audit' ? 'active' : ''}`}
            onClick={() => { setActiveTab('audit'); refreshAudit() }}
          >
            🔐 Audit Log
          </button>
        </div>
      </nav>

      {/* Main Content */}
      <main className="container">
        {error && (
          <div className="alert alert-error">
            <strong>Error:</strong> {error}
            <button onClick={() => setError('')} className="close">✕</button>
          </div>
        )}

        {/* Analyze Tab */}
        {activeTab === 'analyze' && (
          <div className="card">
            <h2>📤 Submit for Analysis</h2>
            <form onSubmit={submitAnalyze}>
              <div className="form-group">
                <label>File Upload</label>
                <input
                  type="file"
                  onChange={(e) => setFile(e.target.files?.[0])}
                  disabled={loading}
                />
              </div>

              <div className="form-group">
                <label>OR URL</label>
                <input
                  type="url"
                  placeholder="https://example.com/sample.bin"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  disabled={loading}
                />
              </div>

              <div className="form-group">
                <label>Password (if needed)</label>
                <input
                  type="password"
                  placeholder="Enter archive password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  disabled={loading}
                />
              </div>

              <div className="form-group">
                <label>Adapters (optional)</label>
                <input
                  type="text"
                  placeholder="strace,firejail,nsjail"
                  value={adapters}
                  onChange={(e) => setAdapters(e.target.value)}
                  disabled={loading}
                />
              </div>

              <button type="submit" className="btn btn-primary" disabled={loading || (!file && !url)}>
                {loading ? 'Analyzing...' : 'Analyze'}
              </button>
            </form>
          </div>
        )}

        {/* Job Status Tab */}
        {activeTab === 'status' && jobId && (
          <div>
            <div className="card">
              <h2>Job Status</h2>
              <p><strong>Job ID:</strong> <code>{jobId}</code></p>

              {status && (
                <>
                  <div className="status-badge" style={{ marginBottom: '20px' }}>
                    <span className={`badge badge-${
                      status.state === 'done' ? 'success' :
                      status.state === 'failed' ? 'danger' :
                      status.state === 'waiting_password' ? 'warning' :
                      'info'
                    }`}>
                      {status.state.toUpperCase()}
                    </span>
                  </div>

                  <div className="progress">
                    <div className="progress-bar" style={{ width: `${progressPercent}%` }}></div>
                  </div>

                  {/* File Info */}
                  {status.file_meta && (
                    <div className="box">
                      <h3>📄 File Information</h3>
                      <table>
                        <tbody>
                          <tr>
                            <td><strong>Name:</strong></td>
                            <td>{status.file_meta.name}</td>
                          </tr>
                          <tr>
                            <td><strong>Size:</strong></td>
                            <td>{(status.file_meta.size / 1024).toFixed(2)} KB</td>
                          </tr>
                          <tr>
                            <td><strong>MIME:</strong></td>
                            <td>{status.file_meta.mime_type}</td>
                          </tr>
                          <tr>
                            <td><strong>MD5:</strong></td>
                            <td><code>{status.file_meta.hashes?.md5}</code></td>
                          </tr>
                          <tr>
                            <td><strong>SHA256:</strong></td>
                            <td><code style={{ wordBreak: 'break-all' }}>{status.file_meta.hashes?.sha256}</code></td>
                          </tr>
                        </tbody>
                      </table>
                    </div>
                  )}

                  {/* Password Prompt */}
                  {status.state === 'waiting_password' && (
                    <div className="box alert-warning">
                      <h3>🔐 Password Required</h3>
                      <p>This archive is password protected.</p>
                      <input
                        type="password"
                        placeholder="Enter password"
                        onKeyPress={(e) => {
                          if (e.key === 'Enter') providePassword(e.target.value)
                        }}
                        style={{ marginBottom: '10px' }}
                      />
                      <button
                        onClick={(e) => providePassword(e.target.previousElementSibling.value)}
                        className="btn btn-warning"
                      >
                        Provide Password
                      </button>
                    </div>
                  )}

                  {/* Analysis Results */}
                  {report && status.state === 'done' && (
                    <>
                      <div className="box">
                        <h3>📊 Risk Analysis</h3>
                        <div style={{ display: 'flex', gap: '20px', alignItems: 'center' }}>
                          <div>
                            <span className={`badge badge-lg badge-${getRiskColor(report.final)}`}>
                              {report.final}/100
                            </span>
                          </div>
                          <div>
                            <p><strong>Severity:</strong> {report.severity || 'Unknown'}</p>
                            <p><strong>Confidence:</strong> {report.confidence || 'N/A'}</p>
                          </div>
                        </div>
                      </div>

                      {/* YARA Matches */}
                      {report.yara_matches && report.yara_matches.length > 0 && (
                        <div className="box alert-danger">
                          <h3>🚨 YARA Matches</h3>
                          <ul>
                            {report.yara_matches.map((m, i) => (
                              <li key={i}><code>{m}</code></li>
                            ))}
                          </ul>
                        </div>
                      )}

                      {/* IOCs */}
                      {report.iocs && report.iocs.length > 0 && (
                        <div className="box">
                          <h3>🔗 Indicators of Compromise</h3>
                          <ul>
                            {report.iocs.slice(0, 10).map((ioc, i) => (
                              <li key={i}>
                                <strong>{ioc.type}:</strong> <code>{ioc.value}</code>
                              </li>
                            ))}
                          </ul>
                        </div>
                      )}

                      {/* Export Links */}
                      <div className="box" style={{ marginTop: '20px' }}>
                        <h3>📥 Download Report</h3>
                        <div style={{ display: 'flex', gap: '10px' }}>
                          {status.exports?.json && (
                            <a
                              href={`${REPORTER_BASE}/exports/${jobId}/report.json`}
                              className="btn btn-secondary"
                              download
                            >
                              JSON
                            </a>
                          )}
                          {status.exports?.pdf && (
                            <a
                              href={`${REPORTER_BASE}/exports/${jobId}/report.pdf`}
                              className="btn btn-secondary"
                              download
                            >
                              PDF
                            </a>
                          )}
                          {status.exports?.stix && (
                            <a
                              href={`${REPORTER_BASE}/exports/${jobId}/report.stix.json`}
                              className="btn btn-secondary"
                              download
                            >
                              STIX
                            </a>
                          )}
                        </div>
                      </div>

                      {/* Feedback */}
                      <div className="box" style={{ marginTop: '20px' }}>
                        <h3>💬 Feedback</h3>
                        <button
                          onClick={() => sendFeedback('false_positive')}
                          className="btn btn-warning"
                        >
                          Mark as False Positive
                        </button>
                        <button
                          onClick={() => sendFeedback('incorrect_detection')}
                          className="btn btn-warning"
                          style={{ marginLeft: '10px' }}
                        >
                          Incorrect Detection
                        </button>
                      </div>
                    </>
                  )}

                  {status.error && (
                    <div className="box alert-danger">
                      <h3>❌ Error</h3>
                      <p>{status.error}</p>
                    </div>
                  )}
                </>
              )}
            </div>
          </div>
        )}

        {/* Jobs Tab */}
        {activeTab === 'jobs' && (
          <div className="card">
            <h2>📋 All Jobs</h2>
            {jobs.length === 0 ? (
              <p>No jobs found</p>
            ) : (
              <table>
                <thead>
                  <tr>
                    <th>Job ID</th>
                    <th>State</th>
                    <th>File</th>
                    <th>Created</th>
                  </tr>
                </thead>
                <tbody>
                  {jobs.map((j) => (
                    <tr key={j.job_id} onClick={() => { setJobId(j.job_id); setActiveTab('status') }} style={{ cursor: 'pointer' }}>
                      <td><code>{j.job_id.substring(0, 8)}...</code></td>
                      <td>
                        <span className={`badge badge-${
                          j.state === 'done' ? 'success' :
                          j.state === 'failed' ? 'danger' :
                          'info'
                        }`}>
                          {j.state}
                        </span>
                      </td>
                      <td>{j.file_meta?.name || 'N/A'}</td>
                      <td>{new Date(j.timestamps?.submitted).toLocaleString()}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        )}

        {/* Audit Tab */}
        {activeTab === 'audit' && (
          <div className="card">
            <h2>🔐 Audit Log</h2>
            {audit.length === 0 ? (
              <p>No audit logs</p>
            ) : (
              <table>
                <thead>
                  <tr>
                    <th>Time</th>
                    <th>Action</th>
                    <th>Job ID</th>
                    <th>Details</th>
                  </tr>
                </thead>
                <tbody>
                  {audit.slice(0, 100).map((a, i) => (
                    <tr key={i}>
                      <td>{new Date(a.timestamp).toLocaleString()}</td>
                      <td><strong>{a.action}</strong></td>
                      <td><code>{a.job_id?.substring(0, 8) || 'N/A'}</code></td>
                      <td>{a.details}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        )}
      </main>

      {/* Footer */}
      <footer className="footer">
        <p>ZORBOX v2.1 | Enterprise Malware Analysis</p>
      </footer>
    </div>
  )
}
