import React, { useEffect, useState } from 'react'

const API_BASE = import.meta.env.VITE_API_BASE || 'http://localhost:8080'

export default function App(){
  const [file, setFile] = useState(null)
  const [url, setUrl] = useState('')
  const [password, setPassword] = useState('')
  const [jobId, setJobId] = useState('')
  const [status, setStatus] = useState(null)
  const [error, setError] = useState('')
  const [note, setNote] = useState('')

  useEffect(() => {
    // Simple RUM: navigation timing log
    const perf = performance.getEntriesByType('navigation')[0]
    if (perf) {
      console.log('RUM', {
        ttfb: perf.responseStart,
        domContentLoaded: perf.domContentLoadedEventEnd,
        load: perf.loadEventEnd
      })
    }
    // Error logging
    const handler = (e) => console.error('FrontendError', e.message)
    window.addEventListener('error', handler)
    return () => window.removeEventListener('error', handler)
  }, [])

  async function submitAnalyze(e){
    e.preventDefault()
    setError('')
    const form = new FormData()
    if (file) form.append('file', file)
    if (url) form.append('url', url)
    if (password) form.append('password', password)
    try{
      const res = await fetch(`${API_BASE}/analyze`, { method:'POST', body: form })
      const data = await res.json()
      if(!res.ok){
        setError(data.detail || 'Request failed')
        return
      }
      setJobId(data.job_id)
    }catch(err){
      setError(err.message)
    }
  }

  async function refreshStatus(){
    if(!jobId) return
    const res = await fetch(`${API_BASE}/result/${jobId}`)
    if (res.ok){
      setStatus(await res.json())
    }
  }

  return (
    <div style={{maxWidth: 720, margin: '2rem auto', fontFamily:'sans-serif'}}>
      <h1>ZORBOX UI (MVP)</h1>
      <form onSubmit={submitAnalyze}>
        <div>
          <label>File: <input type="file" onChange={e=>setFile(e.target.files?.[0]||null)} /></label>
        </div>
        <div>
          <label>URL: <input value={url} onChange={e=>setUrl(e.target.value)} placeholder="https://..." /></label>
        </div>
        <div>
          <label>Archive password: <input value={password} onChange={e=>setPassword(e.target.value)} /></label>
        </div>
        <button type="submit">Analyze</button>
      </form>
      {error && <p style={{color:'red'}}>Error: {error}</p>}
      {jobId && (
        <div style={{marginTop:'1rem'}}>
          <p>Job ID: <code>{jobId}</code></p>
          <button onClick={refreshStatus}>Refresh status</button>
        </div>
      )}
      {status && (
        <div style={{marginTop:'1rem'}}>
          <pre style={{background:'#f5f5f5', padding:'1rem'}}>{JSON.stringify(status, null, 2)}</pre>
          {status.export && (
            <div>
              <h3>Exports</h3>
              {status.export.json_url && <div><a href={status.export.json_url} target="_blank">JSON</a></div>}
              {status.export.pdf_url && <div><a href={status.export.pdf_url} target="_blank">PDF</a></div>}
              {status.export.stix_url && <div><a href={status.export.stix_url} target="_blank">STIX</a></div>}
            </div>
          )}
          <div style={{marginTop:'0.5rem'}}>
            <button onClick={async()=>{
              if(!jobId) return
              await fetch(`${API_BASE}/feedback`, {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({job_id: jobId, kind:'fp', comment: note})})
              setNote('')
            }}>Mark FP</button>
            <button onClick={async()=>{
              if(!jobId) return
              const res = await fetch(`${API_BASE}/reanalysis`, {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({job_id: jobId})})
              if(res.ok){ const d = await res.json(); setJobId(d.job_id); setStatus(null) }
            }} style={{marginLeft:'0.5rem'}}>Request reanalysis</button>
            <input placeholder="note" value={note} onChange={e=>setNote(e.target.value)} style={{marginLeft:'0.5rem'}}/>
          </div>
        </div>
      )}
    </div>
  )
}
