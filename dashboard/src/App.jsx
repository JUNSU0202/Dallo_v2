import React, { useState, useEffect, useRef, useCallback } from 'react'
import StatsCards from './components/StatsCards'
import VulnTable from './components/VulnTable'
import FileChart from './components/FileChart'
import TypeChart from './components/TypeChart'
import PatchView from './components/PatchView'
import AnalyzeView from './components/AnalyzeView'
import HistoryView from './components/HistoryView'
import DependencyView from './components/DependencyView'
import ReportView from './components/ReportView'
import RedBlueView from './components/RedBlueView'
import LoginView from './components/LoginView'
import { apiFetch, isAuthenticated, clearApiKey } from './api/client'

const API = window.location.port === '5173' ? '/api' : `${window.location.origin}/api`

// Tick clock for the status bar — updates every second.
function useClock() {
  const [now, setNow] = useState(() => new Date())
  useEffect(() => {
    const id = setInterval(() => setNow(new Date()), 1000)
    return () => clearInterval(id)
  }, [])
  return now
}

function fmtTime(d) {
  const hh = String(d.getHours()).padStart(2, '0')
  const mm = String(d.getMinutes()).padStart(2, '0')
  const ss = String(d.getSeconds()).padStart(2, '0')
  return `${hh}:${mm}:${ss}`
}

function fmtDate(d) {
  const yy = String(d.getFullYear())
  const mm = String(d.getMonth() + 1).padStart(2, '0')
  const dd = String(d.getDate()).padStart(2, '0')
  return `${yy}-${mm}-${dd}`
}

export default function App() {
  const [authed, setAuthed] = useState(isAuthenticated())
  const [tab, setTab] = useState('analyze')
  const [stats, setStats] = useState(null)
  const [vulns, setVulns] = useState([])
  const [byFile, setByFile] = useState([])
  const [byType, setByType] = useState([])
  const [patches, setPatches] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const prevTabRef = useRef(0)
  const now = useClock()

  // 401 이벤트 수신 — 인증 만료 시 로그인 화면으로 전환
  useEffect(() => {
    const handler = () => setAuthed(false)
    window.addEventListener('dallo:auth-required', handler)
    return () => window.removeEventListener('dallo:auth-required', handler)
  }, [])

  const handleLogout = useCallback(() => {
    clearApiKey()
    setAuthed(false)
  }, [])

  const fetchAll = () => {
    Promise.all([
      apiFetch(`${API}/stats`).then(r => r.json()),
      apiFetch(`${API}/vulnerabilities`).then(r => r.json()),
      apiFetch(`${API}/vulnerabilities/by-file`).then(r => r.json()),
      apiFetch(`${API}/vulnerabilities/by-type`).then(r => r.json()),
      apiFetch(`${API}/patches`).then(r => r.json()),
    ]).then(([s, v, f, t, p]) => {
      setStats(s)
      setVulns(v.vulnerabilities || [])
      setByFile(f.files || [])
      setByType(t.types || [])
      setPatches(p.patches || [])
      setLoading(false)
    }).catch(e => {
      setError(`API_OFFLINE: ${e.message} — start with: $ python start.py`)
      setLoading(false)
    })
  }

  useEffect(() => {
    if (!authed) return
    setLoading(true)
    fetchAll()
  }, [authed])

  if (!authed) {
    return <LoginView onLogin={() => setAuthed(true)} />
  }

  // Tabs as command-line subcommands
  const tabs = [
    { id: 'analyze',   num: '01', cmd: 'scan',     ko: '분석' },
    { id: 'dashboard', num: '02', cmd: 'stats',    ko: '대시보드' },
    { id: 'vulns',     num: '03', cmd: 'findings', ko: '취약점' },
    { id: 'patches',   num: '04', cmd: 'patches',  ko: '수정안' },
    { id: 'deps',      num: '05', cmd: 'deps',     ko: '의존성' },
    { id: 'report',    num: '06', cmd: 'report',   ko: '리포트' },
    { id: 'history',   num: '07', cmd: 'log',      ko: '이력' },
    { id: 'redblue',   num: '08', cmd: 'redblue',  ko: '공방' },
  ]

  const status = error ? 'OFFLINE' : loading ? 'BOOTING' : 'READY'
  const statusColor = error ? '#ff3d24' : loading ? '#ffb000' : '#0a0a0a'
  const totalIssues = stats?.total_issues ?? '--'

  return (
    <>
      {/* ============= STATUS BAR ============= */}
      <div className="statusbar">
        <span className="statusbar__cell">
          <span className="statusbar__blink" />
          dallo.sec / v0.4.1
        </span>
        <span className="statusbar__cell">{fmtDate(now)}</span>
        <span className="statusbar__cell">{fmtTime(now)} KST</span>
        <span className="statusbar__cell">PID 0x{Math.floor(Math.random() * 0xffff).toString(16).padStart(4, '0').toUpperCase()}</span>
        <span className="statusbar__cell" style={{ marginLeft: 'auto' }}>
          STATE: <span style={{ background: statusColor, color: status === 'READY' ? '#0a0a0a' : '#fff', padding: '0 6px' }}>{status}</span>
        </span>
        <span className="statusbar__cell">ISSUES {totalIssues}</span>
        <span className="statusbar__cell" style={{ cursor: 'pointer' }} onClick={handleLogout} title="로그아웃">
          [LOGOUT]
        </span>
      </div>

      {/* ============= MASTHEAD ============= */}
      <header className="app-header">
        <div className="masthead">
          <div className="masthead__top">
            <div>
              <div className="masthead__id">
                <span className="masthead__bracket">[</span>
                <h1 className="masthead__wordmark">
                  dallo<span className="dim">.</span><span className="accent">sec</span>
                  <span className="masthead__caret"></span>
                </h1>
                <span className="masthead__bracket">]</span>
              </div>
              <div style={{
                fontFamily: 'var(--font-mono)',
                fontSize: 10,
                color: 'var(--ink-dim)',
                marginTop: 8,
                textTransform: 'uppercase',
                letterSpacing: '0.14em',
                paddingLeft: 22,
              }}>
                # static analysis · llm patch synthesis · audit trail
              </div>
            </div>

            <div className="masthead__meta">
              <div>uptime <strong>{Math.floor((now - new Date(now.getFullYear(), now.getMonth(), now.getDate())) / 1000 / 60)}m</strong></div>
              <div>build <strong>2026.04.09</strong></div>
              <div>llm <strong>gemini-2.0-flash-lite</strong></div>
              <div>tty <strong>/dev/dallo</strong></div>
            </div>
          </div>

          <nav className="masthead__nav app-header__nav">
            <div className="tab-bar">
              {tabs.map(t => (
                <button
                  key={t.id}
                  onClick={() => setTab(t.id)}
                  className={`tab-btn ${tab === t.id ? 'tab-btn--active' : ''}`}
                >
                  <span className="tab-btn__num">{t.num}</span>
                  {t.cmd}
                </button>
              ))}
            </div>
          </nav>
        </div>
      </header>

      {/* ============= MAIN ============= */}
      <main className="app-main">
        {error && (
          <div className="fade-in alert alert--danger">{error}</div>
        )}

        {loading ? (
          <div style={{
            textAlign: 'center',
            padding: '120px 20px',
            color: 'var(--ink-dim)',
            fontFamily: 'var(--font-mono)',
            fontSize: 11,
            textTransform: 'uppercase',
            letterSpacing: '0.14em',
          }}>
            <div className="loader" />
            <div>$ booting analyzers</div>
          </div>
        ) : (
          (() => {
            const tabIndex = tabs.findIndex(t => t.id === tab)
            const directionClass = tabIndex >= prevTabRef.current ? 'tab-enter-right' : 'tab-enter-left'
            prevTabRef.current = tabIndex
            const currentChapter = tabs[tabIndex]
            return (
              <>
                <div style={{ display: tab === 'analyze' ? 'block' : 'none' }}>
                  <AnalyzeView onComplete={fetchAll} />
                </div>
                <div className={directionClass} key={tab} style={{ display: tab === 'analyze' ? 'none' : 'block' }}>
                  {currentChapter && (
                    <div className="chapter-label">
                      {currentChapter.num} / {currentChapter.cmd}
                    </div>
                  )}

                {tab === 'dashboard' && (
                  <>
                    <div className="page-header">
                      <h1 className="page-title">
                        <em>$</em>&nbsp;stats
                      </h1>
                      <p className="page-subtitle">
                        snapshot of the most recent audit — counts, ratios, current state
                      </p>
                    </div>
                    <StatsCards stats={stats} />
                    <hr className="rule-double" />
                    <div className="dashboard-grid">
                      <FileChart data={byFile} />
                      <TypeChart data={byType} />
                    </div>
                  </>
                )}
                {tab === 'vulns' && <VulnTable vulns={vulns} />}
                {tab === 'patches' && <PatchView patches={patches} />}
                {tab === 'deps' && <DependencyView />}
                {tab === 'report' && <ReportView />}
                {tab === 'history' && <HistoryView />}
                {tab === 'redblue' && <RedBlueView />}
                </div>
              </>
            )
          })()
        )}

        {/* Footer status line */}
        <footer style={{
          marginTop: 80,
          paddingTop: 14,
          borderTop: '1px solid var(--rule-hot)',
          fontFamily: 'var(--font-mono)',
          fontSize: 10,
          color: 'var(--ink-faint)',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          flexWrap: 'wrap',
          gap: 12,
          textTransform: 'uppercase',
          letterSpacing: '0.14em',
        }}>
          <span>-- {tab.toUpperCase()} --</span>
          <span>L1 · C1 · UTF-8 · UNIX · NOEOL</span>
          <span>:wq</span>
        </footer>
      </main>
    </>
  )
}
