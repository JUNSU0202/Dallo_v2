import React, { useState, useEffect } from 'react'
import { apiFetch } from '../api/client'

const API = window.location.port === '5173' ? '/api' : `${window.location.origin}/api`

function asObject(value) {
  if (value && typeof value === 'object' && !Array.isArray(value)) return value
  return {}
}

function formatKey(key) {
  return String(key || '').replace(/_/g, ' ')
}

function MetricBlock({ title, data }) {
  const obj = asObject(data)
  const entries = Object.entries(obj)
  return (
    <section className="glass glass-card" style={{ marginBottom: 18 }}>
      <span className="chapter-label">{title}</span>
      {entries.length === 0 ? (
        <div style={{
          fontFamily: 'var(--font-mono)',
          fontSize: 11,
          color: 'var(--ink-faint)',
          textTransform: 'uppercase',
          letterSpacing: '0.14em',
          marginTop: 12,
        }}>
          # no data
        </div>
      ) : (
        <div style={{
          fontFamily: 'var(--font-mono)',
          fontSize: 12,
          lineHeight: 1.85,
          color: 'var(--ink-dim)',
          marginTop: 12,
        }}>
          {entries.map(([key, value]) => (
            <div key={key} style={{ display: 'flex', gap: 14 }}>
              <span style={{ color: 'var(--phosphor)', minWidth: '22ch' }}>
                {formatKey(key)}
              </span>
              <span style={{ color: 'var(--ink)' }}>
                {value === null || value === undefined ? '--' : String(value)}
              </span>
            </div>
          ))}
        </div>
      )}
    </section>
  )
}

function AttackPathsBlock({ paths }) {
  const list = Array.isArray(paths) ? paths : []
  return (
    <section className="glass glass-card" style={{ marginBottom: 18 }}>
      <span className="chapter-label">attack paths</span>
      {list.length === 0 ? (
        <div style={{
          fontFamily: 'var(--font-mono)',
          fontSize: 11,
          color: 'var(--ink-faint)',
          textTransform: 'uppercase',
          letterSpacing: '0.14em',
          marginTop: 12,
        }}>
          # no attack paths recorded
        </div>
      ) : (
        <div style={{
          fontFamily: 'var(--font-mono)',
          fontSize: 12,
          color: 'var(--ink-dim)',
          marginTop: 12,
        }}>
          {list.map((raw, idx) => {
            const item = asObject(raw)
            const entries = Object.entries(item)
            return (
              <article
                key={idx}
                style={{
                  padding: '12px 14px',
                  border: '1px solid var(--rule-hot)',
                  background: 'var(--bg-elev)',
                  marginBottom: 10,
                }}
              >
                <div style={{
                  color: 'var(--phosphor)',
                  fontWeight: 700,
                  marginBottom: 8,
                }}>
                  [{String(idx + 1).padStart(2, '0')}]
                </div>
                {entries.length === 0 ? (
                  <div style={{ color: 'var(--ink-faint)' }}>--</div>
                ) : (
                  entries.map(([key, value]) => (
                    <div key={key} style={{ display: 'flex', gap: 14, lineHeight: 1.7 }}>
                      <span style={{ color: 'var(--phosphor)', minWidth: '18ch' }}>
                        {formatKey(key)}
                      </span>
                      <span style={{ color: 'var(--ink)' }}>
                        {value === null || value === undefined ? '--' : String(value)}
                      </span>
                    </div>
                  ))
                )}
              </article>
            )
          })}
        </div>
      )}
    </section>
  )
}

export default function RedBlueView() {
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [data, setData] = useState(null)

  useEffect(() => {
    let cancelled = false
    setLoading(true)
    setError(null)
    apiFetch(`${API}/red-blue/summary`)
      .then(r => r.json())
      .then(json => {
        if (cancelled) return
        setData(json)
        setLoading(false)
      })
      .catch(e => {
        if (cancelled) return
        setError(`REDBLUE_OFFLINE: ${e.message}`)
        setLoading(false)
      })
    return () => { cancelled = true }
  }, [])

  if (loading) {
    return (
      <div style={{
        textAlign: 'center',
        padding: '80px 20px',
        color: 'var(--ink-dim)',
        fontFamily: 'var(--font-mono)',
        fontSize: 11,
        textTransform: 'uppercase',
        letterSpacing: '0.14em',
      }}>
        $ loading red/blue summary
      </div>
    )
  }

  if (error) {
    return <div className="fade-in alert alert--danger">{error}</div>
  }

  const safe = asObject(data)
  const redTeam = safe.red_team
  const blueTeam = safe.blue_team
  const comparison = safe.comparison
  const attackPaths = safe.attack_paths

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title">
          <em>$</em>&nbsp;redblue <span style={{ color: 'var(--ink-faint)' }}>--summary</span>
        </h1>
        <p className="page-subtitle">
          공방 — 공격(Red) / 방어(Blue) 종합 요약
        </p>
      </div>

      <MetricBlock title="red_team" data={redTeam} />
      <MetricBlock title="blue_team" data={blueTeam} />
      <MetricBlock title="comparison" data={comparison} />
      <AttackPathsBlock paths={attackPaths} />
    </div>
  )
}
