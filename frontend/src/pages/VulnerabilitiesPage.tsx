import { useMemo, useState } from 'react'

import type { ScanResult } from '../types'
import {
  countBySeverity,
  flattenFindings,
  normalizeSeverity,
  severityRank,
} from '../utils'
import FindingsList from '../components/FindingsList'
import Icon from '../components/Icon'
import ScanContextBar from '../components/ScanContextBar'
import SeverityOverview from '../components/SeverityOverview'
import StateBlock from '../components/StateBlock'

type SortKey = 'severity' | 'cvss' | 'title' | 'host'

type VulnerabilitiesPageProps = {
  scan: ScanResult | null
  loading: boolean
  error: string
  onChangeScan: () => void
}

function VulnerabilitiesPage({
  scan,
  loading,
  error,
  onChangeScan,
}: VulnerabilitiesPageProps) {
  const [query, setQuery] = useState('')
  const [severity, setSeverity] = useState('all')
  const [source, setSource] = useState('all')
  const [sort, setSort] = useState<SortKey>('severity')

  const all = useMemo(() => flattenFindings(scan), [scan])

  const sources = useMemo(
    () => Array.from(new Set(all.map((item) => item.finding.source))).sort(),
    [all],
  )

  const visible = useMemo(() => {
    const needle = query.trim().toLowerCase()

    const filtered = all.filter(({ finding, host, port }) => {
      if (
        severity !== 'all' &&
        normalizeSeverity(finding.severity) !== severity
      ) {
        return false
      }

      if (source !== 'all' && finding.source !== source) {
        return false
      }

      if (!needle) {
        return true
      }

      return [
        finding.title,
        finding.vulnerability_id,
        finding.cwe_ids,
        finding.source,
        host.address,
        host.hostname,
        port.service?.service_name,
        String(port.port_number),
      ].some((value) => value?.toLowerCase().includes(needle))
    })

    return [...filtered].sort((a, b) => {
      switch (sort) {
        case 'cvss':
          return (b.finding.cvss_score ?? -1) - (a.finding.cvss_score ?? -1)
        case 'title':
          return a.finding.title.localeCompare(b.finding.title)
        case 'host':
          return (
            a.host.address.localeCompare(b.host.address) ||
            a.port.port_number - b.port.port_number
          )
        default:
          return (
            severityRank(b.finding.severity) -
              severityRank(a.finding.severity) ||
            (b.finding.cvss_score ?? -1) - (a.finding.cvss_score ?? -1)
          )
      }
    })
  }, [all, query, severity, source, sort])

  if (loading && !scan) {
    return (
      <div className="page">
        <StateBlock kind="loading" title="Loading findings…" />
      </div>
    )
  }

  if (!scan) {
    return (
      <div className="page">
        {error ? (
          <StateBlock kind="error" title="Unable to load findings.">
            {error}
          </StateBlock>
        ) : (
          <StateBlock kind="empty" title="No completed scan available.">
            Run a scan to see vulnerabilities here.
          </StateBlock>
        )}
      </div>
    )
  }

  const filtersActive =
    query !== '' || severity !== 'all' || source !== 'all'

  return (
    <div className="page">
      <ScanContextBar scan={scan} onChangeScan={onChangeScan} />

      {all.length === 0 ? (
        <section className="panel">
          <StateBlock kind="empty" title="No vulnerabilities detected." />
        </section>
      ) : (
        <>
          <section className="panel">
            <div className="panel-header">
              <div>
                <p className="eyebrow">Distribution</p>
                <h2>{all.length} findings</h2>
              </div>
            </div>

            <SeverityOverview counts={countBySeverity(all)} />
          </section>

          <section className="panel">
            <div className="filters">
              <div className="field search-field">
                <label htmlFor="vuln-search">Search</label>
                <div className="input-icon">
                  <Icon name="search" size={16} />
                  <input
                    id="vuln-search"
                    type="search"
                    value={query}
                    onChange={(event) => setQuery(event.target.value)}
                    placeholder="Title, CVE, host, service…"
                  />
                </div>
              </div>

              <div className="field">
                <label htmlFor="vuln-severity">Severity</label>
                <select
                  id="vuln-severity"
                  value={severity}
                  onChange={(event) => setSeverity(event.target.value)}
                >
                  <option value="all">All severities</option>
                  <option value="critical">Critical</option>
                  <option value="high">High</option>
                  <option value="medium">Medium</option>
                  <option value="low">Low</option>
                  <option value="other">Unrated</option>
                </select>
              </div>

              <div className="field">
                <label htmlFor="vuln-source">Source</label>
                <select
                  id="vuln-source"
                  value={source}
                  onChange={(event) => setSource(event.target.value)}
                >
                  <option value="all">All sources</option>
                  {sources.map((name) => (
                    <option key={name} value={name}>
                      {name}
                    </option>
                  ))}
                </select>
              </div>

              <div className="field">
                <label htmlFor="vuln-sort">Sort by</label>
                <select
                  id="vuln-sort"
                  value={sort}
                  onChange={(event) =>
                    setSort(event.target.value as SortKey)
                  }
                >
                  <option value="severity">Severity</option>
                  <option value="cvss">CVSS score</option>
                  <option value="title">Title</option>
                  <option value="host">Host</option>
                </select>
              </div>
            </div>

            <p className="note" aria-live="polite">
              Showing {visible.length} of {all.length} findings
              {filtersActive && (
                <>
                  {' · '}
                  <button
                    type="button"
                    className="link-button"
                    onClick={() => {
                      setQuery('')
                      setSeverity('all')
                      setSource('all')
                    }}
                  >
                    Clear filters
                  </button>
                </>
              )}
            </p>

            {visible.length === 0 ? (
              <StateBlock kind="empty" title="No findings match the filters." />
            ) : (
              <FindingsList items={visible} />
            )}
          </section>
        </>
      )}
    </div>
  )
}

export default VulnerabilitiesPage
