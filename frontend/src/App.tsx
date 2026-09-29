import { useState } from 'react'
import './App.css'

const API_BASE_URL = 'http://127.0.0.1:8001'

type Finding = {
  id: number
  title: string
  description: string | null
  severity: string | null
  matcher_name: string | null
  cvss_score: number | null
  cwe_ids: string | null
  cvss_metrics: string | null
  risk_level: string | null
  risk_reason: string | null
  source: string
  vulnerability_id: string | null
  evidence: string | null
}

type Service = {
  service_name: string | null
  product: string | null
  version: string | null
  cpe: string | null
  confidence?: number | null
  banner?: string | null
}

type Port = {
  id: number
  port_number: number
  protocol: string
  state: string
  service: Service | null
  findings: Finding[]
}

type Host = {
  id: number
  address: string
  hostname: string | null
  status: string
  ports: Port[]
}

type ScanResult = {
  id: number
  target: string
  status: string
  started_at: string | null
  completed_at: string | null
  error_message: string | null
  hosts: Host[]
}

type ScanCreateResponse = {
  id: number
  target: string
  status: string
  started_at: string | null
  completed_at: string | null
}

function App() {
  const [target, setTarget] = useState('http://127.0.0.1:3000')
  const [scanId, setScanId] = useState<number | null>(null)
  const [result, setResult] = useState<ScanResult | null>(null)
  const [loading, setLoading] = useState(false)
  const [scanStatus, setScanStatus] = useState('')
  const [error, setError] = useState('')

  const sleep = (ms: number) =>
    new Promise((resolve) => setTimeout(resolve, ms))

  const getScan = async (id: number): Promise<ScanResult> => {
    const response = await fetch(
      `${API_BASE_URL}/api/scans/${id}`,
    )

    if (!response.ok) {
      throw new Error(
        `Failed to retrieve scan results (${response.status})`,
      )
    }

    return response.json()
  }

  const waitForScan = async (id: number) => {
    const maxAttempts = 240

    for (let attempt = 0; attempt < maxAttempts; attempt++) {
      const scan = await getScan(id)

      setScanStatus(scan.status)

      if (scan.status === 'completed') {
        setResult(scan)
        return
      }

      if (scan.status === 'failed') {
        throw new Error(
          scan.error_message || 'Scan failed on the backend',
        )
      }

      await sleep(2000)
    }

    throw new Error(
      'Scan is taking longer than expected. Check the backend status.',
    )
  }

  const handleStartScan = async () => {
    const cleanTarget = target.trim()

    if (!cleanTarget) {
      setError('Please enter a target URL.')
      return
    }

    setLoading(true)
    setError('')
    setResult(null)
    setScanId(null)
    setScanStatus('starting')

    try {
      const response = await fetch(
        `${API_BASE_URL}/api/scans`,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            target: cleanTarget,
          }),
        },
      )

      if (!response.ok) {
        let message = `Failed to start scan (${response.status})`

        try {
          const data = await response.json()

          if (typeof data.detail === 'string') {
            message = data.detail
          }
        } catch {
          // Keep the default error message.
        }

        throw new Error(message)
      }

      const data: ScanCreateResponse = await response.json()

      setScanId(data.id)
      setScanStatus(data.status)

      await waitForScan(data.id)
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : 'Unable to start scan',
      )
      setScanStatus('failed')
    } finally {
      setLoading(false)
    }
  }

  const totalPorts = result
    ? result.hosts.reduce(
        (total, host) => total + host.ports.length,
        0,
      )
    : 0

  const totalServices = result
    ? result.hosts.reduce(
        (total, host) =>
          total +
          host.ports.filter(
            (port) => port.service !== null,
          ).length,
        0,
      )
    : 0

  const totalFindings = result
    ? result.hosts.reduce(
        (total, host) =>
          total +
          host.ports.reduce(
            (portTotal, port) =>
              portTotal + port.findings.length,
            0,
          ),
        0,
      )
    : 0

  const getConfidence = (riskReason: string | null) => {
    if (!riskReason) {
      return 'N/A'
    }

    const match = riskReason.match(
      /confidence:\s*(\d+)/i,
    )

    return match?.[1] ?? 'N/A'
  }

  const formatValue = (
    value: string | number | null | undefined,
  ) => {
    if (
      value === null ||
      value === undefined ||
      value === ''
    ) {
      return 'Not reported'
    }

    return String(value)
  }

  return (
    <main className="app">
      <header className="header">
        <div>
          <p className="eyebrow">ZYNCLE SECURITY</p>

          <h1>Website Scanner</h1>

          <p className="subtitle">
            Port discovery, service detection and vulnerability
            intelligence in one workflow.
          </p>
        </div>

        <div className="status-badge">
          <span />
          Scanner Online
        </div>
      </header>

      <section className="scan-card">
        <label htmlFor="target">
          Website / Target URL
        </label>

        <div className="scan-row">
          <input
            id="target"
            type="text"
            value={target}
            onChange={(event) =>
              setTarget(event.target.value)
            }
            placeholder="http://127.0.0.1:3000"
            disabled={loading}
          />

          <button
            type="button"
            onClick={handleStartScan}
            disabled={loading}
          >
            {loading ? 'SCANNING...' : 'START SCAN'}
          </button>
        </div>

        <p className="helper">
          For testing, use an authorized target such as example.com.
        </p>
      </section>

      {loading && (
        <section className="scan-progress">
          <div>
            <p className="section-label">SCAN IN PROGRESS</p>

            <h2>
              {scanId
                ? `Scan #${scanId}`
                : 'Starting scan...'}
            </h2>

            <p>
              Status:{' '}
              <strong className="capitalize">
                {scanStatus}
              </strong>
            </p>
          </div>

          <div className="progress-indicator">
            Running
          </div>
        </section>
      )}

      {error && (
        <div className="error">
          <strong>Scan Error:</strong> {error}
        </div>
      )}

      {result && (
        <>
          <section className="overview">
            <div className="summary-card">
              <span>SCAN ID</span>
              <strong>#{result.id}</strong>
            </div>

            <div className="summary-card">
              <span>STATUS</span>

              <strong className="capitalize">
                {result.status}
              </strong>
            </div>

            <div className="summary-card">
              <span>HOSTS</span>
              <strong>{result.hosts.length}</strong>
            </div>

            <div className="summary-card">
              <span>OPEN PORTS</span>
              <strong>{totalPorts}</strong>
            </div>

            <div className="summary-card">
              <span>SERVICES</span>
              <strong>{totalServices}</strong>
            </div>

            <div className="summary-card">
              <span>FINDINGS</span>
              <strong>{totalFindings}</strong>
            </div>
          </section>

          <section className="panel">
            <div className="panel-header">
              <div>
                <p className="section-label">TARGET</p>

                <h2>{result.target}</h2>
              </div>

              <span className="completed">
                {result.status}
              </span>
            </div>
          </section>

          {result.hosts.map((host) => (
            <section className="panel" key={host.id}>
              <div className="panel-header">
                <div>
                  <p className="section-label">HOST</p>

                  <h2>{host.address}</h2>
                </div>

                <span className="host-status">
                  {host.status}
                </span>
              </div>

              <div className="table-wrapper">
                <table>
                  <thead>
                    <tr>
                      <th>PORT</th>
                      <th>PROTOCOL</th>
                      <th>STATE</th>
                      <th>SERVICE</th>
                      <th>PRODUCT</th>
                    </tr>
                  </thead>

                  <tbody>
                    {host.ports.map((port) => (
                      <tr key={port.id}>
                        <td>{port.port_number}</td>

                        <td>{port.protocol}</td>

                        <td>
                          <span className="open-state">
                            {port.state}
                          </span>
                        </td>

                        <td>
                          {port.service?.service_name ??
                            'Unknown'}
                        </td>

                        <td>
                          {port.service?.product ??
                            'Unknown'}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>
          ))}

          <section className="panel">
            <div className="panel-header">
              <div>
                <p className="section-label">NUCLEI</p>

                <h2>Detection Findings</h2>
              </div>
            </div>

            <div className="findings">
              {result.hosts.flatMap((host) =>
                host.ports.flatMap((port) =>
                  port.findings.map((finding) => (
                    <article
                      className="finding"
                      key={finding.id}
                    >
                      <div className="finding-main">
                        <h3>{finding.title}</h3>

                        <p className="finding-meta">
                          Port {port.port_number} ·{' '}
                          {finding.source}
                        </p>

                        <div className="finding-details">
                          <div>
                            <span>SEVERITY</span>
                            <strong>
                              {formatValue(
                                finding.severity,
                              )}
                            </strong>
                          </div>

                          <div>
                            <span>RISK</span>
                            <strong>
                              {formatValue(
                                finding.risk_level,
                              )}
                            </strong>
                          </div>

                          <div>
                            <span>CONFIDENCE</span>
                            <strong>
                              {getConfidence(
                                finding.risk_reason,
                              )}
                            </strong>
                          </div>

                          <div>
                            <span>CVE</span>
                            <strong>
                              {formatValue(
                                finding.vulnerability_id,
                              )}
                            </strong>
                          </div>

                          <div>
                            <span>CVSS</span>
                            <strong>
                              {formatValue(
                                finding.cvss_score,
                              )}
                            </strong>
                          </div>

                          <div>
                            <span>CWE</span>
                            <strong>
                              {formatValue(
                                finding.cwe_ids,
                              )}
                            </strong>
                          </div>
                        </div>

                        {finding.cvss_metrics && (
                          <p>
                            <strong>
                              CVSS Metrics:
                            </strong>{' '}
                            {finding.cvss_metrics}
                          </p>
                        )}

                        {finding.description && (
                          <p>
                            <strong>
                              Description:
                            </strong>{' '}
                            {finding.description}
                          </p>
                        )}

                        {finding.evidence && (
                          <p>
                            <strong>Evidence:</strong>{' '}
                            {finding.evidence}
                          </p>
                        )}

                        {finding.risk_reason && (
                          <p>
                            <strong>
                              Risk Classification:
                            </strong>{' '}
                            {finding.risk_reason}
                          </p>
                        )}
                        {finding.matcher_name && (
                          <p>
                            <strong>Matcher:</strong> {finding.matcher_name}
                          </p>
                        )}
                      </div>

                      <div>
                        <span className="severity">
                          {(
                            finding.severity ??
                            'unknown'
                          ).toUpperCase()}
                        </span>
                      </div>
                    </article>
                  )),
                ),
              )}

              {totalFindings === 0 && (
                <p>
                  No findings were returned by the current
                  vulnerability detection stage.
                </p>
              )}
            </div>
          </section>
        </>
      )}
    </main>
  )
}

export default App