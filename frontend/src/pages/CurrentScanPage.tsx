import { useState } from 'react'

import type {
  ActiveSection,
  ScanCreateResponse,
  ScanProfile,
  ScanResult,
  VulnerabilityProfile,
} from '../types'

import {
  countBySeverity,
  countPorts,
  countServices,
  flattenFindings,
  formatDate,
  getProfileLabel,
  getVulnerabilityProfileLabel,
  isActiveStatus,
} from '../utils'

import ExportActions from '../components/ExportActions'
import FindingsList from '../components/FindingsList'
import HostTable from '../components/HostTable'
import PortTable from '../components/PortTable'
import ScanPipeline from '../components/ScanPipeline'
import SeverityOverview from '../components/SeverityOverview'
import StateBlock from '../components/StateBlock'
import StatusBadge from '../components/StatusBadge'
import SummaryCard from '../components/SummaryCard'

type Tab = 'hosts' | 'findings'

type CurrentScanPageProps = {
  loading: boolean
  scanStatus: string
  scanId: number | null
  scanMeta: ScanCreateResponse | null
  target: string
  profile: ScanProfile
  vulnerabilityProfile: VulnerabilityProfile
  error: string
  result: ScanResult | null
  onNavigate: (section: ActiveSection) => void
  onReloadScan: (id: number) => void
}

function CurrentScanPage({
  loading,
  scanStatus,
  scanId,
  scanMeta,
  target,
  profile,
  vulnerabilityProfile,
  error,
  result,
  onNavigate,
  onReloadScan,
}: CurrentScanPageProps) {
  const [tab, setTab] = useState<Tab>('hosts')

  const findings = flattenFindings(result)

  const monitorTarget = scanMeta?.target ?? target

  const pipelineStatus = result
    ? result.status
    : scanStatus

  const snapshotActive =
    !loading &&
    result !== null &&
    isActiveStatus(result.status)


  const hostsCount = result?.hosts.length ?? 0

  const portsCount = result
    ? countPorts(result)
    : 0

  const servicesCount = result
    ? countServices(result)
    : 0

  const findingsCount = findings.length

  return (
    <div className="page current-scan-page">

      {/* =====================================================
          PAGE HEADER
         ===================================================== */}

      <div className="page-heading current-scan-heading">
        <div>
          <p className="eyebrow">
            SECURITY ASSESSMENT
          </p>

          <h1>
            Current Scan
          </h1>

          <p>
            Monitor scan execution and inspect discovered
            hosts, services and vulnerability findings.
          </p>
        </div>

        {result && (
          <div className="current-scan-header-status">
            <StatusBadge status={result.status} />
          </div>
        )}
      </div>


      {/* =====================================================
          LIVE SCAN MONITOR
         ===================================================== */}

      {loading && (
        <section
          className="panel current-scan-monitor"
          aria-live="polite"
        >
          <div className="panel-header">
            <div>
              <p className="eyebrow">
                {scanStatus === 'loading'
                  ? 'INITIALIZING'
                  : 'LIVE SCAN'}
              </p>

              <h2>
                {scanId
                  ? `Scan #${scanId}`
                  : 'Starting scan…'}
              </h2>

              <p className="helper">
                The scanner is processing the requested target.
              </p>
            </div>

            <StatusBadge status={scanStatus} />
          </div>

          {scanStatus !== 'loading' && (
            <>
              <div
                className="current-scan-live-indicator"
                aria-hidden="true"
              >
                <span />
                Scan activity detected
              </div>

              <div className="detail-grid current-scan-meta">

                <div className="span-2">
                  <dt>Target</dt>
                  <dd className="break">
                    {monitorTarget}
                  </dd>
                </div>

                <div>
                  <dt>Port profile</dt>
                  <dd>
                    {getProfileLabel(
                      scanMeta?.profile ?? profile,
                    )}
                  </dd>
                </div>

                <div>
                  <dt>Vulnerability profile</dt>
                  <dd>
                    {getVulnerabilityProfileLabel(
                      scanMeta?.vulnerability_profile ??
                        vulnerabilityProfile,
                    )}
                  </dd>
                </div>

              </div>

              <p className="note">
                Waiting for the backend to report completion.
                Status is refreshed automatically.
              </p>
            </>
          )}
        </section>
      )}


      {/* =====================================================
          PIPELINE
         ===================================================== */}

      {(loading || (scanId !== null && !result)) && (
        <section className="current-scan-pipeline-section">
          <ScanPipeline
            status={pipelineStatus}
            vulnerabilityProfile={
              scanMeta?.vulnerability_profile ??
              vulnerabilityProfile
            }
          />
        </section>
      )}


      {/* =====================================================
          ERROR
         ===================================================== */}

      {error && !loading && (
        <section
          className="panel panel-danger current-scan-error"
          role="alert"
        >
          <div className="panel-header">
            <div>
              <p className="eyebrow">
                {scanStatus === 'failed'
                  ? 'SCAN FAILED'
                  : 'SCAN ERROR'}
              </p>

              <h2>
                {scanId
                  ? `Scan #${scanId}`
                  : 'Unable to start scan'}
              </h2>
            </div>

            {scanStatus === 'failed' && (
              <StatusBadge status="failed" />
            )}
          </div>

          <p className="error-text">
            {error}
          </p>

          <div className="inline-actions">
            <button
              type="button"
              className="btn btn-sm"
              onClick={() => onNavigate('new-scan')}
            >
              Back to New Scan
            </button>
          </div>
        </section>
      )}


      {/* =====================================================
          RESULT
         ===================================================== */}

      {result && (
        <>

          {/* ACTIVE SNAPSHOT */}

          {snapshotActive && (
            <div
              className="context-bar current-scan-context"
              role="status"
            >
              <div>
                <strong>
                  Scan is still active
                </strong>

                <span>
                  Current result snapshot:
                  {' '}
                  {result.status}
                </span>
              </div>

              <button
                type="button"
                className="btn btn-sm"
                onClick={() => onReloadScan(result.id)}
              >
                Reload
              </button>
            </div>
          )}


          {/* =================================================
              SCAN OVERVIEW
             ================================================= */}

          <section
            className="panel current-scan-overview"
            aria-labelledby="current-scan-overview-title"
          >
            <div className="panel-header">
              <div>
                <p className="eyebrow">
                  SCAN OVERVIEW
                </p>

                <h2 id="current-scan-overview-title">
                  Scan #{result.id}
                </h2>

                <p className="helper">
                  Assessment details and execution metadata.
                </p>
              </div>

              <div className="header-tools">
                <StatusBadge status={result.status} />
                <ExportActions result={result} />
              </div>
            </div>

            <dl className="detail-grid current-scan-detail-grid">

              <div className="span-2">
                <dt>Target</dt>

                <dd className="break mono">
                  {result.target}
                </dd>
              </div>

              <div>
                <dt>Port profile</dt>

                <dd>
                  {getProfileLabel(result.profile)}
                </dd>
              </div>

              <div>
                <dt>Vulnerability profile</dt>

                <dd>
                  {getVulnerabilityProfileLabel(
                    result.vulnerability_profile,
                  )}
                </dd>
              </div>

              <div>
                <dt>Started</dt>

                <dd>
                  {formatDate(result.started_at)}
                </dd>
              </div>

              <div>
                <dt>Completed</dt>

                <dd>
                  {formatDate(result.completed_at)}
                </dd>
              </div>

            </dl>

            {result.error_message && (
              <div className="scan-result-warning">
                <strong>
                  Scan message
                </strong>

                <span>
                  {result.error_message}
                </span>
              </div>
            )}
          </section>


          {/* =================================================
              SUMMARY
             ================================================= */}

          <section
            className="summary-grid current-scan-summary"
            aria-label="Scan totals"
          >
            <SummaryCard
              label="Hosts"
              value={hostsCount}
            />

            <SummaryCard
              label="Open ports"
              value={portsCount}
            />

            <SummaryCard
              label="Services"
              value={servicesCount}
            />

            <SummaryCard
              label="Findings"
              value={findingsCount}
            />
          </section>


          {/* =================================================
              VULNERABILITY INTELLIGENCE
             ================================================= */}

          {findings.length > 0 && (
            <section
              className="panel current-scan-intelligence"
              aria-labelledby="current-scan-intelligence-title"
            >
              <div className="panel-header">
                <div>
                  <p className="eyebrow">
                    VULNERABILITY INTELLIGENCE
                  </p>

                  <h2 id="current-scan-intelligence-title">
                    Severity overview
                  </h2>

                  <p className="helper">
                    Findings identified during this scan.
                  </p>
                </div>

                <span className="panel-meta">
                  {findings.length} findings
                </span>
              </div>

              <SeverityOverview
                counts={countBySeverity(findings)}
              />
            </section>
          )}


          {/* =================================================
              RESULT TABS
             ================================================= */}

          <section
            className="panel current-scan-results"
            aria-labelledby="results-title"
          >
            <div className="panel-header">
              <div>
                <p className="eyebrow">
                  SCAN RESULTS
                </p>

                <h2 id="results-title">
                  Discovered assets & findings
                </h2>

                <p className="helper">
                  Inspect hosts, exposed ports, services and
                  detected vulnerabilities.
                </p>
              </div>
            </div>

            <div
              className="tabs current-scan-tabs"
              role="tablist"
              aria-label="Scan results"
            >
              <button
                type="button"
                role="tab"
                id="tab-hosts"
                aria-selected={tab === 'hosts'}
                aria-controls="panel-hosts"
                className={
                  tab === 'hosts'
                    ? 'tab active'
                    : 'tab'
                }
                onClick={() => setTab('hosts')}
              >
                Hosts & ports

                <span className="tab-count">
                  {hostsCount}
                </span>
              </button>

              <button
                type="button"
                role="tab"
                id="tab-findings"
                aria-selected={tab === 'findings'}
                aria-controls="panel-findings"
                className={
                  tab === 'findings'
                    ? 'tab active'
                    : 'tab'
                }
                onClick={() => setTab('findings')}
              >
                Findings

                <span className="tab-count">
                  {findingsCount}
                </span>
              </button>
            </div>


            {/* =================================================
                HOSTS
               ================================================= */}

            <div
              className="tab-panel current-scan-tab-panel"
              role="tabpanel"
              id="panel-hosts"
              aria-labelledby="tab-hosts"
              hidden={tab !== 'hosts'}
            >
              {result.hosts.length === 0 ? (
                <StateBlock
                  kind="empty"
                  title="No hosts discovered."
                >
                  {result.status === 'completed'
                    ? 'The scan finished without discovering reachable hosts or open ports.'
                    : 'No host data is available for this scan.'}
                </StateBlock>
              ) : (
                <div className="current-scan-host-results">

                  <section className="result-subpanel">
                    <div className="result-subpanel-header">
                      <div>
                        <p className="eyebrow">
                          ASSETS
                        </p>

                        <h3>
                          Discovered hosts
                        </h3>
                      </div>

                      <span className="panel-meta">
                        {hostsCount}
                      </span>
                    </div>

                    <HostTable
                      hosts={result.hosts}
                    />
                  </section>


                  {result.hosts.map((host) => (
                    <section
                      className="result-subpanel"
                      key={host.id}
                    >
                      <div className="result-subpanel-header">
                        <div>
                          <p className="eyebrow">
                            OPEN PORTS
                          </p>

                          <h3 className="mono">
                            {host.address}
                          </h3>

                          {host.hostname && (
                            <p className="muted">
                              {host.hostname}
                            </p>
                          )}
                        </div>

                        <StatusBadge
                          status={host.status}
                        />
                      </div>

                      <PortTable
                        ports={host.ports}
                      />
                    </section>
                  ))}

                </div>
              )}
            </div>


            {/* =================================================
                FINDINGS
               ================================================= */}

            <div
              className="tab-panel current-scan-tab-panel"
              role="tabpanel"
              id="panel-findings"
              aria-labelledby="tab-findings"
              hidden={tab !== 'findings'}
            >
              {findings.length === 0 ? (
                <StateBlock
                  kind="empty"
                  title="No vulnerabilities detected."
                >
                  No findings were returned by the
                  vulnerability detection stages for this scan.
                </StateBlock>
              ) : (
                <FindingsList
                  items={findings}
                />
              )}
            </div>

          </section>

        </>
      )}


      {/* =====================================================
          EMPTY STATE
         ===================================================== */}

      {!loading && !result && !error && (
        <section className="panel">
          <StateBlock
            kind="empty"
            title="No current scan selected."
            action={
              <button
                type="button"
                className="btn btn-primary btn-sm"
                onClick={() => onNavigate('new-scan')}
              >
                Start a new scan
              </button>
            }
          >
            Start a scan or open one from the scan history.
          </StateBlock>
        </section>
      )}

    </div>
  )
}

export default CurrentScanPage