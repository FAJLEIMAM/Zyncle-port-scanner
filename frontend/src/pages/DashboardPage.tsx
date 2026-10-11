import type {
  ActiveSection,
  ScanHistoryItem,
  ScanResult,
} from '../types'

import {
  countBySeverity,
  flattenFindings,
  formatDate,
  getProfileLabel,
  getVulnerabilityProfileLabel,
} from '../utils'

import Icon from '../components/Icon'
import ScanTable from '../components/ScanTable'
import SeverityOverview from '../components/SeverityOverview'
import StateBlock from '../components/StateBlock'
import StatusBadge from '../components/StatusBadge'
import SummaryCard from '../components/SummaryCard'

type DashboardPageProps = {
  history: ScanHistoryItem[]
  historyLoading: boolean
  historyError: string
  onRefresh: () => void
  latestScan: ScanResult | null
  latestLoading: boolean
  latestError: string
  scanActive: boolean
  canViewCurrent: boolean
  canViewVulnerabilities: boolean
  onNavigate: (section: ActiveSection) => void
  onView: (id: number) => void
}

function DashboardPage({
  history,
  historyLoading,
  historyError,
  onRefresh,
  latestScan,
  latestLoading,
  latestError,
  scanActive,
  canViewCurrent,
  canViewVulnerabilities,
  onNavigate,
  onView,
}: DashboardPageProps) {
  const completed = history.filter(
    (scan) => scan.status === 'completed',
  )

  const latestCompleted = completed[0] ?? null

  const historyCapped = history.length >= 50

  const findings = flattenFindings(latestScan)

  const severityCounts = countBySeverity(findings)

  const initialLoad =
    historyLoading && history.length === 0

  const totalScans = history.length

  const completedScans = completed.length

  const totalOpenPorts =
    latestScan?.hosts.reduce(
      (total, host) =>
        total + host.ports.length,
      0,
    ) ?? 0

  const totalFindings =
    latestScan?.hosts.reduce(
      (total, host) =>
        total +
        host.ports.reduce(
          (portTotal, port) =>
            portTotal + port.findings.length,
          0,
        ),
      0,
    ) ?? 0

  /*
   * ==========================================================
   * INITIAL LOADING
   * ==========================================================
   */

  if (initialLoad) {
    return (
      <div className="page dashboard-page">

        <div className="page-heading">
          <div>
            <p className="eyebrow">
              OVERVIEW
            </p>

            <h1>
              Security Dashboard
            </h1>

            <p>
              Security posture across your recent scans.
            </p>
          </div>
        </div>

        <section className="panel">
          <StateBlock
            kind="loading"
            title="Loading dashboard..."
          />
        </section>

      </div>
    )
  }

  /*
   * ==========================================================
   * PAGE
   * ==========================================================
   */

  return (
    <div className="page dashboard-page">

      {/* =====================================================
          PAGE HEADER
      ====================================================== */}

      <div className="page-heading">

        <div>
          <p className="eyebrow">
            OVERVIEW
          </p>

          <h1>
            Security Dashboard
          </h1>

          <p>
            Monitor scans, exposed services and
            vulnerability findings from one workspace.
          </p>
        </div>

        <button
          type="button"
          className="refresh-button"
          onClick={onRefresh}
          disabled={historyLoading}
        >
          <Icon name="refresh" />

          {historyLoading
            ? 'Refreshing...'
            : 'Refresh'}
        </button>

      </div>

      {/* =====================================================
          HISTORY ERROR
      ====================================================== */}

      {historyError && (
        <div className="alert alert-error">

          <strong>
            Unable to refresh scan history.
          </strong>

          <span>
            {historyError}
          </span>

        </div>
      )}

      {/* =====================================================
          SUMMARY CARDS
      ====================================================== */}

      <section
        className="overview-grid"
        aria-label="Security summary"
      >

        <SummaryCard
          label="Total scans"
          value={
            historyCapped
              ? '50+'
              : totalScans
          }
        />

        <SummaryCard
          label="Completed scans"
          value={completedScans}
        />

        <SummaryCard
          label="Open ports"
          value={totalOpenPorts}
        />

        <SummaryCard
          label="Findings"
          value={totalFindings}
        />

      </section>

      {/* =====================================================
          MAIN DASHBOARD GRID
      ====================================================== */}

      <div className="dashboard-grid">

        {/* ===================================================
            VULNERABILITY INTELLIGENCE
        ==================================================== */}

        <section
          className="panel dashboard-panel severity-panel"
          aria-labelledby="severity-title"
        >

          <div className="panel-header">

            <div>
              <p className="eyebrow">
                VULNERABILITY INTELLIGENCE
              </p>

              <h2 id="severity-title">
                Severity overview
              </h2>

              <p className="helper">
                Findings from the latest completed scan.
              </p>
            </div>

            {latestCompleted && (
              <span className="panel-meta">
                Scan #{latestCompleted.id}
              </span>
            )}

          </div>

          {/* -------------------------------------------------
              IMPORTANT:
              SeverityOverview must render even when
              findings = 0.
              It handles the "NO FINDINGS" state itself.
          -------------------------------------------------- */}

          {latestLoading ? (
            <StateBlock
              kind="loading"
              title="Loading findings..."
            />
          ) : latestError && !latestScan ? (
            <StateBlock
              kind="error"
              title="Unable to load findings."
            >
              {latestError}
            </StateBlock>
          ) : !latestScan ? (
            <StateBlock
              kind="empty"
              title="No completed scan available."
            />
          ) : (
            <SeverityOverview
              counts={severityCounts}
            />
          )}

        </section>

        {/* ===================================================
            LATEST SCAN
        ==================================================== */}

        <section
          className="panel dashboard-panel latest-scan-panel"
          aria-labelledby="latest-scan-title"
        >

          <div className="panel-header">

            <div>
              <p className="eyebrow">
                LATEST SCAN
              </p>

              <h2 id="latest-scan-title">
                {latestScan
                  ? `Scan #${latestScan.id}`
                  : 'Latest assessment'}
              </h2>
            </div>

            {latestScan && (
              <StatusBadge
                status={latestScan.status}
              />
            )}

          </div>

          {latestLoading ? (
            <StateBlock
              kind="loading"
              title="Loading latest scan..."
            />
          ) : latestError && !latestScan ? (
            <StateBlock
              kind="error"
              title="Unable to load latest scan."
            >
              {latestError}
            </StateBlock>
          ) : !latestScan ? (
            <StateBlock
              kind="empty"
              title="No completed scan available."
            />
          ) : (
            <>

              <div className="latest-scan-grid">

                <div>
                  <span>
                    TARGET
                  </span>

                  <strong
                    className="value-wrap"
                    title={latestScan.target}
                  >
                    {latestScan.target}
                  </strong>
                </div>

                <div>
                  <span>
                    SCAN ID
                  </span>

                  <strong>
                    #{latestScan.id}
                  </strong>
                </div>

                <div>
                  <span>
                    PORT PROFILE
                  </span>

                  <strong>
                    {getProfileLabel(
                      latestScan.profile,
                    )}
                  </strong>
                </div>

                <div>
                  <span>
                    VULNERABILITY PROFILE
                  </span>

                  <strong>
                    {getVulnerabilityProfileLabel(
                      latestScan.vulnerability_profile,
                    )}
                  </strong>
                </div>

                <div>
                  <span>
                    STARTED
                  </span>

                  <strong>
                    {formatDate(
                      latestScan.started_at,
                    )}
                  </strong>
                </div>

                <div>
                  <span>
                    COMPLETED
                  </span>

                  <strong>
                    {formatDate(
                      latestScan.completed_at,
                    )}
                  </strong>
                </div>

                <div>
                  <span>
                    HOSTS
                  </span>

                  <strong>
                    {latestScan.hosts.length}
                  </strong>
                </div>

                <div>
                  <span>
                    OPEN PORTS
                  </span>

                  <strong>
                    {totalOpenPorts}
                  </strong>
                </div>

                <div>
                  <span>
                    FINDINGS
                  </span>

                  <strong>
                    {totalFindings}
                  </strong>
                </div>

              </div>

              <div className="latest-scan-actions">

                <button
                  type="button"
                  onClick={() =>
                    onView(latestScan.id)
                  }
                >
                  View scan
                </button>

                {canViewVulnerabilities && (
                  <button
                    type="button"
                    onClick={() =>
                      onNavigate(
                        'vulnerabilities',
                      )
                    }
                  >
                    View vulnerabilities
                  </button>
                )}

                <button
                  type="button"
                  onClick={() =>
                    onNavigate('assets')
                  }
                >
                  View assets
                </button>

              </div>

            </>
          )}

        </section>

      </div>

      {/* =====================================================
          QUICK ACTIONS
      ====================================================== */}

      <section
        className="panel quick-actions-panel"
        aria-labelledby="quick-actions-title"
      >

        <div className="panel-header">

          <div>
            <p className="eyebrow">
              SHORTCUTS
            </p>

            <h2 id="quick-actions-title">
              Quick actions
            </h2>

            <p className="helper">
              Launch a scan or inspect existing security data.
            </p>
          </div>

        </div>

        <div className="quick-actions">

          <button
            type="button"
            className="quick-action-primary"
            onClick={() =>
              onNavigate('new-scan')
            }
            disabled={scanActive}
          >
            <Icon name="plus" />

            <span>
              {scanActive
                ? 'Scan in progress'
                : 'Start new scan'}
            </span>
          </button>

          <button
            type="button"
            disabled={!canViewCurrent}
            onClick={() =>
              onNavigate('current-scan')
            }
          >
            <Icon name="activity" />

            <span>
              View current scan
            </span>
          </button>

          <button
            type="button"
            onClick={() =>
              onNavigate('history')
            }
          >
            <Icon name="history" />

            <span>
              View history
            </span>
          </button>

          <button
            type="button"
            disabled={!canViewVulnerabilities}
            onClick={() =>
              onNavigate('vulnerabilities')
            }
          >
            <Icon name="shield" />

            <span>
              View vulnerabilities
            </span>
          </button>

        </div>

      </section>

      {/* =====================================================
          RECENT SCANS
      ====================================================== */}

      <section
        className="panel recent-scans-panel"
        aria-labelledby="recent-scans-title"
      >

        <div className="panel-header">

          <div>
            <p className="eyebrow">
              ACTIVITY
            </p>

            <h2 id="recent-scans-title">
              Recent scans
            </h2>

            <p className="helper">
              Latest scan activity returned by the API.
            </p>
          </div>

          <button
            type="button"
            className="refresh-button"
            onClick={onRefresh}
            disabled={historyLoading}
          >
            <Icon name="refresh" />

            Refresh
          </button>

        </div>

        {history.length === 0 ? (
          <StateBlock
            kind="empty"
            title="No scans recorded yet."
          >
            Start a new scan to populate your
            security activity.
          </StateBlock>
        ) : (
          <ScanTable
            scans={history.slice(0, 8)}
            onView={onView}
            viewDisabled={scanActive}
          />
        )}

      </section>

    </div>
  )
}

export default DashboardPage