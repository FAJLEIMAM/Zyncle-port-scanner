import { useMemo, useState } from 'react'

import type {
  ScanHistoryItem,
} from '../types'

import {
  formatDate,
  getProfileLabel,
  getVulnerabilityProfileLabel,
} from '../utils'

import StateBlock from '../components/StateBlock'
import StatusBadge from '../components/StatusBadge'

type HistoryPageProps = {
  history: ScanHistoryItem[]
  historyLoading: boolean
  historyError: string
  onRefresh: () => void
  onView: (id: number) => void
  viewDisabled: boolean
}

type StatusFilter =
  | 'all'
  | 'completed'
  | 'failed'
  | 'running'

type ProfileFilter =
  | 'all'
  | 'common'
  | 'full'

type VulnerabilityFilter =
  | 'all'
  | 'lightweight'
  | 'full'

function HistoryPage({
  history,
  historyLoading,
  historyError,
  onRefresh,
  onView,
  viewDisabled,
}: HistoryPageProps) {
  const [search, setSearch] = useState('')

  const [statusFilter, setStatusFilter] =
    useState<StatusFilter>('all')

  const [profileFilter, setProfileFilter] =
    useState<ProfileFilter>('all')

  const [vulnerabilityFilter, setVulnerabilityFilter] =
    useState<VulnerabilityFilter>('all')

  const filteredHistory = useMemo(() => {
    const query = search
      .trim()
      .toLowerCase()

    return history.filter((scan) => {
      const matchesSearch =
        query.length === 0 ||
        String(scan.id).includes(query) ||
        scan.target.toLowerCase().includes(query)

      const matchesStatus =
        statusFilter === 'all' ||
        scan.status.toLowerCase() === statusFilter

      const matchesProfile =
        profileFilter === 'all' ||
        scan.profile === profileFilter

      const matchesVulnerability =
        vulnerabilityFilter === 'all' ||
        scan.vulnerability_profile ===
          vulnerabilityFilter

      return (
        matchesSearch &&
        matchesStatus &&
        matchesProfile &&
        matchesVulnerability
      )
    })
  }, [
    history,
    search,
    statusFilter,
    profileFilter,
    vulnerabilityFilter,
  ])

  const completedCount = history.filter(
    (scan) => scan.status === 'completed',
  ).length

  const failedCount = history.filter(
    (scan) => scan.status === 'failed',
  ).length

  const findingsTotal = history.reduce(
    (total, scan) =>
      total + scan.findings,
    0,
  )

  const clearFilters = () => {
    setSearch('')
    setStatusFilter('all')
    setProfileFilter('all')
    setVulnerabilityFilter('all')
  }

  const filtersActive =
    search.trim().length > 0 ||
    statusFilter !== 'all' ||
    profileFilter !== 'all' ||
    vulnerabilityFilter !== 'all'

  return (
    <div className="page history-page">

      {/* =====================================================
          PAGE HEADER
         ===================================================== */}

      <div className="page-heading history-heading">

        <div>
          <p className="eyebrow">
            ACTIVITY
          </p>

          <h1>
            Scan History
          </h1>

          <p>
            Review previous security assessments and
            open detailed scan results.
          </p>
        </div>

        <button
          type="button"
          className="refresh-button"
          onClick={onRefresh}
          disabled={historyLoading}
        >
          {historyLoading
            ? 'Refreshing...'
            : 'Refresh'}
        </button>

      </div>


      {/* =====================================================
          ERROR
         ===================================================== */}

      {historyError && (
        <div
          className="alert alert-error history-alert"
          role="alert"
        >
          <strong>
            Unable to load scan history.
          </strong>

          <span>
            {historyError}
          </span>
        </div>
      )}


      {/* =====================================================
          HISTORY SUMMARY
         ===================================================== */}

      <section
        className="history-summary"
        aria-label="History summary"
      >

        <div className="history-stat">
          <span>
            TOTAL SCANS
          </span>

          <strong>
            {history.length}
          </strong>
        </div>

        <div className="history-stat">
          <span>
            COMPLETED
          </span>

          <strong>
            {completedCount}
          </strong>
        </div>

        <div className="history-stat">
          <span>
            FAILED
          </span>

          <strong>
            {failedCount}
          </strong>
        </div>

        <div className="history-stat">
          <span>
            TOTAL FINDINGS
          </span>

          <strong>
            {findingsTotal}
          </strong>
        </div>

      </section>


      {/* =====================================================
          HISTORY TABLE
         ===================================================== */}

      <section
        className="panel history-panel"
        aria-labelledby="history-table-title"
      >

        <div className="panel-header history-panel-header">

          <div>
            <p className="eyebrow">
              SCAN RECORDS
            </p>

            <h2 id="history-table-title">
              Previous assessments
            </h2>

            <p className="helper">
              Search, filter and open individual scan results.
            </p>
          </div>

          <span className="panel-meta">
            {filteredHistory.length}
            {' '}
            {filteredHistory.length === 1
              ? 'scan'
              : 'scans'}
          </span>

        </div>


        {/* =================================================
            FILTERS
           ================================================= */}

        <div className="history-filters">

          <div className="history-search">

            <label htmlFor="history-search">
              Search
            </label>

            <input
              id="history-search"
              type="search"
              value={search}
              onChange={(event) =>
                setSearch(event.target.value)
              }
              placeholder="Search by scan ID or target..."
              autoComplete="off"
            />

          </div>


          <div className="history-filter">

            <label htmlFor="history-status">
              Status
            </label>

            <select
              id="history-status"
              value={statusFilter}
              onChange={(event) =>
                setStatusFilter(
                  event.target.value as StatusFilter,
                )
              }
            >
              <option value="all">
                All statuses
              </option>

              <option value="completed">
                Completed
              </option>

              <option value="failed">
                Failed
              </option>

              <option value="running">
                Running
              </option>
            </select>

          </div>


          <div className="history-filter">

            <label htmlFor="history-profile">
              Port profile
            </label>

            <select
              id="history-profile"
              value={profileFilter}
              onChange={(event) =>
                setProfileFilter(
                  event.target.value as ProfileFilter,
                )
              }
            >
              <option value="all">
                All profiles
              </option>

              <option value="common">
                Common Ports
              </option>

              <option value="full">
                Full Ports
              </option>
            </select>

          </div>


          <div className="history-filter">

            <label htmlFor="history-vulnerability">
              Vulnerability profile
            </label>

            <select
              id="history-vulnerability"
              value={vulnerabilityFilter}
              onChange={(event) =>
                setVulnerabilityFilter(
                  event.target.value as VulnerabilityFilter,
                )
              }
            >
              <option value="all">
                All profiles
              </option>

              <option value="lightweight">
                Lightweight
              </option>

              <option value="full">
                Full & Fast
              </option>
            </select>

          </div>


          {filtersActive && (
            <button
              type="button"
              className="history-clear-button"
              onClick={clearFilters}
            >
              Clear
            </button>
          )}

        </div>


        {/* =================================================
            LOADING
           ================================================= */}

        {historyLoading && history.length === 0 ? (
          <StateBlock
            kind="loading"
            title="Loading scan history..."
          />
        ) : history.length === 0 ? (

          <StateBlock
            kind="empty"
            title="No scan history available."
          >
            Start a new scan to create your first
            assessment record.
          </StateBlock>

        ) : filteredHistory.length === 0 ? (

          <StateBlock
            kind="empty"
            title="No scans match your filters."
          >
            Try a different search or clear the
            active filters.
          </StateBlock>

        ) : (

          /* =================================================
             TABLE
             ================================================= */

          <div className="history-table-wrapper">

            <table className="history-table">

              <thead>
                <tr>
                  <th>
                    SCAN
                  </th>

                  <th>
                    TARGET
                  </th>

                  <th>
                    PORT PROFILE
                  </th>

                  <th>
                    VULNERABILITY
                  </th>

                  <th>
                    STATUS
                  </th>

                  <th>
                    STARTED
                  </th>

                  <th>
                    COMPLETED
                  </th>

                  <th className="history-number">
                    HOSTS
                  </th>

                  <th className="history-number">
                    PORTS
                  </th>

                  <th className="history-number">
                    FINDINGS
                  </th>

                  <th>
                    ACTION
                  </th>
                </tr>
              </thead>

              <tbody>

                {filteredHistory.map((scan) => (
                  <tr key={scan.id}>

                    <td>
                      <strong className="history-scan-id">
                        #{scan.id}
                      </strong>
                    </td>


                    <td>
                      <span
                        className="history-target"
                        title={scan.target}
                      >
                        {scan.target}
                      </span>
                    </td>


                    <td>
                      <span className="history-profile">
                        {getProfileLabel(
                          scan.profile,
                        )}
                      </span>
                    </td>


                    <td>
                      <span className="history-profile">
                        {getVulnerabilityProfileLabel(
                          scan.vulnerability_profile,
                        )}
                      </span>
                    </td>


                    <td>
                      <StatusBadge
                        status={scan.status}
                      />
                    </td>


                    <td>
                      <span className="history-date">
                        {formatDate(
                          scan.started_at,
                        )}
                      </span>
                    </td>


                    <td>
                      <span className="history-date">
                        {formatDate(
                          scan.completed_at,
                        )}
                      </span>
                    </td>


                    <td className="history-number">
                      {scan.hosts}
                    </td>


                    <td className="history-number">
                      {scan.open_ports}
                    </td>


                    <td className="history-number">
                      <strong
                        className={
                          scan.findings > 0
                            ? 'history-findings has-findings'
                            : 'history-findings'
                        }
                      >
                        {scan.findings}
                      </strong>
                    </td>


                    <td>
                      <button
                        type="button"
                        className="history-view-button"
                        disabled={viewDisabled}
                        onClick={() =>
                          onView(scan.id)
                        }
                      >
                        View
                      </button>
                    </td>

                  </tr>
                ))}

              </tbody>

            </table>

          </div>

        )}

      </section>

    </div>
  )
}

export default HistoryPage