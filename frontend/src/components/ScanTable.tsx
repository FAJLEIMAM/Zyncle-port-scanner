import type { ScanHistoryItem } from '../types'
import {
  formatDate,
  getProfileLabel,
  getVulnerabilityProfileLabel,
} from '../utils'
import StatusBadge from './StatusBadge'

type ScanTableProps = {
  scans: ScanHistoryItem[]
  onView: (id: number) => void
  viewDisabled: boolean
  /** Compact layout used on the dashboard. */
  compact?: boolean
}

function ScanTable({
  scans,
  onView,
  viewDisabled,
  compact = false,
}: ScanTableProps) {
  return (
    <div className="table-wrapper">
      <table>
        <caption className="sr-only">Scan history</caption>

        <thead>
          <tr>
            <th scope="col">Scan ID</th>
            <th scope="col">Target</th>
            <th scope="col">Profile</th>
            {!compact && <th scope="col">Vulnerability</th>}
            <th scope="col">Status</th>
            <th scope="col">Started</th>
            {!compact && <th scope="col">Completed</th>}
            <th scope="col" className="num">Hosts</th>
            <th scope="col" className="num">Ports</th>
            <th scope="col" className="num">Findings</th>
            <th scope="col">
              <span className="sr-only">Action</span>
            </th>
          </tr>
        </thead>

        <tbody>
          {scans.map((scan) => (
            <tr key={scan.id}>
              <td className="mono">#{scan.id}</td>
              <td className="cell-target" title={scan.target}>
                {scan.target}
              </td>
              <td>{getProfileLabel(scan.profile)}</td>
              {!compact && (
                <td>
                  {getVulnerabilityProfileLabel(
                    scan.vulnerability_profile,
                  )}
                </td>
              )}
              <td>
                <StatusBadge status={scan.status} />
              </td>
              <td className="nowrap">
                {formatDate(scan.started_at)}
              </td>
              {!compact && (
                <td className="nowrap">
                  {formatDate(scan.completed_at)}
                </td>
              )}
              <td className="num">{scan.hosts}</td>
              <td className="num">{scan.open_ports}</td>
              <td className="num">{scan.findings}</td>
              <td className="action-cell">
                <button
                  type="button"
                  className="btn btn-sm"
                  onClick={() => onView(scan.id)}
                  disabled={viewDisabled}
                  aria-label={`View scan ${scan.id}`}
                >
                  View
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

export default ScanTable
