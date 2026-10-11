import type { ScanResult } from '../types'
import { formatDate } from '../utils'

type ScanContextBarProps = {
  scan: ScanResult
  onChangeScan: () => void
}

function ScanContextBar({ scan, onChangeScan }: ScanContextBarProps) {
  return (
    <div className="context-bar">
      <span>
        Showing data from <strong className="mono">Scan #{scan.id}</strong>
        {' · '}
        {scan.target}
        {' · '}
        {formatDate(scan.completed_at ?? scan.started_at)}
      </span>

      <button
        type="button"
        className="btn btn-ghost btn-sm"
        onClick={onChangeScan}
      >
        Choose another scan
      </button>
    </div>
  )
}

export default ScanContextBar
