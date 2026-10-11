import type { ApiState } from '../types'
import Icon from './Icon'

type TopbarProps = {
  title: string
  subtitle: string
  apiState: ApiState
  scanActive: boolean
  onOpenCurrentScan: () => void
}

const API_LABELS: Record<ApiState, string> = {
  checking: 'Checking API',
  online: 'API connected',
  offline: 'API unreachable',
}

function Topbar({
  title,
  subtitle,
  apiState,
  scanActive,
  onOpenCurrentScan,
}: TopbarProps) {
  return (
    <header className="topbar">
      <div>
        <h1>{title}</h1>
        <p>{subtitle}</p>
      </div>

      <div className="topbar-actions">
        {scanActive && (
          <button
            type="button"
            className="btn btn-ghost btn-sm scan-chip"
            onClick={onOpenCurrentScan}
          >
            <span className="live-dot" aria-hidden="true" />
            Scan in progress
            <Icon name="arrow" size={14} />
          </button>
        )}

        <span className={`api-pill api-${apiState}`}>
          <span className="api-dot" aria-hidden="true" />
          {API_LABELS[apiState]}
        </span>
      </div>
    </header>
  )
}

export default Topbar
