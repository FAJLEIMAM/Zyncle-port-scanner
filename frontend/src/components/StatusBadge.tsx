import { getStatusClass } from '../utils'

const LABELS: Record<string, string> = {
  starting: 'Starting',
  loading: 'Loading',
  pending: 'Pending',
  running: 'Running',
  completed: 'Completed',
  failed: 'Failed',
  up: 'Up',
  down: 'Down',
  open: 'Open',
}

type StatusBadgeProps = {
  status: string
}

function StatusBadge({ status }: StatusBadgeProps) {
  const key = getStatusClass(status)
  const label = LABELS[key] ?? status

  return (
    <span className={`status-badge status-${key}`}>
      <span className="status-dot" aria-hidden="true" />
      {label}
    </span>
  )
}

export default StatusBadge
