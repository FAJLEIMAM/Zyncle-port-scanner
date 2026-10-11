import { normalizeSeverity } from '../utils'

type SeverityBadgeProps = {
  severity: string | null | undefined
}

function SeverityBadge({ severity }: SeverityBadgeProps) {
  const key = normalizeSeverity(severity)
  const label = severity ? severity.toUpperCase() : 'UNRATED'

  return (
    <span className={`severity-badge sev-${key}`}>{label}</span>
  )
}

export default SeverityBadge
