import type { SeverityKey } from '../types'
import { SEVERITY_LABELS, SEVERITY_ORDER } from '../utils'

type SeverityOverviewProps = {
  counts: Record<SeverityKey, number>
}

function SeverityOverview({ counts }: SeverityOverviewProps) {
  const total = SEVERITY_ORDER.reduce(
    (sum, key) => sum + counts[key],
    0,
  )

  const keys = SEVERITY_ORDER.filter(
    (key) => key !== 'other' || counts.other > 0,
  )

  return (
    <div className="severity-overview">
      <div className="severity-summary">

        <div>
          <span className="severity-summary-label">
            TOTAL FINDINGS
          </span>

          <strong>{total}</strong>

          <small>
            From latest completed scan
          </small>
        </div>

        <span
          className={`severity-summary-status ${
            total === 0 ? 'clear' : 'detected'
          }`}
        >
          {total === 0
            ? 'NO FINDINGS'
            : 'FINDINGS DETECTED'}
        </span>
      </div>

      {total === 0 ? (
        <div className="severity-empty">
          <div
            className="severity-empty-icon"
            aria-hidden="true"
          >
            ✓
          </div>

          <div>
            <strong>
              No vulnerabilities detected
            </strong>

            <span>
              The latest completed scan returned no
              vulnerability findings.
            </span>
          </div>
        </div>
      ) : (
        <>
          <div
            className="severity-bar"
            role="img"
            aria-label={`${total} findings by severity`}
          >
            {keys.map(
              (key) =>
                counts[key] > 0 && (
                  <span
                    key={key}
                    className={`sev-fill sev-${key}`}
                    style={{
                      flexGrow: counts[key],
                    }}
                  />
                ),
            )}
          </div>

          <ul className="severity-list">
            {keys.map((key) => (
              <li key={key}>
                <span
                  className={`sev-swatch sev-${key}`}
                  aria-hidden="true"
                />

                <span>
                  {SEVERITY_LABELS[key]}
                </span>

                <strong>
                  {counts[key]}
                </strong>
              </li>
            ))}
          </ul>
        </>
      )}
    </div>
  )
}

export default SeverityOverview