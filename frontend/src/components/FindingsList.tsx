import type { FlatFinding } from '../types'
import { formatDate, formatValue, getConfidence } from '../utils'
import SeverityBadge from './SeverityBadge'

type FindingsListProps = {
  items: FlatFinding[]
  /** Show affected host alongside port/service. */
  showHost?: boolean
}

function FindingsList({ items, showHost = true }: FindingsListProps) {
  return (
    <div className="findings" role="list">
      {items.map(({ finding, host, port }) => {
        const confidence = getConfidence(finding.risk_reason)

        const affected = [
          showHost ? host.address : null,
          `${port.port_number}/${port.protocol}`,
          port.service?.service_name ?? null,
        ]
          .filter(Boolean)
          .join(' · ')

        return (
          <details
            className="finding"
            key={`${host.id}-${port.id}-${finding.id}`}
            role="listitem"
          >
            <summary className="finding-summary">
              <SeverityBadge severity={finding.severity} />

              <span className="finding-title">
                <strong>{finding.title}</strong>
                <small>{affected}</small>
              </span>

              <span className="finding-id mono">
                {finding.vulnerability_id ?? '—'}
              </span>

              <span className="finding-cvss">
                <small>CVSS</small>
                {finding.cvss_score ?? '—'}
              </span>

              <span className="finding-source">{finding.source}</span>
            </summary>

            <div className="finding-body">
              <dl className="detail-grid">
                <div>
                  <dt>Risk</dt>
                  <dd>{formatValue(finding.risk_level)}</dd>
                </div>

                {confidence && (
                  <div>
                    <dt>Confidence</dt>
                    <dd>{confidence}</dd>
                  </div>
                )}

                <div>
                  <dt>CWE</dt>
                  <dd>{formatValue(finding.cwe_ids)}</dd>
                </div>

                <div>
                  <dt>Source</dt>
                  <dd>{finding.source}</dd>
                </div>

                {finding.matcher_name && (
                  <div>
                    <dt>Matcher</dt>
                    <dd>{finding.matcher_name}</dd>
                  </div>
                )}

                {finding.detected_at && (
                  <div>
                    <dt>Detected</dt>
                    <dd>{formatDate(finding.detected_at)}</dd>
                  </div>
                )}
              </dl>

              {finding.cvss_metrics && (
                <div className="detail-block">
                  <h4>CVSS metrics</h4>
                  <p className="mono">{finding.cvss_metrics}</p>
                </div>
              )}

              {finding.description && (
                <div className="detail-block">
                  <h4>Description</h4>
                  <p>{finding.description}</p>
                </div>
              )}

              {finding.risk_reason && (
                <div className="detail-block">
                  <h4>Risk classification</h4>
                  <p>{finding.risk_reason}</p>
                </div>
              )}

              {finding.evidence && (
                <div className="detail-block">
                  <h4>Evidence</h4>
                  <pre>{finding.evidence}</pre>
                </div>
              )}
            </div>
          </details>
        )
      })}
    </div>
  )
}

export default FindingsList
