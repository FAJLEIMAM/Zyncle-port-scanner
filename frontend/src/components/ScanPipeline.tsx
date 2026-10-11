import type { VulnerabilityProfile } from '../types'
import {
  getStatusClass,
  getVulnerabilityProfileLabel,
} from '../utils'
import StatusBadge from './StatusBadge'

type PipelineStage = {
  name: string
  role: string
}

const STAGES: PipelineStage[] = [
  { name: 'Naabu', role: 'Port discovery' },
  { name: 'Nmap', role: 'Service & version detection' },
  { name: 'NVD', role: 'CVE correlation' },
  { name: 'Nuclei', role: 'Template-based detection' },
  { name: 'Greenbone', role: 'Vulnerability assessment' },
]

type ScanPipelineProps = {
  /** Overall scan status reported by the backend, if any. */
  status?: string | null
  vulnerabilityProfile?: VulnerabilityProfile | null
}

/**
 * The backend exposes only an overall scan status. Individual stage
 * state is NOT reported, so stages are shown as the expected workflow
 * and never as active / done / failed.
 */
function ScanPipeline({
  status,
  vulnerabilityProfile,
}: ScanPipelineProps) {
  return (
    <section className="panel" aria-labelledby="pipeline-title">
      <div className="panel-header">
        <div>
          <p className="eyebrow">Workflow</p>
          <h2 id="pipeline-title">Scan pipeline</h2>
        </div>

        {status && (
          <div className="pipeline-status">
            <span>Overall status</span>
            <StatusBadge status={getStatusClass(status)} />
          </div>
        )}
      </div>

      <ol className="pipeline">
        {STAGES.map((stage, index) => (
          <li key={stage.name} className="pipeline-stage">
            <span className="pipeline-index" aria-hidden="true">
              {index + 1}
            </span>

            <div>
              <strong>{stage.name}</strong>
              <span>{stage.role}</span>

              {stage.name === 'Greenbone' &&
                vulnerabilityProfile && (
                  <em>
                    Profile:{' '}
                    {getVulnerabilityProfileLabel(
                      vulnerabilityProfile,
                    )}
                  </em>
                )}
            </div>
          </li>
        ))}
      </ol>

      <p className="note">
        Expected workflow. The backend reports only the overall scan
        status, so per-stage progress is not shown.
      </p>
    </section>
  )
}

export default ScanPipeline
