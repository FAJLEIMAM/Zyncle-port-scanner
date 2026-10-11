import type { ScanProfile, VulnerabilityProfile } from '../types'
import {
  API_BASE_URL,
  POLL_INTERVAL_MS,
} from '../api'
import {
  getProfileLabel,
  getVulnerabilityProfileLabel,
} from '../utils'
import type { ApiState } from '../types'

type SettingsPageProps = {
  apiState: ApiState
  historyCount: number
  profile: ScanProfile
  vulnerabilityProfile: VulnerabilityProfile
}

const API_LABELS: Record<ApiState, string> = {
  checking: 'Checking…',
  online: 'Connected',
  offline: 'Unreachable',
}

type RowProps = {
  label: string
  value: string
  note?: string
  mono?: boolean
}

function Row({ label, value, note, mono }: RowProps) {
  return (
    <div className="settings-row">
      <div>
        <dt>{label}</dt>
        {note && <small>{note}</small>}
      </div>
      <dd className={mono ? 'mono' : undefined}>{value}</dd>
    </div>
  )
}

function SettingsPage({
  apiState,
  historyCount,
  profile,
  vulnerabilityProfile,
}: SettingsPageProps) {
  return (
    <div className="page">
      <section className="panel">
        <div className="panel-header">
          <div>
            <p className="eyebrow">Connection</p>
            <h2>Backend API</h2>
          </div>
        </div>

        <dl className="settings-list">
          <Row label="API endpoint" value={API_BASE_URL} mono />
          <Row label="Status" value={API_LABELS[apiState]} />
          <Row
            label="Status polling interval"
            value={`${POLL_INTERVAL_MS / 1000} seconds`}
            note="Used while a scan is running"
          />
          <Row
            label="Scans loaded"
            value={String(historyCount)}
            note="The API returns the 50 most recent scans"
          />
        </dl>
      </section>

      <section className="panel">
        <div className="panel-header">
          <div>
            <p className="eyebrow">Scan defaults</p>
            <h2>Current selections</h2>
          </div>
        </div>

        <dl className="settings-list">
          <Row
            label="Port scan profile"
            value={getProfileLabel(profile)}
            note="Change on the New Scan page"
          />
          <Row
            label="Vulnerability profile"
            value={getVulnerabilityProfileLabel(vulnerabilityProfile)}
            note="Change on the New Scan page"
          />
        </dl>
      </section>

      <section className="panel">
        <div className="panel-header">
          <div>
            <p className="eyebrow">Scanner engine</p>
            <h2>Detection pipeline</h2>
          </div>
        </div>

        <dl className="settings-list">
          <Row label="Port discovery" value="Naabu" />
          <Row label="Service detection" value="Nmap" />
          <Row label="CVE correlation" value="NVD" />
          <Row label="Template detection" value="Nuclei" />
          <Row label="Vulnerability assessment" value="Greenbone" />
        </dl>

        <p className="note">
          Scanner tools, API keys and credentials are configured on the
          server and are not exposed or editable from this interface.
        </p>
      </section>
    </div>
  )
}

export default SettingsPage
