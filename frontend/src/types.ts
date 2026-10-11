export type ScanProfile = 'common' | 'full'

export type VulnerabilityProfile = 'lightweight' | 'full'

export type ActiveSection =
  | 'dashboard'
  | 'new-scan'
  | 'current-scan'
  | 'history'
  | 'vulnerabilities'
  | 'assets'
  | 'settings'

export type ApiState = 'checking' | 'online' | 'offline'

export type Finding = {
  id: number
  title: string
  description: string | null
  matcher_name: string | null
  severity: string | null
  cvss_score: number | null
  cwe_ids: string | null
  cvss_metrics: string | null
  risk_level: string | null
  risk_reason: string | null
  source: string
  vulnerability_id: string | null
  evidence: string | null
  detected_at?: string | null
}

export type Service = {
  service_name: string | null
  product: string | null
  version: string | null
  cpe: string | null
  confidence?: number | null
  banner?: string | null
}

export type Port = {
  id: number
  port_number: number
  protocol: string
  state: string
  service: Service | null
  findings: Finding[]
}

export type Host = {
  id: number
  address: string
  hostname: string | null
  status: string
  ports: Port[]
}

export type ScanResult = {
  id: number
  target: string
  profile: ScanProfile
  vulnerability_profile: VulnerabilityProfile
  status: string
  started_at: string | null
  completed_at: string | null
  error_message: string | null
  hosts: Host[]
}

export type ScanCreateResponse = {
  id: number
  target: string
  profile: ScanProfile
  vulnerability_profile: VulnerabilityProfile
  status: string
  started_at: string | null
  completed_at: string | null
}

export type ScanHistoryItem = {
  id: number
  target: string
  profile: ScanProfile
  vulnerability_profile: VulnerabilityProfile
  status: string
  started_at: string | null
  completed_at: string | null
  error_message: string | null
  hosts: number
  open_ports: number
  services: number
  findings: number
}

export type ScanCreatePayload = {
  target: string
  profile: ScanProfile
  vulnerability_profile: VulnerabilityProfile
}

/** A finding together with the host and port it was detected on. */
export type FlatFinding = {
  finding: Finding
  host: Host
  port: Port
}

export type SeverityKey =
  | 'critical'
  | 'high'
  | 'medium'
  | 'low'
  | 'other'
