import type {
  FlatFinding,
  ScanProfile,
  ScanResult,
  SeverityKey,
  VulnerabilityProfile,
} from './types'

export const sleep = (ms: number) =>
  new Promise((resolve) => setTimeout(resolve, ms))

export const formatValue = (
  value: string | number | null | undefined,
) => {
  if (value === null || value === undefined || value === '') {
    return 'Not reported'
  }

  return String(value)
}

export const formatDate = (value: string | null) => {
  if (!value) {
    return 'Not available'
  }

  const date = new Date(value)

  if (Number.isNaN(date.getTime())) {
    return value
  }

  return date.toLocaleString()
}

export const getStatusClass = (status: string) =>
  status.toLowerCase().replace(/\s+/g, '-')

export const getProfileLabel = (profile: ScanProfile) =>
  profile === 'full' ? 'Full Ports' : 'Common Ports'

export const getVulnerabilityProfileLabel = (
  value: VulnerabilityProfile,
) => (value === 'full' ? 'Full & Fast' : 'Lightweight')

export const getConfidence = (riskReason: string | null) => {
  if (!riskReason) {
    return null
  }

  const match = riskReason.match(/confidence:\s*(\d+)/i)

  return match?.[1] ?? null
}

// ------------------------------------------------------------
// Aggregation helpers (all derived from real scan data)
// ------------------------------------------------------------

export const countPorts = (scan: ScanResult) =>
  scan.hosts.reduce((t, h) => t + h.ports.length, 0)

export const countServices = (scan: ScanResult) =>
  scan.hosts.reduce(
    (t, h) => t + h.ports.filter((p) => p.service !== null).length,
    0,
  )

export const flattenFindings = (
  scan: ScanResult | null,
): FlatFinding[] =>
  scan
    ? scan.hosts.flatMap((host) =>
        host.ports.flatMap((port) =>
          port.findings.map((finding) => ({
            finding,
            host,
            port,
          })),
        ),
      )
    : []

export const SEVERITY_ORDER: SeverityKey[] = [
  'critical',
  'high',
  'medium',
  'low',
  'other',
]

export const SEVERITY_LABELS: Record<SeverityKey, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  other: 'Unrated',
}

export const normalizeSeverity = (
  severity: string | null | undefined,
): SeverityKey => {
  const value = (severity ?? '').trim().toLowerCase()

  if (
    value === 'critical' ||
    value === 'high' ||
    value === 'medium' ||
    value === 'low'
  ) {
    return value
  }

  return 'other'
}

export const severityRank = (
  severity: string | null | undefined,
) => 4 - SEVERITY_ORDER.indexOf(normalizeSeverity(severity))

export const countBySeverity = (
  items: FlatFinding[],
): Record<SeverityKey, number> => {
  const counts: Record<SeverityKey, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    other: 0,
  }

  for (const item of items) {
    counts[normalizeSeverity(item.finding.severity)] += 1
  }

  return counts
}

export const isActiveStatus = (status: string) =>
  ['pending', 'running', 'starting'].includes(
    status.toLowerCase(),
  )

// ------------------------------------------------------------
// Export helpers (behaviour preserved from the original UI)
// ------------------------------------------------------------

const downloadFile = (
  content: string,
  filename: string,
  mimeType: string,
) => {
  const blob = new Blob([content], { type: mimeType })
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')

  link.href = url
  link.download = filename

  document.body.appendChild(link)
  link.click()
  link.remove()

  URL.revokeObjectURL(url)
}

const escapeCsv = (value: string) =>
  `"${value.replace(/"/g, '""')}"`

export const exportJson = (result: ScanResult) => {
  downloadFile(
    JSON.stringify(result, null, 2),
    `zyncle-scan-${result.id}.json`,
    'application/json',
  )
}

export const exportCsv = (result: ScanResult) => {
  const rows: string[][] = [
    [
      'Scan ID',
      'Target',
      'Profile',
      'Vulnerability Profile',
      'Host',
      'Hostname',
      'Port',
      'Protocol',
      'State',
      'Service',
      'Product',
      'Version',
      'CPE',
      'Confidence',
      'Finding',
      'Severity',
      'Risk',
      'CVE',
      'CVSS',
      'CWE',
      'Source',
      'Evidence',
    ],
  ]

  for (const host of result.hosts) {
    for (const port of host.ports) {
      const findings =
        port.findings.length > 0 ? port.findings : [null]

      for (const finding of findings) {
        rows.push([
          String(result.id),
          result.target,
          result.profile,
          result.vulnerability_profile,
          host.address,
          host.hostname ?? '',
          String(port.port_number),
          port.protocol,
          port.state,
          port.service?.service_name ?? '',
          port.service?.product ?? '',
          port.service?.version ?? '',
          port.service?.cpe ?? '',
          port.service?.confidence != null
            ? String(port.service.confidence)
            : '',
          finding?.title ?? '',
          finding?.severity ?? '',
          finding?.risk_level ?? '',
          finding?.vulnerability_id ?? '',
          finding?.cvss_score != null
            ? String(finding.cvss_score)
            : '',
          finding?.cwe_ids ?? '',
          finding?.source ?? '',
          finding?.evidence ?? '',
        ])
      }
    }
  }

  const csv = rows
    .map((row) => row.map(escapeCsv).join(','))
    .join('\n')

  downloadFile(
    csv,
    `zyncle-scan-${result.id}.csv`,
    'text/csv;charset=utf-8',
  )
}

export const exportPdf = () => {
  window.print()
}
