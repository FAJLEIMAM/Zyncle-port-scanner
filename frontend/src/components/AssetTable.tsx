import type { Host } from '../types'
import { normalizeSeverity, SEVERITY_ORDER } from '../utils'
import SeverityBadge from './SeverityBadge'
import StatusBadge from './StatusBadge'

type AssetTableProps = {
  hosts: Host[]
}

function AssetTable({ hosts }: AssetTableProps) {
  return (
    <div className="table-wrapper">
      <table>
        <caption className="sr-only">Asset inventory</caption>

        <thead>
          <tr>
            <th scope="col">Address</th>
            <th scope="col">Hostname</th>
            <th scope="col">Status</th>
            <th scope="col">Open ports</th>
            <th scope="col">Services</th>
            <th scope="col" className="num">Findings</th>
            <th scope="col">Highest severity</th>
          </tr>
        </thead>

        <tbody>
          {hosts.map((host) => {
            const findings = host.ports.flatMap(
              (port) => port.findings,
            )

            const services = Array.from(
              new Set(
                host.ports
                  .map((port) => port.service?.service_name)
                  .filter((name): name is string => !!name),
              ),
            )

            const highest = findings.reduce<string | null>(
              (best, finding) => {
                if (!best) {
                  return finding.severity
                }

                return SEVERITY_ORDER.indexOf(
                  normalizeSeverity(finding.severity),
                ) < SEVERITY_ORDER.indexOf(normalizeSeverity(best))
                  ? finding.severity
                  : best
              },
              null,
            )

            return (
              <tr key={host.id}>
                <td className="mono strong">{host.address}</td>
                <td>{host.hostname ?? '—'}</td>
                <td>
                  <StatusBadge status={host.status} />
                </td>
                <td>
                  <div className="chips">
                    {host.ports.map((port) => (
                      <span className="chip mono" key={port.id}>
                        {port.port_number}/{port.protocol}
                      </span>
                    ))}

                    {host.ports.length === 0 && '—'}
                  </div>
                </td>
                <td>
                  <div className="chips">
                    {services.map((name) => (
                      <span className="chip" key={name}>
                        {name}
                      </span>
                    ))}

                    {services.length === 0 && '—'}
                  </div>
                </td>
                <td className="num">{findings.length}</td>
                <td>
                  {findings.length > 0 ? (
                    <SeverityBadge severity={highest} />
                  ) : (
                    '—'
                  )}
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}

export default AssetTable
