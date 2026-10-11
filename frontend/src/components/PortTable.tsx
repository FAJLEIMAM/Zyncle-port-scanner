import type { Port } from '../types'
import { formatValue } from '../utils'

type PortTableProps = {
  ports: Port[]
}

function PortTable({ ports }: PortTableProps) {
  const hasBanner = ports.some((port) => port.service?.banner)

  if (ports.length === 0) {
    return (
      <p className="note">No ports were recorded for this host.</p>
    )
  }

  return (
    <div className="table-wrapper">
      <table>
        <caption className="sr-only">Ports</caption>

        <thead>
          <tr>
            <th scope="col">Port</th>
            <th scope="col">Protocol</th>
            <th scope="col">State</th>
            <th scope="col">Service</th>
            <th scope="col">Product</th>
            <th scope="col">Version</th>
            <th scope="col">Confidence</th>
            {hasBanner && <th scope="col">Banner</th>}
            <th scope="col" className="num">Findings</th>
          </tr>
        </thead>

        <tbody>
          {ports.map((port) => (
            <tr key={port.id}>
              <td className="mono strong">{port.port_number}</td>
              <td className="upper">{port.protocol}</td>
              <td>
                <span className="state-tag">{port.state}</span>
              </td>
              <td>{port.service?.service_name ?? '—'}</td>
              <td>
                {port.service?.product ?? '—'}
                {port.service?.cpe && (
                  <small className="cell-sub mono">
                    {port.service.cpe}
                  </small>
                )}
              </td>
              <td>{port.service?.version ?? '—'}</td>
              <td>
                {port.service?.confidence != null
                  ? formatValue(port.service.confidence)
                  : '—'}
              </td>
              {hasBanner && (
                <td>
                  {port.service?.banner ? (
                    <code
                      className="cell-clip"
                      title={port.service.banner}
                    >
                      {port.service.banner}
                    </code>
                  ) : (
                    '—'
                  )}
                </td>
              )}
              <td className="num">{port.findings.length}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

export default PortTable
