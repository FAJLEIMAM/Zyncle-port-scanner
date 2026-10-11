import type { Host } from '../types'
import StatusBadge from './StatusBadge'

type HostTableProps = {
  hosts: Host[]
}

function HostTable({ hosts }: HostTableProps) {
  return (
    <div className="table-wrapper">
      <table>
        <caption className="sr-only">Hosts</caption>

        <thead>
          <tr>
            <th scope="col">Address</th>
            <th scope="col">Hostname</th>
            <th scope="col">Status</th>
            <th scope="col" className="num">Ports</th>
          </tr>
        </thead>

        <tbody>
          {hosts.map((host) => (
            <tr key={host.id}>
              <td className="mono strong">{host.address}</td>
              <td>{host.hostname ?? '—'}</td>
              <td>
                <StatusBadge status={host.status} />
              </td>
              <td className="num">{host.ports.length}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

export default HostTable
