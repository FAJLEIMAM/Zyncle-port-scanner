import type { ScanResult } from '../types'
import AssetTable from '../components/AssetTable'
import ScanContextBar from '../components/ScanContextBar'
import StateBlock from '../components/StateBlock'
import SummaryCard from '../components/SummaryCard'
import { countPorts, countServices, flattenFindings } from '../utils'

type AssetsPageProps = {
  scan: ScanResult | null
  loading: boolean
  error: string
  onChangeScan: () => void
}

function AssetsPage({
  scan,
  loading,
  error,
  onChangeScan,
}: AssetsPageProps) {
  if (loading && !scan) {
    return (
      <div className="page">
        <StateBlock kind="loading" title="Loading assets…" />
      </div>
    )
  }

  if (!scan) {
    return (
      <div className="page">
        {error ? (
          <StateBlock kind="error" title="Unable to load assets.">
            {error}
          </StateBlock>
        ) : (
          <StateBlock kind="empty" title="No completed scan available.">
            Run a scan to build the asset inventory.
          </StateBlock>
        )}
      </div>
    )
  }

  return (
    <div className="page">
      <ScanContextBar scan={scan} onChangeScan={onChangeScan} />

      <section className="summary-grid" aria-label="Asset summary">
        <SummaryCard label="Hosts" value={scan.hosts.length} />
        <SummaryCard label="Open ports" value={countPorts(scan)} />
        <SummaryCard label="Services" value={countServices(scan)} />
        <SummaryCard
          label="Findings"
          value={flattenFindings(scan).length}
        />
      </section>

      <section className="panel">
        <div className="panel-header">
          <div>
            <p className="eyebrow">Inventory</p>
            <h2>Discovered hosts</h2>
          </div>
        </div>

        {scan.hosts.length === 0 ? (
          <StateBlock kind="empty" title="No hosts discovered in this scan." />
        ) : (
          <AssetTable hosts={scan.hosts} />
        )}
      </section>
    </div>
  )
}

export default AssetsPage
