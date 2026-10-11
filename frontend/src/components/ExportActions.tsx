import type { ScanResult } from '../types'
import { exportCsv, exportJson, exportPdf } from '../utils'
import Icon from './Icon'

type ExportActionsProps = {
  result: ScanResult
}

function ExportActions({ result }: ExportActionsProps) {
  return (
    <div className="export-actions" role="group" aria-label="Export">
      <button
        type="button"
        className="btn btn-sm"
        onClick={() => exportJson(result)}
      >
        <Icon name="download" size={14} />
        JSON
      </button>

      <button
        type="button"
        className="btn btn-sm"
        onClick={() => exportCsv(result)}
      >
        <Icon name="download" size={14} />
        CSV
      </button>

      <button type="button" className="btn btn-sm" onClick={exportPdf}>
        <Icon name="download" size={14} />
        PDF
      </button>
    </div>
  )
}

export default ExportActions
