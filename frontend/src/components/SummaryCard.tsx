type SummaryCardProps = {
  label: string
  value: string | number
  hint?: string
}

function SummaryCard({ label, value, hint }: SummaryCardProps) {
  return (
    <div className="summary-card">
      <span className="summary-label">{label}</span>
      <strong className="summary-value">{value}</strong>
      {hint && <span className="summary-hint">{hint}</span>}
    </div>
  )
}

export default SummaryCard
