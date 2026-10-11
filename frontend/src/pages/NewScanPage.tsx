import { useState } from 'react'
import type { FormEvent } from 'react'

import type { ScanProfile, VulnerabilityProfile } from '../types'
import {
  getProfileLabel,
  getVulnerabilityProfileLabel,
} from '../utils'
import ScanPipeline from '../components/ScanPipeline'

type Option<T extends string> = {
  value: T
  title: string
  detail: string
}

const PORT_OPTIONS: Option<ScanProfile>[] = [
  { value: 'common', title: 'Common Ports', detail: 'TCP 1 – 1000' },
  { value: 'full', title: 'Full Ports', detail: 'TCP 1 – 65535' },
]

const VULN_OPTIONS: Option<VulnerabilityProfile>[] = [
  {
    value: 'lightweight',
    title: 'Lightweight',
    detail: 'Faster vulnerability assessment',
  },
  {
    value: 'full',
    title: 'Full & Fast',
    detail: 'Comprehensive Greenbone scan',
  },
]

type OptionGroupProps<T extends string> = {
  legend: string
  value: T
  options: Option<T>[]
  disabled: boolean
  onChange: (value: T) => void
}

function OptionGroup<T extends string>({
  legend,
  value,
  options,
  disabled,
  onChange,
}: OptionGroupProps<T>) {
  return (
    <fieldset className="option-group" disabled={disabled}>
      <legend>{legend}</legend>

      <div className="option-grid" role="radiogroup" aria-label={legend}>
        {options.map((option) => {
          const selected = option.value === value

          return (
            <button
              key={option.value}
              type="button"
              role="radio"
              aria-checked={selected}
              className={selected ? 'option active' : 'option'}
              onClick={() => onChange(option.value)}
            >
              <strong>{option.title}</strong>
              <span>{option.detail}</span>
            </button>
          )
        })}
      </div>
    </fieldset>
  )
}

type NewScanPageProps = {
  target: string
  onTargetChange: (value: string) => void
  profile: ScanProfile
  onProfileChange: (value: ScanProfile) => void
  vulnerabilityProfile: VulnerabilityProfile
  onVulnerabilityProfileChange: (value: VulnerabilityProfile) => void
  loading: boolean
  scanStatus: string
  onStart: () => void
}

function NewScanPage({
  target,
  onTargetChange,
  profile,
  onProfileChange,
  vulnerabilityProfile,
  onVulnerabilityProfileChange,
  loading,
  scanStatus,
  onStart,
}: NewScanPageProps) {
  const [validation, setValidation] = useState('')

  const handleSubmit = (event: FormEvent) => {
    event.preventDefault()

    if (loading) {
      return
    }

    if (!target.trim()) {
      setValidation('Please enter a target URL.')
      return
    }

    setValidation('')
    onStart()
  }

  return (
    <div className="page two-col">
      <form className="panel scan-form" onSubmit={handleSubmit} noValidate>
        <div className="panel-header">
          <div>
            <p className="eyebrow">Configuration</p>
            <h2>New security scan</h2>
          </div>
        </div>

        <div className="field">
          <label htmlFor="target">Website / target URL</label>

          <input
            id="target"
            type="text"
            value={target}
            onChange={(event) => {
              onTargetChange(event.target.value)
              if (validation) {
                setValidation('')
              }
            }}
            placeholder="https://example.com"
            disabled={loading}
            autoComplete="off"
            spellCheck={false}
            aria-invalid={validation ? true : undefined}
            aria-describedby={
              validation ? 'target-error' : 'target-help'
            }
          />

          {validation ? (
            <p className="field-error" id="target-error" role="alert">
              {validation}
            </p>
          ) : (
            <p className="field-help" id="target-help">
              Only scan systems you are authorised to test.
            </p>
          )}
        </div>

        <OptionGroup
          legend="Port scan profile"
          value={profile}
          options={PORT_OPTIONS}
          disabled={loading}
          onChange={onProfileChange}
        />

        <OptionGroup
          legend="Vulnerability profile"
          value={vulnerabilityProfile}
          options={VULN_OPTIONS}
          disabled={loading}
          onChange={onVulnerabilityProfileChange}
        />

        <div className="form-footer">
          <p className="field-help" aria-live="polite">
            {loading
              ? scanStatus === 'starting'
                ? 'Starting scan…'
                : 'A scan is in progress.'
              : `${getProfileLabel(profile)} · ${getVulnerabilityProfileLabel(vulnerabilityProfile)}`}
          </p>

          <button
            type="submit"
            className="btn btn-primary"
            disabled={loading}
          >
            {loading ? 'Scanning…' : 'START SCAN'}
          </button>
        </div>
      </form>

      <ScanPipeline vulnerabilityProfile={vulnerabilityProfile} />
    </div>
  )
}

export default NewScanPage
