import { useCallback, useEffect, useRef, useState } from 'react'

import './App.css'

import {
  POLL_INTERVAL_MS,
  createScan,
  getScan,
  getScanHistory,
} from './api'
import Sidebar from './components/Sidebar'
import Topbar from './components/Topbar'
import AssetsPage from './pages/AssetsPage'
import CurrentScanPage from './pages/CurrentScanPage'
import DashboardPage from './pages/DashboardPage'
import HistoryPage from './pages/HistoryPage'
import NewScanPage from './pages/NewScanPage'
import SettingsPage from './pages/SettingsPage'
import VulnerabilitiesPage from './pages/VulnerabilitiesPage'
import type {
  ActiveSection,
  ApiState,
  ScanCreateResponse,
  ScanHistoryItem,
  ScanProfile,
  ScanResult,
  VulnerabilityProfile,
} from './types'
import { sleep } from './utils'

const PAGE_TITLES: Record<
  ActiveSection,
  { title: string; subtitle: string }
> = {
  dashboard: {
    title: 'Dashboard',
    subtitle: 'Security posture across your recent scans',
  },
  'new-scan': {
    title: 'New Scan',
    subtitle: 'Configure the target and scanning profiles',
  },
  'current-scan': {
    title: 'Current Scan',
    subtitle: 'Live status and detailed results',
  },
  history: {
    title: 'Scan History',
    subtitle: 'Review and open previous scan results',
  },
  vulnerabilities: {
    title: 'Vulnerabilities',
    subtitle: 'Findings from the selected scan',
  },
  assets: {
    title: 'Assets',
    subtitle: 'Hosts, ports and services from the selected scan',
  },
  settings: {
    title: 'Settings',
    subtitle: 'Connection and scanner configuration',
  },
}

function App() {
  const [target, setTarget] = useState('http://127.0.0.1:3000')

  const [profile, setProfile] = useState<ScanProfile>('common')

  const [vulnerabilityProfile, setVulnerabilityProfile] =
    useState<VulnerabilityProfile>('lightweight')

  const [scanId, setScanId] = useState<number | null>(null)

  const [scanMeta, setScanMeta] =
    useState<ScanCreateResponse | null>(null)

  const [result, setResult] = useState<ScanResult | null>(null)

  const [loading, setLoading] = useState(false)

  const [scanStatus, setScanStatus] = useState('')

  const [error, setError] = useState('')

  const [scanHistory, setScanHistory] = useState<ScanHistoryItem[]>([])

  const [historyLoading, setHistoryLoading] = useState(true)

  const [historyError, setHistoryError] = useState('')

  const [apiState, setApiState] = useState<ApiState>('checking')

  // Most recent completed scan (full detail) for the dashboard,
  // vulnerabilities and assets views.
  const [latestScan, setLatestScan] = useState<ScanResult | null>(null)

  const [latestLoading, setLatestLoading] = useState(false)

  const [latestError, setLatestError] = useState('')

  const latestScanIdRef = useRef<number | null>(null)

  const [activeSection, setActiveSection] =
    useState<ActiveSection>('dashboard')

  const mainRef = useRef<HTMLElement | null>(null)

  const firstRender = useRef(true)

  // ==========================================================
  // LATEST COMPLETED SCAN (detail)
  // ==========================================================

  const loadLatestScan = useCallback(
    async (history: ScanHistoryItem[]) => {
      const latestCompleted = history.find(
        (scan) => scan.status === 'completed',
      )

      if (!latestCompleted) {
        latestScanIdRef.current = null
        setLatestScan(null)
        setLatestError('')
        return
      }

      // Completed scans do not change; skip the request.
      if (latestScanIdRef.current === latestCompleted.id) {
        return
      }

      setLatestLoading(true)
      setLatestError('')

      try {
        const scan = await getScan(latestCompleted.id)

        latestScanIdRef.current = scan.id
        setLatestScan(scan)
      } catch (err) {
        setLatestError(
          err instanceof Error
            ? err.message
            : 'Unable to load latest scan',
        )
      } finally {
        setLatestLoading(false)
      }
    },
    [],
  )

  // ==========================================================
  // GET SCAN HISTORY
  // ==========================================================

  const loadScanHistory = useCallback(async () => {
    setHistoryLoading(true)

    try {
      const data = await getScanHistory()

      setScanHistory(data)
      setHistoryError('')
      setApiState('online')

      await loadLatestScan(data)
    } catch (err) {
      console.error('Scan history error:', err)

      setHistoryError(
        err instanceof Error
          ? err.message
          : 'Unable to load scan history',
      )

      setApiState('offline')
    } finally {
      setHistoryLoading(false)
    }
  }, [loadLatestScan])

  useEffect(() => {
    void loadScanHistory()
  }, [loadScanHistory])

  // Move keyboard focus to the content area when the page changes.
  useEffect(() => {
    if (firstRender.current) {
      firstRender.current = false
      return
    }

    mainRef.current?.focus()
  }, [activeSection])

  // ==========================================================
  // VIEW HISTORICAL SCAN
  // ==========================================================

  const handleViewScan = async (id: number) => {
    try {
      setError('')
      setLoading(true)
      setScanStatus('loading')

      const scan = await getScan(id)

      setScanId(scan.id)
      setScanMeta(null)
      setScanStatus(scan.status)
      setProfile(scan.profile)
      setVulnerabilityProfile(scan.vulnerability_profile)
      setResult(scan)

      setActiveSection('current-scan')
    } catch (err) {
      setError(
        err instanceof Error ? err.message : 'Unable to load scan',
      )

      setActiveSection('current-scan')
    } finally {
      setLoading(false)
    }
  }

  // ==========================================================
  // POLL ACTIVE SCAN
  // ==========================================================

  const waitForScan = async (id: number) => {
    while (true) {
      const scan = await getScan(id)

      setScanStatus(scan.status)

      if (scan.status === 'completed') {
        setResult(scan)
        setProfile(scan.profile)
        setVulnerabilityProfile(scan.vulnerability_profile)

        latestScanIdRef.current = scan.id
        setLatestScan(scan)
        setLatestError('')

        await loadScanHistory()

        return
      }

      if (scan.status === 'failed') {
        await loadScanHistory()

        throw new Error(
          scan.error_message || 'Scan failed on the backend',
        )
      }

      await sleep(POLL_INTERVAL_MS)
    }
  }

  // ==========================================================
  // START NEW SCAN
  // ==========================================================

  const handleStartScan = async () => {
    const cleanTarget = target.trim()

    if (!cleanTarget) {
      setError('Please enter a target URL.')
      return
    }

    if (loading) {
      return
    }

    setLoading(true)
    setError('')
    setResult(null)
    setScanId(null)
    setScanMeta(null)
    setScanStatus('starting')
    setActiveSection('current-scan')

    try {
      const data = await createScan({
        target: cleanTarget,
        profile,
        vulnerability_profile: vulnerabilityProfile,
      })

      setScanId(data.id)
      setScanMeta(data)
      setScanStatus(data.status)
      setProfile(data.profile)
      setVulnerabilityProfile(data.vulnerability_profile)

      await loadScanHistory()

      await waitForScan(data.id)
    } catch (err) {
      setError(
        err instanceof Error ? err.message : 'Unable to start scan',
      )

      setScanStatus('failed')

      await loadScanHistory()
    } finally {
      setLoading(false)
    }
  }

  // ==========================================================
  // DERIVED
  // ==========================================================

  // Scan used by the Vulnerabilities and Assets views.
  const focusScan = result ?? latestScan

  const dataLoading = loading || latestLoading

  const page = PAGE_TITLES[activeSection]

  const goToHistory = () => setActiveSection('history')

  // ==========================================================
  // UI
  // ==========================================================

  return (
    <div className="app">
      <a className="skip-link" href="#main-content">
        Skip to content
      </a>

      <Sidebar
        activeSection={activeSection}
        onNavigate={setActiveSection}
        scanActive={loading}
        apiState={apiState}
      />

      <div className="app-content">
        <Topbar
          title={page.title}
          subtitle={page.subtitle}
          apiState={apiState}
          scanActive={loading}
          onOpenCurrentScan={() => setActiveSection('current-scan')}
        />

        <main id="main-content" className="main" ref={mainRef} tabIndex={-1}>
          {activeSection === 'dashboard' && (
            <DashboardPage
              history={scanHistory}
              historyLoading={historyLoading}
              historyError={historyError}
              onRefresh={() => void loadScanHistory()}
              latestScan={latestScan}
              latestLoading={latestLoading}
              latestError={latestError}
              scanActive={loading}
              canViewCurrent={scanId !== null || result !== null}
              canViewVulnerabilities={focusScan !== null}
              onNavigate={setActiveSection}
              onView={(id) => void handleViewScan(id)}
            />
          )}

          {activeSection === 'new-scan' && (
            <NewScanPage
              target={target}
              onTargetChange={setTarget}
              profile={profile}
              onProfileChange={setProfile}
              vulnerabilityProfile={vulnerabilityProfile}
              onVulnerabilityProfileChange={setVulnerabilityProfile}
              loading={loading}
              scanStatus={scanStatus}
              onStart={() => void handleStartScan()}
            />
          )}

          {activeSection === 'current-scan' && (
            <CurrentScanPage
              loading={loading}
              scanStatus={scanStatus}
              scanId={scanId}
              scanMeta={scanMeta}
              target={target}
              profile={profile}
              vulnerabilityProfile={vulnerabilityProfile}
              error={error}
              result={result}
              onNavigate={setActiveSection}
              onReloadScan={(id) => void handleViewScan(id)}
            />
          )}

          {activeSection === 'history' && (
            <HistoryPage
              history={scanHistory}
              historyLoading={historyLoading}
              historyError={historyError}
              onRefresh={() => void loadScanHistory()}
              onView={(id) => void handleViewScan(id)}
              viewDisabled={loading}
            />
          )}

          {activeSection === 'vulnerabilities' && (
            <VulnerabilitiesPage
              scan={focusScan}
              loading={dataLoading}
              error={latestError}
              onChangeScan={goToHistory}
            />
          )}

          {activeSection === 'assets' && (
            <AssetsPage
              scan={focusScan}
              loading={dataLoading}
              error={latestError}
              onChangeScan={goToHistory}
            />
          )}

          {activeSection === 'settings' && (
            <SettingsPage
              apiState={apiState}
              historyCount={scanHistory.length}
              profile={profile}
              vulnerabilityProfile={vulnerabilityProfile}
            />
          )}
        </main>
      </div>
    </div>
  )
}

export default App
