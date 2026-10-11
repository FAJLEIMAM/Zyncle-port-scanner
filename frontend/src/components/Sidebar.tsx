import type { ActiveSection, ApiState } from '../types'
import Icon from './Icon'
import type { IconName } from './Icon'
import ygcleLogo from '../assets/assets/ygcle-logo.png'

type NavItem = {
  id: ActiveSection
  label: string
  icon: IconName
}

const NAV_ITEMS: NavItem[] = [
  { id: 'dashboard', label: 'Dashboard', icon: 'dashboard' },
  { id: 'new-scan', label: 'New Scan', icon: 'plus' },
  { id: 'current-scan', label: 'Current Scan', icon: 'activity' },
  { id: 'history', label: 'Scan History', icon: 'history' },
  { id: 'vulnerabilities', label: 'Vulnerabilities', icon: 'shield' },
  { id: 'assets', label: 'Assets', icon: 'server' },
  { id: 'settings', label: 'Settings', icon: 'settings' },
]

const API_LABELS: Record<ApiState, string> = {
  checking: 'Checking API…',
  online: 'API connected',
  offline: 'API unreachable',
}

type SidebarProps = {
  activeSection: ActiveSection
  onNavigate: (section: ActiveSection) => void
  scanActive: boolean
  apiState: ApiState
}

function Sidebar({
  activeSection,
  onNavigate,
  scanActive,
  apiState,
}: SidebarProps) {
  return (
    <aside className="sidebar">
      <div className="sidebar-brand">
        <img
          src={ygcleLogo}
          alt="YGCLE Innovations logo"
          className="brand-mark"
        />

        <div className="brand-text">
          <strong>ZYNCLE</strong>
          <span>Security</span>
        </div>
      </div>

      <nav className="sidebar-nav" aria-label="Main navigation">
        {NAV_ITEMS.map((item) => {
          const active = activeSection === item.id

          return (
            <button
              key={item.id}
              type="button"
              className={
                active ? 'sidebar-item active' : 'sidebar-item'
              }
              aria-current={active ? 'page' : undefined}
              aria-label={item.label}
              title={item.label}
              onClick={() => onNavigate(item.id)}
            >
              <Icon name={item.icon} />

              <span className="sidebar-label">{item.label}</span>

              {item.id === 'current-scan' && scanActive && (
                <span
                  className="live-dot"
                  role="img"
                  aria-label="Scan in progress"
                />
              )}
            </button>
          )
        })}
      </nav>

      <div className={`sidebar-footer api-${apiState}`}>
        <span className="api-dot" aria-hidden="true" />
        <span className="sidebar-label">{API_LABELS[apiState]}</span>
      </div>
    </aside>
  )
}

export default Sidebar
