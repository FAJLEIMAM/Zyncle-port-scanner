export type IconName =
  | 'dashboard'
  | 'plus'
  | 'activity'
  | 'history'
  | 'shield'
  | 'server'
  | 'settings'
  | 'download'
  | 'search'
  | 'refresh'
  | 'arrow'
  | 'alert'
  | 'check'

const PATHS: Record<IconName, string> = {
  dashboard: 'M4 4h7v7H4zM13 4h7v4h-7zM13 10h7v10h-7zM4 13h7v7H4z',
  plus: 'M12 5v14M5 12h14',
  activity: 'M3 12h4l3-8 4 16 3-8h4',
  history: 'M3 12a9 9 0 1 0 3-6.7M3 4v5h5M12 7v5l3 2',
  shield: 'M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6zM9 12l2 2 4-4',
  server: 'M4 4h16v6H4zM4 14h16v6H4zM8 7h.01M8 17h.01',
  settings:
    'M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6zM19 12l2-1-2-4-2 .5-1.5-1L15 4h-4l-.5 2.5-1.5 1L7 7l-2 4 2 1v2l-2 1 2 4 2-.5 1.5 1L11 20h4l.5-2.5 1.5-1 2 .5 2-4-2-1z',
  download: 'M12 4v12M7 11l5 5 5-5M5 20h14',
  search: 'M11 4a7 7 0 1 0 0 14 7 7 0 0 0 0-14zM20 20l-4-4',
  refresh: 'M20 11a8 8 0 0 0-14-4M4 4v4h4M4 13a8 8 0 0 0 14 4M20 20v-4h-4',
  arrow: 'M5 12h14M13 6l6 6-6 6',
  alert: 'M12 4l9 16H3zM12 10v4M12 17h.01',
  check: 'M5 12l5 5 9-10',
}

type IconProps = {
  name: IconName
  size?: number
}

function Icon({ name, size = 18 }: IconProps) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.7"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
    >
      <path d={PATHS[name]} />
    </svg>
  )
}

export default Icon
