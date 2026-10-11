import type { ReactNode } from 'react'

import Icon from './Icon'

type StateBlockProps = {
  kind: 'loading' | 'empty' | 'error'
  title: string
  children?: ReactNode
  action?: ReactNode
}

function StateBlock({
  kind,
  title,
  children,
  action,
}: StateBlockProps) {
  return (
    <div
      className={`state-block state-${kind}`}
      role={kind === 'error' ? 'alert' : 'status'}
    >
      {kind === 'loading' && (
        <div className="skeleton" aria-hidden="true">
          <span />
          <span />
          <span />
        </div>
      )}

      {kind === 'error' && (
        <span className="state-icon">
          <Icon name="alert" size={20} />
        </span>
      )}

      <strong>{title}</strong>

      {children && <p>{children}</p>}

      {action}
    </div>
  )
}

export default StateBlock
