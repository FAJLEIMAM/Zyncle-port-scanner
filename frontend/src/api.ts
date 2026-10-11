import type {
  ScanCreatePayload,
  ScanCreateResponse,
  ScanHistoryItem,
  ScanResult,
} from './types'

export const API_BASE_URL = 'http://127.0.0.1:8000'

export const POLL_INTERVAL_MS = 3000

// GET /api/scans/{id}
export async function getScan(
  id: number,
): Promise<ScanResult> {
  const response = await fetch(
    `${API_BASE_URL}/api/scans/${id}`,
  )

  if (!response.ok) {
    throw new Error(
      `Failed to retrieve scan results (${response.status})`,
    )
  }

  return response.json()
}

// GET /api/scans
export async function getScanHistory(): Promise<
  ScanHistoryItem[]
> {
  const response = await fetch(`${API_BASE_URL}/api/scans`)

  if (!response.ok) {
    throw new Error(
      `Failed to load scan history (${response.status})`,
    )
  }

  return response.json()
}

// POST /api/scans
export async function createScan(
  payload: ScanCreatePayload,
): Promise<ScanCreateResponse> {
  const response = await fetch(`${API_BASE_URL}/api/scans`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(payload),
  })

  if (!response.ok) {
    let message = `Failed to start scan (${response.status})`

    try {
      const data = await response.json()

      if (typeof data.detail === 'string') {
        message = data.detail
      } else if (Array.isArray(data.detail)) {
        message = data.detail
          .map((item: { msg?: string }) => item.msg)
          .filter(Boolean)
          .join(', ')
      }
    } catch {
      // Keep default message.
    }

    throw new Error(message)
  }

  return response.json()
}
