import fetch from 'node-fetch'
import * as fs from 'fs'
import * as path from 'path'
import { createHash, createPublicKey, verify } from 'crypto'
import FormData from 'form-data'

export class FeedbackDisabledError extends Error {
  constructor(message = 'feedback disabled') {
    super(message)
    this.name = 'FeedbackDisabledError'
  }
}

function isFeedbackDisabledBody(body: string): boolean {
  if (!body) return false
  try {
    const parsed = JSON.parse(body)
    const err = parsed?.error
    if (err && typeof err === 'object' && typeof err.code === 'string') {
      return err.code.toLowerCase() === 'feedback_disabled'
    }
    if (typeof err === 'string') {
      return err.toLowerCase() === 'feedback_disabled'
    }
  } catch {
    return false
  }
  return false
}

export const CONTROL_EVENT_SHUTDOWN = 'device_shutdown'
export const CONTROL_EVENT_MAINTENANCE_SCHEDULED = 'maintenance_scheduled'
export const CONTROL_EVENT_MAINTENANCE_CANCELLED = 'maintenance_cancelled'

export interface Maintenance {
  enabled: boolean
  start_at?: string
  message?: string
  active: boolean
}

export interface UpdateCheckResponse {
  update_available: boolean
  mandatory: boolean
  heartbeat_interval_seconds?: number
  release_id?: string
  version?: string
  notes?: string
  download_url?: string
  checksum_sha256?: string
  signature?: string
  size?: number
  rollback_allowed?: boolean
  release_notes_url?: string
  maintenance?: Maintenance
}

export interface UpdatePushEvent {
  id?: string
  event_type: string
  org_id: string
  app_id: string
  channel_code: string
  platform: string
  arch: string
  release_id: string
  published_at: string
  reason: string
  message?: string
  maintenance_start_at?: string
}

export interface UpdateStreamOptions {
  channel_code?: string
  platform?: string
  arch?: string
  device_id?: string
  current_version?: string
  version_code?: number
  reconnect?: boolean
  reconnect_backoff_ms?: number
  reconnect_max_backoff_ms?: number
  jitter?: boolean
  onError?: (err: Error) => void
}

export interface UpdateWatchHandle {
  stop: () => void
}

export class Client {
  baseUrl: string
  appKey: string
  channel = ''
  platform = ''
  arch = ''
  deviceId = ''
  attributes: Record<string, any> = {}
  retries = 2
  backoffMs = 500
  publicKey = ''
  verifySignature = false

  constructor(baseUrl: string, appKey: string) {
    this.baseUrl = baseUrl
    this.appKey = appKey
  }

  startUpdateStream(options: UpdateStreamOptions, onEvent: (event: UpdatePushEvent) => void): UpdateWatchHandle {
    const reconnect = options.reconnect ?? true
    const baseBackoff = Math.max(300, options.reconnect_backoff_ms ?? 1500)
    const maxBackoff = Math.max(baseBackoff, options.reconnect_max_backoff_ms ?? 20000)
    const jitter = options.jitter ?? true
    const channel = options.channel_code || this.channel
    const platform = options.platform || this.platform
    const arch = options.arch || this.arch
    const deviceId = options.device_id || this.deviceId
    if (!channel || !platform || !arch || !deviceId) {
      throw new Error('channel_code/platform/arch/device_id required')
    }

    let stopped = false
    let controller: AbortController | null = null
    let retryDelay = baseBackoff

    const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms))

    const connect = async () => {
      while (!stopped) {
        try {
          controller = new AbortController()
          const qs = new URLSearchParams({
            app_key: this.appKey,
            channel_code: channel,
            platform,
            arch,
            device_id: deviceId
          })
          if (options.current_version) qs.set('current_version', options.current_version)
          if (options.version_code !== undefined) qs.set('version_code', String(options.version_code))

          const res = await fetch(`${this.baseUrl}/api/client/updates/stream?${qs.toString()}`, {
            method: 'GET',
            signal: controller.signal
          })
          if (res.status === 401 || res.status === 403) {
            throw new Error(`stream unauthorized: ${res.status}`)
          }
          if (!res.ok || !res.body) {
            throw new Error(`stream failed: ${res.status}`)
          }

          retryDelay = baseBackoff
          let eventType = ''
          const dataLines: string[] = []
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          for await (const chunk of res.body as any) {
            if (stopped) break
            const text = Buffer.isBuffer(chunk) ? chunk.toString('utf8') : String(chunk)
            const lines = text.replace(/\r/g, '').split('\n')
            for (const rawLine of lines) {
              const line = rawLine.trimEnd()
              if (!line) {
                if (dataLines.length > 0) {
                  const data = dataLines.join('\n')
                  if (eventType !== 'connected') {
                    try {
                      onEvent(JSON.parse(data) as UpdatePushEvent)
                    } catch (e) {
                      options.onError?.(e as Error)
                    }
                  }
                }
                eventType = ''
                dataLines.length = 0
                continue
              }
              if (line.startsWith(':')) continue
              if (line.startsWith('event:')) {
                eventType = line.slice(6).trim()
                continue
              }
              if (line.startsWith('data:')) {
                dataLines.push(line.slice(5).trim())
              }
            }
          }
        } catch (err) {
          if (stopped) break
          options.onError?.(err as Error)
          if (!reconnect) break
          let wait = retryDelay
          if (jitter) wait += Math.floor(Math.random() * (wait / 2))
          await sleep(wait)
          retryDelay = Math.min(maxBackoff, retryDelay * 2)
        }
      }
    }

    void connect()
    return {
      stop: () => {
        stopped = true
        if (controller) {
          controller.abort()
        }
      }
    }
  }

  watchUpdates(options: UpdateStreamOptions, onUpdateAvailable: (resp: UpdateCheckResponse) => void): UpdateWatchHandle {
    return this.startUpdateStream(options, async () => {
      try {
        const resp = await this.checkUpdate(options.current_version || '', options.version_code)
        if (resp.update_available) {
          onUpdateAvailable(resp)
        }
      } catch (err) {
        options.onError?.(err as Error)
      }
    })
  }

  private async request(path: string, body: Record<string, any>) {
    let lastErr: any
    for (let attempt = 0; attempt <= this.retries; attempt++) {
      try {
        const res = await fetch(`${this.baseUrl}${path}`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(body)
        })
        return res
      } catch (err) {
        lastErr = err
        await new Promise((r) => setTimeout(r, this.backoffMs * Math.pow(2, attempt)))
      }
    }
    throw lastErr
  }

  async checkUpdate(currentVersion: string, versionCode?: number): Promise<UpdateCheckResponse> {
    const res = await this.request('/api/client/update-check', {
      app_key: this.appKey,
      channel_code: this.channel,
      current_version: currentVersion,
      version_code: versionCode,
      platform: this.platform,
      arch: this.arch,
      device_id: this.deviceId,
      attributes: this.attributes
    })
    if (!res.ok) throw new Error(`update check failed: ${res.status}`)
    const data = await res.json() as UpdateCheckResponse
    if (this.verifySignature && data.signature && data.checksum_sha256) {
      this.verifySignatureForChecksum(data.checksum_sha256, data.signature)
    }
    return data
  }

  async reportEvent(eventName: string, properties: Record<string, any> = {}) {
    const res = await this.request('/api/client/events', {
      app_key: this.appKey,
      device_id: this.deviceId,
      event_name: eventName,
      event_time: new Date().toISOString(),
      channel_code: this.channel,
      properties,
      attributes: this.attributes
    })
    if (!res.ok) throw new Error(`event report failed: ${res.status}`)
  }

  async reportHeartbeat(appVersion?: string, userId?: string) {
    if (!this.deviceId) {
      throw new Error('device_id required')
    }
    const payload: Record<string, any> = {
      app_key: this.appKey,
      device_id: this.deviceId
    }
    if (this.channel) payload.channel_code = this.channel
    if (appVersion) payload.app_version = appVersion
    if (userId) payload.user_id = userId
    if (this.platform) payload.platform = this.platform
    if (this.arch) payload.arch = this.arch
    if (this.attributes && Object.keys(this.attributes).length > 0) {
      payload.attributes = this.attributes
    }
    const res = await this.request('/api/client/heartbeat', payload)
    if (!res.ok) throw new Error(`heartbeat failed: ${res.status}`)
  }

  async reportEvents(events: any[]) {
    const res = await this.request('/api/client/events', {
      app_key: this.appKey,
      events
    })
    if (!res.ok) throw new Error(`event report failed: ${res.status}`)
  }

  async reportFeedback(content: string, options: {
    rating?: number
    contact?: string
    attachments?: string[]
    metadata?: Record<string, any>
  } = {}) {
    if (!content || !content.trim()) {
      throw new Error('content required')
    }
    const form = new FormData()
    form.append('app_key', this.appKey)
    form.append('device_id', this.deviceId)
    if (this.channel) form.append('channel_code', this.channel)
    if (options.rating !== undefined) form.append('rating', String(options.rating))
    form.append('content', content)
    if (options.contact) form.append('contact', options.contact)

    const metadata = { ...(options.metadata || {}) }
    if (this.attributes && Object.keys(this.attributes).length > 0 && metadata.attributes === undefined) {
      metadata.attributes = this.attributes
    }
    if (metadata.app_version) {
      form.append('app_version', String(metadata.app_version))
    }
    if (Object.keys(metadata).length > 0) {
      form.append('metadata', JSON.stringify(metadata))
    }
    ;(options.attachments || []).forEach((filePath) => {
      if (!filePath) return
      form.append('attachments', fs.createReadStream(filePath))
    })

    const res = await fetch(`${this.baseUrl}/api/client/feedback`, {
      method: 'POST',
      headers: form.getHeaders() as any,
      body: form as any
    })
    if (!res.ok) {
      const body = await res.text().catch(() => '')
      if (isFeedbackDisabledBody(body)) throw new FeedbackDisabledError()
      throw new Error(`report feedback failed: ${res.status}`)
    }
  }

  async download(url: string, destPath: string, checksum?: string, signature?: string, onProgress?: (written: number, total: number) => void) {
    const res = await fetch(url)
    if (!res.ok || !res.body) throw new Error(`download failed: ${res.status}`)

    await fs.promises.mkdir(path.dirname(destPath), { recursive: true })
    const file = fs.createWriteStream(destPath)
    const hash = createHash('sha256')

    const total = Number(res.headers.get('content-length') || 0)
    let written = 0

    await new Promise<void>((resolve, reject) => {
      res.body.on('data', (chunk: Buffer) => {
        written += chunk.length
        hash.update(chunk)
        file.write(chunk)
        if (onProgress) onProgress(written, total)
      })
      res.body.on('error', reject)
      res.body.on('end', () => {
        file.end()
        resolve()
      })
    })

    if (checksum) {
      const got = hash.digest('hex')
      if (got !== checksum) throw new Error(`checksum mismatch: ${got} != ${checksum}`)
    }
    if (this.verifySignature && signature && checksum) {
      this.verifySignatureForChecksum(checksum, signature)
    }
  }

  private verifySignatureForChecksum(checksum: string, signature: string) {
    if (!this.publicKey) return
    const sig = this.decodeBase64OrHex(signature)
    const pubKey = this.publicKey.includes('BEGIN PUBLIC KEY')
      ? createPublicKey(this.publicKey)
      : createPublicKey({ key: this.decodeBase64OrHex(this.publicKey), format: 'der', type: 'spki' })
    const ok = verify(null, Buffer.from(checksum), pubKey, sig)
    if (!ok) throw new Error('signature verification failed')
  }

  private decodeBase64OrHex(value: string): Buffer {
    const trimmed = value.trim()
    const isHex = /^[0-9a-fA-F]+$/.test(trimmed) && trimmed.length % 2 === 0
    return isHex ? Buffer.from(trimmed, 'hex') : Buffer.from(trimmed, 'base64')
  }
}
