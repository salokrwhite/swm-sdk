import fetch from 'node-fetch'
import * as fs from 'fs'
import * as path from 'path'
import { createHash, createHmac, createPublicKey, randomUUID, verify } from 'crypto'
import FormData from 'form-data'

export class FeedbackDisabledError extends Error {
  constructor(message = 'feedback disabled') {
    super(message)
    this.name = 'FeedbackDisabledError'
  }
}

export const API_ERROR_CODE_AUTHZ_INVALID = 'authz_invalid'
export const API_ERROR_CODE_AUTHZ_DENIED = 'authz_denied'

/** Thrown when a required authorization verdict is missing or invalid (fail closed). */
export class AuthzError extends Error {
  code: string
  constructor(code: string, message: string) {
    super(message)
    this.name = 'AuthzError'
    this.code = code
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

export interface AuthzEnvelope {
  decision?: string
  nonce?: string
  device_id?: string
  issued_at?: number
  expires_at?: number
  key_id?: string
  reason?: string
  signature?: string
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
  authz?: AuthzEnvelope
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

// RFC3986 escape matching the backend (Go url.QueryEscape + '+'->'%20', '*'->'%2A').
function escapeRfc3986(value: string): string {
  return encodeURIComponent(value).replace(/[!'()*]/g, (c) => '%' + c.charCodeAt(0).toString(16).toUpperCase())
}

// Canonical query string: pairs sorted by key then value, RFC3986-escaped, joined '&'.
function canonicalQuery(pairs: Array<[string, string]>): string {
  const sorted = pairs
    .slice()
    .sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : a[1] < b[1] ? -1 : a[1] > b[1] ? 1 : 0))
  return sorted.map(([k, v]) => `${escapeRfc3986(k)}=${escapeRfc3986(v)}`).join('&')
}

function sha256Hex(data: Buffer): string {
  return createHash('sha256').update(data).digest('hex')
}

function hmacSha256Hex(secret: string, canonical: string): string {
  return createHmac('sha256', secret).update(canonical, 'utf8').digest('hex')
}

function decodeKeyMaterial(value: string): Buffer {
  const trimmed = value.trim()
  const isHex = trimmed.length % 2 === 0 && /^[0-9a-fA-F]+$/.test(trimmed)
  return isHex ? Buffer.from(trimmed, 'hex') : Buffer.from(trimmed, 'base64')
}

// Must match backend internal/auth/authz.go authzCanonical byte-for-byte.
function authzCanonical(appId: string, env: AuthzEnvelope): string {
  return [
    'authz_v1',
    'app_id:' + appId,
    'device_id:' + (env.device_id ?? ''),
    'nonce:' + (env.nonce ?? ''),
    'decision:' + (env.decision ?? ''),
    'reason:' + (env.reason ?? ''),
    'issued_at:' + String(env.issued_at ?? 0),
    'expires_at:' + String(env.expires_at ?? 0),
    'key_id:' + (env.key_id ?? '')
  ].join('\n')
}

// SPKI DER prefix for an Ed25519 public key; raw 32-byte key appended.
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex')

function ed25519Verify(pubRaw: Buffer, message: Buffer, signature: Buffer): boolean {
  const der = Buffer.concat([ED25519_SPKI_PREFIX, pubRaw])
  const key = createPublicKey({ key: der, format: 'der', type: 'spki' })
  return verify(null, message, key, signature)
}

export class Client {
  baseUrl: string
  appId: string
  appSecret: string
  channel = ''
  platform = ''
  arch = ''
  deviceId = ''
  attributes: Record<string, any> = {}
  retries = 2
  backoffMs = 500
  publicKey = ''
  verifySignature = false
  // When true, every call that can carry a signed verdict fails closed unless the
  // response is accompanied by a valid Ed25519 "allow" bound to this request + device.
  requireAuthz = false
  // key_id -> Ed25519 public key (hex or base64).
  authzPublicKeys: Record<string, string> = {}
  authzClockSkewSeconds = 120

  constructor(baseUrl: string, appId: string, appSecret: string) {
    this.baseUrl = baseUrl.replace(/\/+$/, '')
    this.appId = appId
    this.appSecret = appSecret
  }

  private signHeaders(method: string, pathname: string, canonicalQ: string, body: Buffer): { headers: Record<string, string>; nonce: string } {
    const ts = Math.floor(Date.now() / 1000).toString()
    const nonce = randomUUID()
    const canonical = [method.toUpperCase(), pathname, canonicalQ, sha256Hex(body), ts, nonce, this.appId].join('\n')
    const signature = hmacSha256Hex(this.appSecret, canonical)
    return {
      headers: {
        'X-App-Id': this.appId,
        'X-Timestamp': ts,
        'X-Nonce': nonce,
        'X-Signature': signature,
        'X-Sign-Version': 'v1'
      },
      nonce
    }
  }

  // verifyAuthz enforces a server verdict. No-op when requireAuthz is false.
  // Throws AuthzError on any failure so callers fail closed.
  private verifyAuthz(env: AuthzEnvelope | undefined | null, requestNonce: string): void {
    if (!this.requireAuthz) return
    if (!env) throw new AuthzError(API_ERROR_CODE_AUTHZ_INVALID, 'authorization missing')
    if (!requestNonce || env.nonce !== requestNonce) {
      throw new AuthzError(API_ERROR_CODE_AUTHZ_INVALID, 'authorization nonce mismatch')
    }
    if ((env.device_id ?? '') !== (this.deviceId ?? '')) {
      throw new AuthzError(API_ERROR_CODE_AUTHZ_INVALID, 'authorization device mismatch')
    }
    const skew = this.authzClockSkewSeconds > 0 ? this.authzClockSkewSeconds : 120
    const now = Math.floor(Date.now() / 1000)
    const exp = env.expires_at ?? 0
    if (exp <= 0 || now > exp + skew) {
      throw new AuthzError(API_ERROR_CODE_AUTHZ_INVALID, 'authorization expired')
    }
    const keyId = env.key_id ?? ''
    const pubEncoded = this.authzPublicKeys[keyId]
    if (!pubEncoded || !pubEncoded.trim()) {
      throw new AuthzError(API_ERROR_CODE_AUTHZ_INVALID, `authorization key unknown: ${keyId}`)
    }
    if (!env.signature || !env.signature.trim()) {
      throw new AuthzError(API_ERROR_CODE_AUTHZ_INVALID, 'authorization signature missing')
    }
    const pubBytes = decodeKeyMaterial(pubEncoded)
    if (pubBytes.length !== 32) {
      throw new AuthzError(API_ERROR_CODE_AUTHZ_INVALID, 'authorization public key invalid')
    }
    const sigBytes = decodeKeyMaterial(env.signature)
    const msg = Buffer.from(authzCanonical(this.appId, env), 'utf8')
    let ok = false
    try {
      ok = ed25519Verify(pubBytes, msg, sigBytes)
    } catch (e) {
      throw new AuthzError(API_ERROR_CODE_AUTHZ_INVALID, `authorization verify error: ${(e as Error).message}`)
    }
    if (!ok) throw new AuthzError(API_ERROR_CODE_AUTHZ_INVALID, 'authorization signature invalid')
    if (env.decision !== 'allow') {
      const reason = env.reason && env.reason.trim() ? env.reason : 'access denied'
      throw new AuthzError(API_ERROR_CODE_AUTHZ_DENIED, `authorization denied: ${reason}`)
    }
  }

  private verifyResponseAuthz(body: string, requestNonce: string): void {
    if (!this.requireAuthz) return
    let env: AuthzEnvelope | undefined
    try {
      env = (JSON.parse(body) as { authz?: AuthzEnvelope })?.authz
    } catch {
      env = undefined
    }
    this.verifyAuthz(env, requestNonce)
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
          const pairs: Array<[string, string]> = [
            ['device_id', deviceId],
            ['channel_code', channel],
            ['platform', platform],
            ['arch', arch]
          ]
          if (options.current_version) pairs.push(['current_version', options.current_version])
          if (options.version_code !== undefined) pairs.push(['version_code', String(options.version_code)])
          const canonicalQ = canonicalQuery(pairs)
          const { headers, nonce } = this.signHeaders('GET', '/api/client/updates/stream', canonicalQ, Buffer.alloc(0))

          const res = await fetch(`${this.baseUrl}/api/client/updates/stream?${canonicalQ}`, {
            method: 'GET',
            headers,
            signal: controller.signal
          })
          if (res.status === 401 || res.status === 403) {
            throw new Error(`stream unauthorized: ${res.status}`)
          }
          if (!res.ok || !res.body) {
            throw new Error(`stream failed: ${res.status}`)
          }

          retryDelay = baseBackoff
          // When requireAuthz, ignore pushed events until a valid authz event proves
          // the stream comes from the real server.
          let authzOk = !this.requireAuthz
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
                  if (eventType === 'authz') {
                    if (this.requireAuthz) {
                      let env: AuthzEnvelope | undefined
                      try {
                        env = JSON.parse(data) as AuthzEnvelope
                      } catch {
                        throw new AuthzError(API_ERROR_CODE_AUTHZ_INVALID, 'authorization malformed')
                      }
                      this.verifyAuthz(env, nonce)
                      authzOk = true
                    }
                  } else if (eventType !== 'connected' && authzOk) {
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
          // A failed/denied verdict means the server is fake or the device is
          // revoked — stop, don't reconnect.
          if (err instanceof AuthzError) break
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

  private async request(pathname: string, body: Record<string, any>): Promise<{ res: import('node-fetch').Response; nonce: string }> {
    const bodyBuf = Buffer.from(JSON.stringify(body), 'utf8')
    let lastErr: any
    for (let attempt = 0; attempt <= this.retries; attempt++) {
      try {
        const { headers, nonce } = this.signHeaders('POST', pathname, '', bodyBuf)
        const res = await fetch(`${this.baseUrl}${pathname}`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', ...headers },
          body: bodyBuf
        })
        return { res, nonce }
      } catch (err) {
        lastErr = err
        await new Promise((r) => setTimeout(r, this.backoffMs * Math.pow(2, attempt)))
      }
    }
    throw lastErr
  }

  async checkUpdate(currentVersion: string, versionCode?: number): Promise<UpdateCheckResponse> {
    const { res, nonce } = await this.request('/api/client/update-check', {
      channel_code: this.channel,
      current_version: currentVersion,
      version_code: versionCode,
      platform: this.platform,
      arch: this.arch,
      device_id: this.deviceId,
      attributes: this.attributes
    })
    if (!res.ok) throw new Error(`update check failed: ${res.status}`)
    const text = await res.text()
    const data = JSON.parse(text) as UpdateCheckResponse
    // Fail closed: when requireAuthz, the response must carry a valid signed "allow".
    this.verifyAuthz(data.authz, nonce)
    if (this.verifySignature && data.signature && data.checksum_sha256) {
      this.verifySignatureForChecksum(data.checksum_sha256, data.signature)
    }
    return data
  }

  async reportEvent(eventName: string, properties: Record<string, any> = {}) {
    const { res, nonce } = await this.request('/api/client/events', {
      device_id: this.deviceId,
      event_name: eventName,
      event_time: new Date().toISOString(),
      channel_code: this.channel,
      properties,
      attributes: this.attributes
    })
    if (!res.ok) throw new Error(`event report failed: ${res.status}`)
    this.verifyResponseAuthz(await res.text(), nonce)
  }

  async reportHeartbeat(appVersion?: string, userId?: string) {
    if (!this.deviceId) {
      throw new Error('device_id required')
    }
    const payload: Record<string, any> = {
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
    const { res, nonce } = await this.request('/api/client/heartbeat', payload)
    if (!res.ok) throw new Error(`heartbeat failed: ${res.status}`)
    this.verifyResponseAuthz(await res.text(), nonce)
  }

  async reportEvents(events: any[]) {
    const { res, nonce } = await this.request('/api/client/events', {
      events
    })
    if (!res.ok) throw new Error(`event report failed: ${res.status}`)
    this.verifyResponseAuthz(await res.text(), nonce)
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
    // Read attachments into buffers so the multipart body can be materialized and
    // signed (the request signature covers the exact body bytes).
    for (const filePath of options.attachments || []) {
      if (!filePath) continue
      form.append('attachments', fs.readFileSync(filePath), { filename: path.basename(filePath) })
    }

    const bodyBuf = form.getBuffer()
    const { headers, nonce } = this.signHeaders('POST', '/api/client/feedback', '', bodyBuf)
    const res = await fetch(`${this.baseUrl}/api/client/feedback`, {
      method: 'POST',
      headers: { ...(form.getHeaders() as Record<string, string>), ...headers },
      body: bodyBuf
    })
    if (!res.ok) {
      const body = await res.text().catch(() => '')
      if (isFeedbackDisabledBody(body)) throw new FeedbackDisabledError()
      throw new Error(`report feedback failed: ${res.status}`)
    }
    this.verifyResponseAuthz(await res.text(), nonce)
  }

  async download(url: string, destPath: string, checksum?: string, signature?: string, onProgress?: (written: number, total: number) => void) {
    const res = await fetch(url)
    const respBody = res.body
    if (!res.ok || !respBody) throw new Error(`download failed: ${res.status}`)

    await fs.promises.mkdir(path.dirname(destPath), { recursive: true })
    const file = fs.createWriteStream(destPath)
    const hash = createHash('sha256')

    const total = Number(res.headers.get('content-length') || 0)
    let written = 0

    await new Promise<void>((resolve, reject) => {
      respBody.on('data', (chunk: Buffer) => {
        written += chunk.length
        hash.update(chunk)
        file.write(chunk)
        if (onProgress) onProgress(written, total)
      })
      respBody.on('error', reject)
      respBody.on('end', () => {
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
    const sig = decodeKeyMaterial(signature)
    const pubKey = this.publicKey.includes('BEGIN PUBLIC KEY')
      ? createPublicKey(this.publicKey)
      : createPublicKey({ key: decodeKeyMaterial(this.publicKey), format: 'der', type: 'spki' })
    const ok = verify(null, Buffer.from(checksum), pubKey, sig)
    if (!ok) throw new Error('signature verification failed')
  }
}
