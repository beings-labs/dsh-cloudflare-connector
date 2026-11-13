import { randomUUID } from 'node:crypto'
import { chmodSync, closeSync, existsSync, fsyncSync, lstatSync, mkdirSync, openSync, readFileSync, renameSync, unlinkSync, writeFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { dirname, isAbsolute, join } from 'node:path'
import { z } from 'zod'

export const MCP_URL = 'https://mcp.cloudflare.com/mcp'
export const DEFAULT_SCOPES = ['user:read', 'account:read']

const record = z.record(z.string(), z.unknown())
const stateSchema = z.object({
  version: z.literal(1),
  endpoint: z.string().url(),
  clientInformation: record.optional(),
  tokens: z.object({
    access_token: z.string().min(1),
    token_type: z.string().min(1),
    refresh_token: z.string().optional(),
    scope: z.string().optional(),
    issuer: z.string().optional(),
    expires_in: z.number().nonnegative().optional(),
  }).passthrough().optional(),
  expiresAt: z.number().finite().optional(),
  discoveryState: record.optional(),
  correctionScopes: z.array(z.string()).optional(),
  pending: z.object({
    state: z.string().min(1),
    scopes: z.array(z.string()),
    redirectUrl: z.string().url(),
    startedAt: z.number().finite(),
    stepUp: z.boolean(),
    authorizeUrl: z.string().url().optional(),
    verifier: z.string().optional(),
  }).optional(),
}).strict()

export function configPath(tokenFile) {
  if (tokenFile !== undefined) {
    if (!isAbsolute(tokenFile)) throw new Error('tokenFile must be an absolute path')
    return tokenFile
  }
  return join(process.env.DSH_HOME || join(homedir(), '.dsh'), 'dsh-cloudflare-connector', 'auth.json')
}

export class CredentialStore {
  constructor({ endpoint = MCP_URL, tokenFile } = {}) {
    this.path = configPath(tokenFile)
    this.endpoint = new URL(endpoint).href
    this.data = { version: 1, endpoint: this.endpoint }
    if (!existsSync(this.path)) return
    if (!lstatSync(this.path).isFile()) throw new Error('Cloudflare credential path must be a regular file, not a symlink')
    let value
    try {
      value = JSON.parse(readFileSync(this.path, 'utf8'))
    } catch (error) {
      if (!(error instanceof SyntaxError)) throw error
      throw new Error('Cloudflare credential file contains invalid JSON; restore it or remove it and authorize again')
    }
    const parsed = stateSchema.safeParse(value)
    if (!parsed.success) throw new Error('Cloudflare credential file has an invalid format; restore it or remove it and authorize again')
    if (parsed.data.endpoint !== this.endpoint) {
      throw new Error('Cloudflare credential file belongs to another endpoint; use a different tokenFile')
    }
    chmodSync(this.path, 0o600)
    this.data = parsed.data
  }

  update(patch) {
    const parsed = stateSchema.safeParse({ ...this.data, ...patch })
    if (!parsed.success) throw new Error('Refusing to persist invalid Cloudflare credential state')
    const next = parsed.data
    mkdirSync(dirname(this.path), { recursive: true, mode: 0o700 })
    const temporary = `${this.path}.${randomUUID()}.tmp`
    let descriptor
    try {
      descriptor = openSync(temporary, 'wx', 0o600)
      writeFileSync(descriptor, `${JSON.stringify(next)}\n`)
      fsyncSync(descriptor)
      closeSync(descriptor)
      descriptor = undefined
      renameSync(temporary, this.path)
      this.data = next
    } finally {
      if (descriptor !== undefined) closeSync(descriptor)
      if (existsSync(temporary)) unlinkSync(temporary)
    }
  }

  clear() {
    try {
      unlinkSync(this.path)
    } catch (error) {
      if (error.code !== 'ENOENT') throw error
    }
    this.data = { version: 1, endpoint: this.endpoint }
  }

  redact(value) {
    let text = String(value)
    const secrets = [
      this.data.tokens?.access_token,
      this.data.tokens?.refresh_token,
      this.data.tokens?.id_token,
      this.data.clientInformation?.client_secret,
      this.data.pending?.verifier,
      this.data.pending?.state,
    ].filter((secret) => typeof secret === 'string' && secret.length > 0)
    for (const secret of secrets.sort((a, b) => b.length - a.length)) text = text.replaceAll(secret, '[redacted]')
    return text
      .replace(/\bBearer\s+[^\s"',]+/gi, 'Bearer [redacted]')
      .replace(/([?&](?:code|code_verifier|access_token|refresh_token|state)=)[^&\s]*/gi, '$1[redacted]')
      .replace(/("(?:access_token|refresh_token|client_secret|code_verifier)"\s*:\s*")[^"]*/gi, '$1[redacted]')
  }
}
