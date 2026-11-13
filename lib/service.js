import { CloudflareConnectorError, redactError } from './errors.js'
import { FLOW_TTL_MS, scopesOf } from './oauth.js'

export function statusOf(flow, connection) {
  const { tokens, pending, correctionScopes, expiresAt } = flow.store.data
  return {
    authorized: Boolean(tokens),
    connected: connection.connected,
    scopes: scopesOf(tokens?.scope ?? ''),
    toolCount: connection.toolNames.length,
    pendingAuthorization: Boolean(pending),
    authorizationExpired: Boolean(pending && Date.now() - pending.startedAt >= FLOW_TTL_MS),
    pendingStepUp: Boolean(pending?.stepUp || correctionScopes),
    requestedScopes: [...(pending?.scopes ?? correctionScopes ?? [])],
    ...(expiresAt === undefined ? {} : { expiresAt: new Date(expiresAt).toISOString() }),
  }
}

function requestObject(value, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new CloudflareConnectorError(`${label} must be an object`, { code: 'invalid_request' })
  }
  return value
}

export function requestCode(input = {}) {
  const { method = 'GET', path, query, body } = requestObject(input, 'Cloudflare request')
  if (typeof method !== 'string' || !/^[A-Za-z]+$/.test(method)) throw new CloudflareConnectorError('Cloudflare request method must be an HTTP verb', { code: 'invalid_request' })
  if (typeof path !== 'string' || !path.startsWith('/') || path.startsWith('//') || /[\\#\x00-\x20\x7f]/.test(path)) {
    throw new CloudflareConnectorError('Cloudflare request path must be an absolute API path, not a URL', { code: 'invalid_request' })
  }
  const request = { method: method.toUpperCase(), path }
  if (query !== undefined) {
    if (!query || typeof query !== 'object' || Array.isArray(query)) throw new CloudflareConnectorError('Cloudflare query must be an object of scalar values', { code: 'invalid_request' })
    const entries = Object.entries(query).filter(([, value]) => value !== undefined && value !== null)
    if (entries.some(([, value]) => !['string', 'number', 'boolean'].includes(typeof value) || (typeof value === 'number' && !Number.isFinite(value)))) {
      throw new CloudflareConnectorError('Cloudflare query values must be strings, finite numbers, or booleans', { code: 'invalid_request' })
    }
    if (entries.length) request.query = Object.fromEntries(entries.map(([key, value]) => [key, String(value)]))
  }
  if (body !== undefined) request.body = body
  let encoded
  try {
    encoded = JSON.stringify(request, (_key, value) => {
      if (['undefined', 'function', 'symbol', 'bigint'].includes(typeof value) || (typeof value === 'number' && !Number.isFinite(value))) {
        throw new Error('Not JSON')
      }
      return value
    })
  } catch {
    throw new CloudflareConnectorError('Cloudflare request body must be serializable JSON', { code: 'invalid_request' })
  }
  return `async () => cloudflare.request(JSON.parse(${JSON.stringify(encoded)}))`
}

export function decodeJsonResult(result) {
  if (result.structuredContent !== undefined) return result.structuredContent
  const text = result.content.filter((block) => block.type === 'text').map((block) => block.text).join('\n')
  try {
    return JSON.parse(text)
  } catch {
    throw new CloudflareConnectorError('Cloudflare MCP tool did not return a JSON result; use callTool for non-JSON content', { code: 'invalid_result' })
  }
}

export function createService(flow, connection) {
  const status = () => statusOf(flow, connection)
  return {
    status,
    listTools: (params, options) => connection.listTools(params, options),
    callTool: (params, options) => connection.callTool(params, options),
    authorize: async ({ scopes = [] } = {}) => {
      const requestedScopes = scopesOf(scopes)
      if (!flow.store.data.pending) flow.validateScopes(requestedScopes)
      await connection.disconnect()
      return flow.begin(requestedScopes)
    },
    finish: async ({ code, state }) => {
      await flow.finish(code, { state })
      await connection.disconnect()
      await connection.connect()
      return status()
    },
    test: async () => {
      await connection.disconnect()
      await connection.connect()
      return { ...status(), tools: [...connection.toolNames] }
    },
    clear: async () => {
      try {
        flow.clear()
      } finally {
        await connection.disconnect()
      }
      return status()
    },
    request: async (request, options = {}) => {
      const { accountId, timeoutMs = 120_000, signal, sensitiveValues = [] } = requestObject(options, 'Cloudflare request options')
      if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) throw new CloudflareConnectorError('timeoutMs must be a positive finite number', { code: 'invalid_request' })
      if (accountId !== undefined && (typeof accountId !== 'string' || !/^[A-Za-z0-9_-]{1,64}$/.test(accountId))) {
        throw new CloudflareConnectorError('Cloudflare accountId has an unexpected format', { code: 'invalid_request' })
      }
      if (!Array.isArray(sensitiveValues) || sensitiveValues.some((value) => typeof value !== 'string')) {
        throw new CloudflareConnectorError('sensitiveValues must be an array of strings', { code: 'invalid_request' })
      }
      const redact = (message) => {
        let text = flow.store.redact(message)
        for (const value of sensitiveValues.filter(Boolean).flatMap((value) => [value, JSON.stringify(value).slice(1, -1)]).sort((a, b) => b.length - a.length)) {
          text = text.replaceAll(value, '[redacted]')
        }
        return text
      }
      try {
        const args = { code: requestCode(request), truncate: false, ...(accountId === undefined ? {} : { account_id: accountId }) }
        const result = await connection.callTool({ name: 'execute', arguments: args }, { signal, timeout: timeoutMs })
        if (flow.store.data.pending) throw flow.requiredError()
        if (result.isError) {
          const text = result.content.filter((block) => block.type === 'text').map((block) => block.text).join('\n') || 'Cloudflare MCP execute failed without a message'
          const match = /\b(?:returned )?HTTP (\d{3})\b/.exec(text)
          throw new CloudflareConnectorError(redact(text), { code: 'api_error', status: match ? Number(match[1]) : null })
        }
        return decodeJsonResult(result)
      } catch (error) {
        throw redactError(error, redact)
      }
    },
  }
}
