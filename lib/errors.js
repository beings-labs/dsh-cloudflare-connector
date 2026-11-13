export class CloudflareConnectorError extends Error {
  constructor(message, { code = 'mcp_error', status = null } = {}) {
    super(message)
    this.name = 'CloudflareConnectorError'
    this.code = code
    this.status = status
  }
}

export class AuthorizationRequiredError extends CloudflareConnectorError {
  constructor(pending) {
    super(`Cloudflare authorization required${pending?.stepUp ? ' (HTTP 403 insufficient_scope)' : ''}. ` +
      'Call cloudflare_connector_authorize, open its authorization URL, and retry the original operation only after authorization completes.' +
      (pending?.scopes.length ? ` Requested scopes: ${pending.scopes.join(' ')}.` : '') +
      (pending?.authorizeUrl ? ` Authorization URL: ${pending.authorizeUrl}` : ''),
    { code: 'authorization_required', status: pending?.stepUp ? 403 : 401 })
    this.name = 'AuthorizationRequiredError'
    this.scopes = [...(pending?.scopes ?? [])]
    this.authorizationUrl = pending?.authorizeUrl
  }
}

export function redactError(error, redact) {
  if (!(error instanceof Error)) return new Error(redact(String(error)))
  const message = redact(error.message)
  if (message !== error.message) Object.defineProperty(error, 'message', { value: message, writable: true, configurable: true })
  if (typeof error.stack === 'string') {
    const stack = redact(error.stack)
    if (stack !== error.stack) Object.defineProperty(error, 'stack', { value: stack, writable: true, configurable: true })
  }
  return error
}
