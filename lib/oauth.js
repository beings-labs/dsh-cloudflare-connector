import { randomBytes, timingSafeEqual } from 'node:crypto'
import { auth, extractWWWAuthenticateParams } from '@modelcontextprotocol/sdk/client/auth.js'
import { InvalidScopeError } from '@modelcontextprotocol/sdk/server/auth/errors.js'
import { DEFAULT_SCOPES } from './store.js'
import { AuthorizationRequiredError, CloudflareConnectorError } from './errors.js'

export { AuthorizationRequiredError } from './errors.js'

export const FLOW_TTL_MS = 10 * 60 * 1000
export const CALLBACK_PATH = '/api/dsh-cloudflare-connector/oauth/callback'

export function scopesOf(value) {
  const scopes = typeof value === 'string' ? value.trim().split(/\s+/).filter(Boolean) : value
  if (!Array.isArray(scopes) || scopes.some((scope) => typeof scope !== 'string' || !/^[\x21\x23-\x5b\x5d-\x7e]+$/.test(scope))) {
    throw new Error('OAuth scopes must be nonempty scope names without whitespace, quotes, or backslashes')
  }
  return [...new Set(scopes)]
}

export function isLoopback(hostname) {
  return hostname === 'localhost' || hostname === '[::1]' || hostname === '::1' || /^127(?:\.\d{1,3}){3}$/.test(hostname)
}

function sameState(actual, expected) {
  if (typeof actual !== 'string') return false
  const a = Buffer.from(actual)
  const b = Buffer.from(expected)
  return a.length === b.length && timingSafeEqual(a, b)
}

function compatibleRedirect(registered, current) {
  const a = new URL(registered)
  const b = new URL(current)
  if (isLoopback(a.hostname) && isLoopback(b.hostname)) {
    a.port = ''
    b.port = ''
  }
  return a.href === b.href
}

export class CloudflareOAuthProvider {
  constructor(flow, epoch = flow.epoch) {
    this.flow = flow
    this.epoch = epoch
  }

  check() {
    this.flow.check(this.epoch)
  }

  get redirectUrl() {
    this.check()
    return this.flow.store.data.pending?.redirectUrl ?? this.flow.redirectUrl
  }

  get clientMetadata() {
    return {
      client_name: '@beings-labs/dsh-cloudflare-connector',
      redirect_uris: [this.redirectUrl],
      token_endpoint_auth_method: 'none',
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      scope: this.flow.scopes.join(' '),
    }
  }

  clientInformation() {
    this.check()
    const info = this.flow.store.data.clientInformation
    if (info?.redirect_uris && !info.redirect_uris.some((uri) => compatibleRedirect(uri, this.redirectUrl))) return undefined
    return info
  }

  saveClientInformation(info) {
    this.check()
    if (info.client_secret || (info.token_endpoint_auth_method && info.token_endpoint_auth_method !== 'none')) {
      throw new Error('Cloudflare OAuth registration must be a public client with token_endpoint_auth_method=none')
    }
    this.flow.store.update({ clientInformation: info })
  }

  tokens() {
    this.check()
    return this.flow.store.data.pending ? undefined : this.flow.store.data.tokens
  }

  saveTokens(tokens) {
    this.check()
    const { pending, tokens: previous } = this.flow.store.data
    this.flow.store.update({
      tokens: {
        ...tokens,
        ...(!pending && !tokens.refresh_token && previous?.refresh_token ? { refresh_token: previous.refresh_token } : {}),
        scope: tokens.scope ?? (pending ? pending.scopes.join(' ') : previous?.scope),
      },
      expiresAt: tokens.expires_in === undefined ? undefined : Date.now() + tokens.expires_in * 1000,
    })
  }

  state() {
    this.check()
    return this.flow.ensurePending().state
  }

  saveCodeVerifier(verifier) {
    this.check()
    this.flow.store.update({ pending: { ...this.flow.ensurePending(), verifier } })
  }

  codeVerifier() {
    this.check()
    const verifier = this.flow.store.data.pending?.verifier
    if (!verifier) throw new Error('No pending Cloudflare PKCE verifier; run cloudflare_connector_authorize again')
    return verifier
  }

  redirectToAuthorization(url) {
    this.check()
    const pending = this.flow.ensurePending()
    const target = new URL(url)
    target.searchParams.set('scope', pending.scopes.join(' '))
    this.flow.store.update({ pending: { ...pending, authorizeUrl: target.href } })
  }

  discoveryState() {
    this.check()
    this.flow.validateScopes(this.flow.store.data.pending?.scopes ?? [])
    return this.flow.store.data.discoveryState
  }

  saveDiscoveryState(state) {
    this.check()
    this.flow.store.update({ discoveryState: state })
    this.flow.validateScopes(this.flow.store.data.pending?.scopes ?? [])
  }

  async validateResourceURL(serverUrl, resource) {
    this.check()
    if (new URL(serverUrl).href !== this.flow.store.endpoint || (resource && new URL(resource).href !== this.flow.store.endpoint)) {
      throw new Error('Cloudflare OAuth resource does not match the configured MCP endpoint')
    }
    return new URL(this.flow.store.endpoint)
  }

  invalidateCredentials(scope) {
    this.check()
    const patch = {}
    if (scope === 'all' || scope === 'client') patch.clientInformation = undefined
    if (scope === 'all' || scope === 'tokens') {
      patch.tokens = undefined
      patch.expiresAt = undefined
    }
    if (scope === 'all' || scope === 'discovery') patch.discoveryState = undefined
    if ((scope === 'all' || scope === 'verifier') && this.flow.store.data.pending) {
      patch.pending = { ...this.flow.store.data.pending, verifier: undefined, authorizeUrl: undefined }
    }
    this.flow.store.update(patch)
  }
}

export class OAuthFlow {
  constructor(store, { redirectUrl, scopes = DEFAULT_SCOPES, fetch: fetchImpl = globalThis.fetch } = {}) {
    this.store = store
    this.redirectUrl = redirectUrl
    this.scopes = scopesOf(scopes)
    this.fetchImpl = fetchImpl
    this.epoch = 0
    this.controller = new AbortController()
    this.disposed = false
  }

  check(epoch = this.epoch) {
    if (this.disposed || epoch !== this.epoch) throw new Error('Cloudflare authorization operation was cancelled')
  }

  get provider() {
    return new CloudflareOAuthProvider(this)
  }

  fetchForEpoch({ timeoutMs = 30_000 } = {}) {
    const epoch = this.epoch
    const signal = this.controller.signal
    return async (url, init = {}) => {
      this.check(epoch)
      const response = await this.fetchImpl(url, {
        ...init,
        signal: AbortSignal.any([
          signal,
          ...(timeoutMs === null ? [] : [AbortSignal.timeout(timeoutMs)]),
          ...(init.signal ? [init.signal] : []),
        ]),
      })
      this.check(epoch)
      return response
    }
  }

  ensurePending(scopes, stepUp = false) {
    this.check()
    if (this.store.data.pending && Date.now() - this.store.data.pending.startedAt < FLOW_TTL_MS) return this.store.data.pending
    const requestedScopes = scopesOf(scopes ?? this.store.data.correctionScopes ?? [
      ...this.scopes, ...scopesOf(this.store.data.tokens?.scope ?? ''),
    ])
    this.validateScopes(requestedScopes)
    const pending = {
      state: randomBytes(32).toString('base64url'),
      scopes: requestedScopes,
      redirectUrl: this.redirectUrl,
      startedAt: Date.now(),
      stepUp: stepUp || Boolean(this.store.data.correctionScopes),
    }
    this.store.update({ pending })
    return pending
  }

  requiredError() {
    return new AuthorizationRequiredError(this.store.data.pending)
  }

  scopeError(scopes) {
    const supported = this.store.data.discoveryState?.authorizationServerMetadata?.scopes_supported
    const hint = scopes.some((scope) => scope.startsWith('registrar')) && supported?.includes('registrar-domains.read')
      ? ' For Registrar reads, use registrar-domains.read, not registrar:read.'
      : ''
    return new CloudflareConnectorError(
      `Cloudflare OAuth invalid_scope: cannot authorize scopes ${scopes.join(' ')}. ` +
      'Use only scopes advertised by the authorization server in scopes_supported.' + hint +
      ' Call cloudflare_connector_authorize with supported scopes; retrying unchanged scopes will not help.',
      { code: 'invalid_scope', status: 400 },
    )
  }

  validateScopes(scopes) {
    const supported = this.store.data.discoveryState?.authorizationServerMetadata?.scopes_supported
    if (supported === undefined) return
    if (!Array.isArray(supported) || supported.some((scope) => typeof scope !== 'string')) {
      throw new Error('Cloudflare OAuth authorization server returned invalid scopes_supported metadata')
    }
    const unsupported = scopes.filter((scope) => !supported.includes(scope))
    if (unsupported.length) throw this.scopeError(unsupported)
  }

  begin(extraScopes = []) {
    this.check()
    if (this.finishing) return Promise.reject(new Error('Cloudflare authorization is completing; wait before authorizing again'))
    if (this.beginning) return this.beginning
    const pending = this.store.data.pending
    try {
      if (pending?.authorizeUrl && Date.now() - pending.startedAt < FLOW_TTL_MS) {
        this.validateScopes(pending.scopes)
        return Promise.resolve(this.authorizationView())
      }
      const scopes = scopesOf(this.store.data.correctionScopes ?? [
        ...this.scopes, ...scopesOf(this.store.data.tokens?.scope ?? ''), ...scopesOf(extraScopes),
      ])
      this.ensurePending(scopes, Boolean(this.store.data.correctionScopes))
    } catch (error) {
      if (error instanceof CloudflareConnectorError && error.code === 'invalid_scope') {
        this.store.update({ pending: undefined, correctionScopes: undefined })
      }
      throw error
    }
    const epoch = this.epoch
    const task = this.startAuthorization(epoch).finally(() => {
      if (this.beginning === task) this.beginning = undefined
    })
    this.beginning = task
    return task
  }

  async startAuthorization(epoch) {
    try {
      const result = await auth(this.provider, {
        serverUrl: this.store.endpoint,
        scope: this.store.data.pending.scopes.join(' '),
        fetchFn: this.fetchForEpoch(),
      })
      this.check(epoch)
      if (result !== 'REDIRECT' || !this.store.data.pending?.authorizeUrl) throw new Error('Expected OAuth authorization redirect')
      return this.authorizationView()
    } catch (error) {
      this.check(epoch)
      const failure = this.failure('start', error)
      this.store.update({ pending: undefined, ...(failure.code === 'invalid_scope' ? { correctionScopes: undefined } : {}) })
      throw failure
    }
  }

  authorizationView() {
    const pending = this.store.data.pending
    return {
      authorizationUrl: pending.authorizeUrl,
      scopes: [...pending.scopes],
      stepUp: pending.stepUp,
      instructions: 'Open this URL in your browser and approve the requested Cloudflare permissions. Return to DSH after the callback. If it cannot open, pass the full callback URL to cloudflare_connector_finish.',
    }
  }

  validateCallback(state, issuer) {
    const pending = this.store.data.pending
    if (!pending) throw new Error('No pending Cloudflare authorization; run cloudflare_connector_authorize')
    if (Date.now() - pending.startedAt >= FLOW_TTL_MS) {
      throw new Error('Cloudflare authorization expired; run cloudflare_connector_authorize for a new URL')
    }
    if (!sameState(state, pending.state)) throw new Error('Cloudflare OAuth state mismatch; use the callback from the current authorization')
    const expectedIssuer = this.store.data.discoveryState?.authorizationServerMetadata?.issuer
    if (issuer !== undefined && (!expectedIssuer || issuer !== expectedIssuer)) throw new Error('Cloudflare OAuth callback issuer mismatch')
    return pending
  }

  finish(input, { state, issuer, callback = false } = {}) {
    this.check()
    if (this.finishing) return Promise.reject(new Error('Cloudflare authorization is already completing'))
    if (this.beginning) return Promise.reject(new Error('Cloudflare authorization is still starting'))
    let code = input
    if (typeof input !== 'string' || input.trim().length === 0) throw new Error('Provide an authorization code or full callback URL')
    if (/^https?:\/\//i.test(input)) {
      const url = new URL(input)
      const expected = new URL(this.store.data.pending?.redirectUrl ?? this.redirectUrl)
      if (url.origin !== expected.origin || url.pathname !== expected.pathname || url.hash) {
        throw new Error('Cloudflare callback URL does not match the pending redirect')
      }
      if (['code', 'state', 'iss', 'error'].some((key) => url.searchParams.getAll(key).length > 1)) {
        throw new Error('Cloudflare callback contains duplicate OAuth parameters')
      }
      state = url.searchParams.get('state')
      issuer = url.searchParams.get('iss') ?? undefined
      const pending = this.validateCallback(state, issuer)
      if (url.searchParams.has('error')) {
        if (url.searchParams.get('error') === 'invalid_scope') {
          const error = this.scopeError(pending.scopes)
          this.store.update({ pending: undefined, correctionScopes: undefined })
          throw error
        }
        this.store.update({ pending: undefined })
        throw new Error('Cloudflare authorization was denied or failed; run cloudflare_connector_authorize to try again')
      }
      code = url.searchParams.get('code')
    } else {
      const pending = this.store.data.pending
      this.validateCallback(state ?? (callback ? undefined : pending?.state), issuer)
    }
    if (typeof code !== 'string' || !code.trim() || /[\s?#&]/.test(code)) throw new Error('Cloudflare callback is missing a valid authorization code')
    const task = this.exchange(code, this.epoch).finally(() => {
      if (this.finishing === task) this.finishing = undefined
    })
    this.finishing = task
    return task
  }

  async exchange(code, epoch) {
    try {
      const result = await auth(this.provider, {
        serverUrl: this.store.endpoint,
        authorizationCode: code,
        scope: this.store.data.pending.scopes.join(' '),
        fetchFn: this.fetchForEpoch(),
      })
      this.check(epoch)
      if (result !== 'AUTHORIZED' || !this.store.data.tokens) throw new Error('Cloudflare did not issue tokens')
      this.store.update({ pending: undefined, correctionScopes: undefined })
      return { authorized: true, scopes: scopesOf(this.store.data.tokens.scope ?? '') }
    } catch (error) {
      this.check(epoch)
      const failure = this.failure('complete', error)
      if (failure.code === 'invalid_scope') this.store.update({ pending: undefined, correctionScopes: undefined })
      throw failure
    }
  }

  async challenge(header) {
    const response = new Response(null, { headers: { 'www-authenticate': header } })
    const { scope, error } = extractWWWAuthenticateParams(response)
    if (error !== 'insufficient_scope') return false
    if (!scope?.trim()) throw new Error('Cloudflare returned HTTP 403 insufficient_scope without requested scopes; inspect permissions with Cloudflare before retrying')
    const scopes = scopesOf(scope)
    this.validateScopes(scopes)
    this.store.update({ correctionScopes: scopes })
    await this.begin()
    return true
  }

  transportFetch() {
    const fetchImpl = this.fetchForEpoch({ timeoutMs: null })
    return async (url, init) => {
      let response = await fetchImpl(url, init)
      if (response.status === 401 && new URL(url).href === this.store.endpoint && this.store.data.tokens && !this.store.data.pending) {
        await response.body?.cancel()
        const headers = new Headers(init?.headers)
        const rejectedToken = headers.get('authorization')
        // Share one SDK refresh across concurrent requests rejected with the same token.
        if (rejectedToken === `Bearer ${this.store.data.tokens.access_token}`) await this.refreshIfNeeded(true)
        if (this.store.data.pending) throw this.requiredError()
        headers.set('authorization', `Bearer ${this.store.data.tokens.access_token}`)
        response = await fetchImpl(url, { ...init, headers })
        if (response.status === 401) {
          await response.body?.cancel()
          throw new Error('Cloudflare MCP returned HTTP 401 after token refresh; run cloudflare_connector_authorize to reconnect')
        }
      }
      if (response.status === 403) {
        const header = response.headers.get('www-authenticate')
        if (header && extractWWWAuthenticateParams(response).error === 'insufficient_scope') {
          await response.body?.cancel()
          if (await this.challenge(header)) throw this.requiredError()
        }
      }
      return response
    }
  }

  refreshIfNeeded(force = false) {
    if (this.refreshing) return this.refreshing
    const task = this.refresh(force).finally(() => {
      if (this.refreshing === task) this.refreshing = undefined
    })
    this.refreshing = task
    return task
  }

  async refresh(force) {
    const { tokens, expiresAt, pending } = this.store.data
    if (pending) throw this.requiredError()
    if (!tokens) throw this.requiredError()
    if (!force && (expiresAt === undefined || expiresAt > Date.now() + 60_000)) return
    const epoch = this.epoch
    try {
      const result = await auth(this.provider, {
        serverUrl: this.store.endpoint,
        scope: scopesOf(tokens.scope ?? this.scopes).join(' '),
        fetchFn: this.fetchForEpoch(),
      })
      this.check(epoch)
      if (result !== 'AUTHORIZED') throw this.requiredError()
    } catch (error) {
      if (error instanceof AuthorizationRequiredError) throw error
      this.check(epoch)
      throw this.failure('refresh', error)
    }
  }

  failure(operation, error) {
    if (error instanceof CloudflareConnectorError && error.code === 'invalid_scope') return error
    if (error instanceof InvalidScopeError) return this.scopeError(this.store.data.pending?.scopes ?? this.scopes)
    const kind = /^[A-Za-z]+Error$/.test(error?.name) ? ` (${error.name})` : ''
    return new Error(`Cloudflare OAuth could not ${operation}${kind}. Check the endpoint and network, then retry cloudflare_connector_authorize. If registration is invalid, run cloudflare_connector_clear first.`)
  }

  clear() {
    this.check()
    this.controller.abort()
    this.epoch++
    this.controller = new AbortController()
    this.beginning = undefined
    this.finishing = undefined
    this.refreshing = undefined
    this.store.clear()
  }

  dispose() {
    this.disposed = true
    this.controller.abort()
    this.epoch++
  }
}
