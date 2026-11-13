import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'
import { CredentialStore, DEFAULT_SCOPES } from '../lib/store.js'
import { CloudflareConnectorError } from '../lib/errors.js'
import { FLOW_TTL_MS, OAuthFlow } from '../lib/oauth.js'
import { setup } from './support.js'

test('authorization adds only explicitly requested resource scopes, uses DCR/PKCE, and is single-flight', async (t) => {
  const { flow, server, store } = await setup(t)
  const [first, second] = await Promise.all([flow.begin(['zone.read']), flow.begin()])
  assert.deepEqual(first, second)
  assert.deepEqual(new URL(first.authorizationUrl).searchParams.get('scope').split(' '), [...DEFAULT_SCOPES, 'zone.read'])
  assert.equal(server.registrations.length, 1)
  assert.equal(server.registrations[0].token_endpoint_auth_method, 'none')
  assert.equal(server.registrations[0].client_secret, undefined)
  assert.deepEqual(await flow.begin(['dns.write']), first)
  assert.equal(flow.provider.tokens(), undefined)
  const callback = server.callback(first.authorizationUrl)
  await flow.finish(callback)
  assert.equal(store.data.pending, undefined)
  assert.equal(store.data.tokens.issuer, server.origin)
  assert.ok(store.data.expiresAt > Date.now())
  assert.equal(store.data.clientInformation.issuer, server.origin)
  assert.equal(server.tokenRequests[0].resource, server.endpoint)
  await assert.rejects(async () => flow.finish(callback), /No pending/)
  await flow.begin()
  assert.equal(server.registrations.length, 1, 'reuse dynamic registration')
})

test('unknown scopes fail before registration and a corrected Registrar grant succeeds without clearing credentials', async (t) => {
  const { service, flow, server, store } = await setup(t)
  await assert.rejects(service.authorize({ scopes: ['registrar:read'] }), (error) => {
    assert.ok(error instanceof CloudflareConnectorError)
    assert.equal(error.code, 'invalid_scope')
    assert.equal(error.status, 400)
    assert.match(error.message, /registrar:read/)
    assert.match(error.message, /use registrar-domains\.read/)
    return true
  })
  assert.equal(server.registrations.length, 0)
  assert.equal(store.data.pending, undefined)
  assert.equal(store.data.correctionScopes, undefined)
  assert.equal(service.status().pendingAuthorization, false)
  assert.ok(store.data.discoveryState.authorizationServerMetadata.scopes_supported.includes('registrar-domains.read'))
  const authorization = await service.authorize({ scopes: ['registrar-domains.read'] })
  assert.deepEqual(authorization.scopes, [...DEFAULT_SCOPES, 'registrar-domains.read'])
  assert.equal(new URL(authorization.authorizationUrl).searchParams.get('scope'), authorization.scopes.join(' '))
  assert.equal(server.registrations[0].scope, authorization.scopes.join(' '))
  await flow.finish(server.callback(authorization.authorizationUrl))
  assert.ok(store.data.tokens.scope.includes('registrar-domains.read'))
})

test('configured scopes are checked against authorization metadata, not the resource default scope list', async (t) => {
  const { flow, server, store } = await setup(t, { scopes: [...DEFAULT_SCOPES, 'registrar:read'] })
  await assert.rejects(flow.begin(), (error) => error.code === 'invalid_scope')
  assert.equal(server.registrations.length, 0)
  assert.equal(store.data.pending, undefined)
  const corrected = new OAuthFlow(store, { redirectUrl: flow.redirectUrl, scopes: [...DEFAULT_SCOPES, 'registrar-domains.read'] })
  t.after(() => corrected.dispose())
  assert.deepEqual((await corrected.begin()).scopes, [...DEFAULT_SCOPES, 'registrar-domains.read'])
})

test('cached scope validation retains an existing connection and credentials on invalid proactive authorization', async (t) => {
  const { service, authorize, server, store, connection } = await setup(t)
  await authorize()
  const tokens = { ...store.data.tokens }
  const requestCount = server.requests.length
  await assert.rejects(service.authorize({ scopes: ['registrar:read'] }), (error) => error.code === 'invalid_scope')
  assert.equal(server.requests.length, requestCount)
  assert.equal(connection.connected, true)
  assert.deepEqual(store.data.tokens, tokens)
  assert.equal(store.data.pending, undefined)
  assert.equal((await service.request({ path: '/accounts' })).success, true)
})

test('a restored invalid pending scope list is discarded rather than returning its broken URL forever', async (t) => {
  const { flow, server, store } = await setup(t)
  await flow.begin(['registrar-domains.read'])
  store.update({
    pending: { ...store.data.pending, scopes: [...DEFAULT_SCOPES, 'registrar:read'] },
    correctionScopes: [...DEFAULT_SCOPES, 'registrar:read'],
  })
  const restored = new CredentialStore({ endpoint: server.endpoint, tokenFile: store.path })
  const restarted = new OAuthFlow(restored, { redirectUrl: flow.redirectUrl })
  t.after(() => restarted.dispose())
  await assert.rejects(async () => restarted.begin(['registrar-domains.read']), (error) => error.code === 'invalid_scope')
  assert.equal(restored.data.pending, undefined)
  assert.equal(restored.data.correctionScopes, undefined)
  assert.deepEqual((await restarted.begin(['registrar-domains.read'])).scopes, [...DEFAULT_SCOPES, 'registrar-domains.read'])
})

test('scope discovery remains optional, but an explicitly empty advertised list rejects requested scopes', async (t) => {
  const { flow, server } = await setup(t)
  server.options.scopesSupported = undefined
  assert.ok((await flow.begin(['custom.scope'])).scopes.includes('custom.scope'))
  flow.clear()
  server.options.scopesSupported = []
  await assert.rejects(flow.begin(), (error) => error.code === 'invalid_scope')
})

test('invalid_scope callbacks retain tokens, clear broken consent and never echo callback secrets', async (t) => {
  const { flow, authorize, server, store } = await setup(t)
  await authorize()
  const tokens = { ...store.data.tokens }
  const authorization = await flow.begin(['registrar-domains.read'])
  const callback = new URL(server.callback(authorization.authorizationUrl))
  callback.searchParams.set('error', 'invalid_scope')
  callback.searchParams.set('error_description', 'secret-provider-description')
  const secretCode = callback.searchParams.get('code')
  const secretState = callback.searchParams.get('state')
  const before = server.tokenRequests.length
  await assert.rejects(async () => flow.finish(callback.href), (error) => {
    assert.equal(error.code, 'invalid_scope')
    assert.equal(error.status, 400)
    for (const secret of [secretCode, secretState, 'secret-provider-description']) {
      assert.equal(error.message.includes(secret), false)
      assert.equal(error.stack.includes(secret), false)
    }
    return true
  })
  assert.equal(server.tokenRequests.length, before)
  assert.deepEqual(store.data.tokens, tokens)
  assert.equal(store.data.pending, undefined)
  assert.equal(store.data.correctionScopes, undefined)
  assert.ok((await flow.begin(['registrar-domains.read'])).authorizationUrl)
})

test('SDK invalid_scope errors remain actionable without exposing the provider description', async (t) => {
  const { flow, store } = await setup(t, {
    fetch: async (url, init) => new URL(url).pathname === '/register'
      ? Response.json({ error: 'invalid_scope', error_description: 'secret-registration-description' }, { status: 400 })
      : fetch(url, init),
  })
  await assert.rejects(flow.begin(['registrar-domains.read']), (error) => {
    assert.equal(error.code, 'invalid_scope')
    assert.match(error.message, /registrar-domains\.read/)
    assert.equal(error.message.includes('secret-registration-description'), false)
    assert.equal(error.stack.includes('secret-registration-description'), false)
    return true
  })
  assert.equal(store.data.pending, undefined)
  assert.equal(store.data.correctionScopes, undefined)
})

test('state, issuer, callback target and duplicates are validated before token exchange', async (t) => {
  const { flow, server, store } = await setup(t)
  const { authorizationUrl } = await flow.begin()
  const callback = new URL(server.callback(authorizationUrl))
  const tryUrl = async (change, expression) => {
    const url = new URL(callback)
    change(url)
    await assert.rejects(async () => flow.finish(url.href), expression)
    assert.equal(server.tokenRequests.length, 0)
    assert.ok(store.data.pending)
  }
  await tryUrl((url) => url.searchParams.set('state', 'wrong'), /state mismatch/)
  await tryUrl((url) => url.searchParams.delete('state'), /state mismatch/)
  await tryUrl((url) => url.searchParams.set('iss', 'https://attacker.example'), /issuer mismatch/)
  await tryUrl((url) => { url.pathname = '/other' }, /does not match/)
  await tryUrl((url) => url.searchParams.append('code', 'other'), /duplicate/)
  await tryUrl((url) => { url.searchParams.set('error', 'access_denied'); url.searchParams.set('state', 'wrong') }, /state mismatch/)
  await flow.finish(callback.href)
})

test('pending state and verifier survive restart, including the original redirect URI', async (t) => {
  const { flow, server, store } = await setup(t)
  const { authorizationUrl } = await flow.begin()
  const oldPending = JSON.parse(readFileSync(store.path)).pending
  const restored = new CredentialStore({ endpoint: server.endpoint, tokenFile: store.path })
  const restarted = new OAuthFlow(restored, { redirectUrl: 'http://127.0.0.1:9999/api/dsh-cloudflare-connector/oauth/callback' })
  t.after(() => restarted.dispose())
  assert.deepEqual(await restarted.begin(), await flow.begin())
  assert.equal(restarted.provider.codeVerifier(), oldPending.verifier)
  await restarted.finish(server.callback(authorizationUrl))
  assert.equal(server.tokenRequests[0].redirect_uri, oldPending.redirectUrl)
  assert.equal(restored.data.pending, undefined)
})

test('manual raw codes work, denied and expired flows can be restarted, and exchange errors never echo a code', async (t) => {
  const { flow, server, store } = await setup(t)
  const first = await flow.begin()
  await assert.rejects(async () => flow.finish('super-secret-invalid-code'), (error) => /could not complete/.test(error.message) && !error.message.includes('super-secret-invalid-code'))
  const denied = new URL(server.callback(first.authorizationUrl))
  denied.searchParams.set('error', 'access_denied')
  await assert.rejects(async () => flow.finish(denied.href), /denied/)
  assert.equal(store.data.pending, undefined)
  const next = await flow.begin()
  store.update({ pending: { ...store.data.pending, startedAt: Date.now() - FLOW_TTL_MS - 1 } })
  await assert.rejects(async () => flow.finish(server.callback(next.authorizationUrl)), /expired/)
  const fresh = await flow.begin()
  assert.notEqual(fresh.authorizationUrl, next.authorizationUrl)
  const raw = new URL(server.callback(fresh.authorizationUrl)).searchParams.get('code')
  await flow.finish(raw)
  assert.ok(store.data.tokens)
})

test('proactive refresh is single-flight and persists refresh-token rotation', async (t) => {
  const { flow, store, authorize, server } = await setup(t)
  await authorize()
  const old = store.data.tokens.refresh_token
  store.update({ expiresAt: Date.now() - 1 })
  await Promise.all([flow.refreshIfNeeded(), flow.refreshIfNeeded(), flow.refreshIfNeeded()])
  assert.notEqual(store.data.tokens.refresh_token, old)
  assert.equal(server.tokenRequests.filter((request) => request.grant_type === 'refresh_token').length, 1)
  const restored = new CredentialStore({ endpoint: server.endpoint, tokenFile: store.path })
  assert.equal(restored.data.tokens.refresh_token, store.data.tokens.refresh_token)
})

test('invalid_grant prompts reauthorization instead of retrying forever', async (t) => {
  const { flow, server, store, authorize } = await setup(t)
  await authorize()
  server.options.refreshInvalid = true
  store.update({ expiresAt: Date.now() - 1 })
  await assert.rejects(flow.refreshIfNeeded(), /cloudflare_connector_authorize/)
  assert.equal(store.data.tokens, undefined)
  assert.ok(store.data.pending.authorizeUrl)
})

test('clear cancels an in-flight exchange without recreating credentials', async (t) => {
  const { flow, server, store } = await setup(t)
  const result = await flow.begin()
  server.options.tokenDelay = 100
  const completion = flow.finish(server.callback(result.authorizationUrl))
  flow.clear()
  await assert.rejects(completion, /cancelled/)
  assert.equal(store.data.tokens, undefined)
  assert.equal(store.data.pending, undefined)
})

test('OAuth fetches are bounded without imposing their timeout on MCP requests', async (t) => {
  const signals = []
  const { flow, server } = await setup(t, {
    fetch: async (_url, init) => {
      signals.push(init.signal)
      return new Response('{}', { status: 200 })
    },
  })
  const timeouts = []
  t.mock.method(AbortSignal, 'timeout', (duration) => {
    timeouts.push(duration)
    return new AbortController().signal
  })
  await flow.fetchForEpoch()(server.origin)
  const controller = new AbortController()
  await flow.transportFetch()(server.endpoint, { signal: controller.signal })
  assert.deepEqual(timeouts, [30_000], 'MCP requests must use the SDK request timeout, not the OAuth timeout')
  controller.abort()
  assert.equal(signals[1].aborted, true)
  assert.equal(signals[0].aborted, false)
  flow.clear()
  assert.equal(signals[0].aborted, true)
})

test('a disposed OAuth flow cannot clear credentials owned by a replacement instance', async (t) => {
  const { flow, store } = await setup(t)
  flow.dispose()
  const replacement = new CredentialStore({ endpoint: store.endpoint, tokenFile: store.path })
  replacement.update({ tokens: { access_token: 'replacement-access', token_type: 'bearer' } })
  assert.throws(() => flow.clear(), /cancelled/)
  assert.equal(JSON.parse(readFileSync(store.path)).tokens.access_token, 'replacement-access')
})
