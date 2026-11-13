import assert from 'node:assert/strict'
import { join } from 'node:path'
import test from 'node:test'
import { apply, Config } from '../index.js'
import { CALLBACK_PATH } from '../lib/oauth.js'
import { fakeContext, fakeServer, serve, temporaryDirectory } from './support.js'

test('plugin registers only tools, a callback and guidance; a real browser redirect completes OAuth', async (t) => {
  const directory = temporaryDirectory(t)
  const server = await fakeServer(t)
  const harness = fakeContext()
  const callbackOrigin = await serve(t, (req, res) => {
    const route = harness.routes.get(new URL(req.url, 'http://localhost').pathname)
    if (route) return route.handler(req, res)
    res.writeHead(404)
    res.end()
  })
  harness.ctx.webServer.getOrigin = () => callbackOrigin
  apply(harness.ctx, { endpoint: server.endpoint, tokenFile: join(directory, 'auth.json') })
  t.after(() => harness.dispose())
  assert.equal(harness.registry.size, 5)
  const service = harness.ctx.cloudflareConnector
  assert.equal(service.status().authorized, false)
  function assertLosslessJson(value) {
    if (value === null || typeof value !== 'object') {
      assert.ok(['string', 'number', 'boolean'].includes(typeof value) || value === null)
      return
    }
    if (!Array.isArray(value)) assert.deepEqual(Reflect.ownKeys(value), Object.keys(value))
    for (const child of Object.values(value)) assertLosslessJson(child)
  }
  for (const tool of harness.registry.values()) assertLosslessJson(tool.parameters)
  assert.equal(harness.routes.size, 1)
  assert.equal(harness.sections.size, 1)
  const section = [...harness.sections.values()][0]
  assert.equal(section.interpolate, false)
  assert.match(section.text, /cloudflare_connector_authorize/)
  const initial = await harness.registry.get('cloudflare_connector_status').execute({})
  assert.equal(initial.authorized, false)
  await assert.rejects(harness.registry.get('cloudflare_connector_test').execute({}), /cloudflare_connector_authorize/)
  const result = await harness.registry.get('cloudflare_connector_authorize').execute({})
  assert.deepEqual(Config.parse({}).scopes, ['user:read', 'account:read'])
  assert.equal(new URL(result.authorizationUrl).searchParams.get('scope'), 'user:read account:read')
  assert.equal(server.registrations[0].client_name, '@beings-labs/dsh-cloudflare-connector')
  const response = await fetch(result.authorizationUrl)
  assert.equal(response.status, 200)
  assert.match(await response.text(), /Authorization complete/)
  assert.equal(response.headers.get('referrer-policy'), 'no-referrer')
  assert.equal(response.headers.get('cache-control'), 'no-store')
  const ready = await harness.registry.get('cloudflare_connector_status').execute({})
  assert.equal(ready.authorized, true)
  assert.equal(ready.connected, true)
  assert.deepEqual(ready.scopes, ['user:read', 'account:read'])
  assert.equal(ready.toolCount, 3)
  assert.equal(harness.registry.size, 8)
  const invalid = await fetch(`${callbackOrigin}${CALLBACK_PATH}?code=do-not-log-this-code&state=wrong`)
  assert.equal(invalid.status, 400)
  assert.equal((await invalid.text()).includes('do-not-log-this-code'), false)
  assert.equal(JSON.stringify(harness.logs).includes('do-not-log-this-code'), false)
  await harness.dispose()
  assert.equal(harness.registry.size, 0)
  assert.equal(harness.routes.size, 0)
  assert.equal(harness.sections.size, 0)
  assert.equal(harness.ctx.cloudflareConnector, undefined)
  await assert.rejects(service.callTool({ name: 'whoami' }), /disposed/)
})

test('callback rejects remote peers, bad Host and mutation methods without exchanging a code', async (t) => {
  const directory = temporaryDirectory(t)
  const server = await fakeServer(t)
  const harness = fakeContext()
  apply(harness.ctx, { endpoint: server.endpoint, tokenFile: join(directory, 'auth.json') })
  t.after(() => harness.dispose())
  const route = harness.routes.get(CALLBACK_PATH)
  async function request({ address = '127.0.0.1', host = '127.0.0.1:4899', method = 'GET' }) {
    const headers = {}
    const result = {
      status: undefined,
      setHeader: (name, value) => { headers[name] = value },
      writeHead: (status) => { result.status = status },
      end() {},
    }
    await route.handler({ url: CALLBACK_PATH, socket: { remoteAddress: address }, headers: { host }, method }, result)
    return { ...result, headers }
  }
  assert.equal((await request({ address: '198.51.100.1' })).status, 403)
  assert.equal((await request({ host: 'attacker.example' })).status, 403)
  const post = await request({ method: 'POST' })
  assert.equal(post.status, 405)
  assert.equal(post.headers.allow, 'GET')
  assert.equal(server.tokenRequests.length, 0)
})

test('browser callback reports invalid_scope instead of suggesting unchanged authorization retries', async (t) => {
  const directory = temporaryDirectory(t)
  const server = await fakeServer(t)
  const harness = fakeContext()
  apply(harness.ctx, { endpoint: server.endpoint, tokenFile: join(directory, 'auth.json') })
  t.after(() => harness.dispose())
  const authorization = await harness.ctx.cloudflareConnector.authorize()
  const callback = new URL(server.callback(authorization.authorizationUrl))
  callback.searchParams.set('error', 'invalid_scope')
  callback.searchParams.set('error_description', 'secret-callback-description')
  let status
  let page
  await harness.routes.get(CALLBACK_PATH).handler({
    url: callback.pathname + callback.search,
    method: 'GET',
    socket: { remoteAddress: '127.0.0.1' },
    headers: { host: callback.host },
  }, {
    writeHead: (value) => { status = value },
    end: (value) => { page = value },
  })
  assert.equal(status, 400)
  assert.match(page, /invalid_scope/)
  assert.match(page, /supported OAuth scopes/)
  assert.match(harness.logs.at(-1).message, /invalid_scope/)
  for (const secret of [callback.searchParams.get('code'), callback.searchParams.get('state'), 'secret-callback-description']) {
    assert.equal(page.includes(secret), false)
    assert.equal(JSON.stringify(harness.logs).includes(secret), false)
  }
  assert.equal(server.tokenRequests.length, 0)
  assert.equal(harness.ctx.cloudflareConnector.status().pendingAuthorization, false)
})

test('uses the GUI HTTPS origin and reconnects from persisted credentials on a new plugin instance', async (t) => {
  const directory = temporaryDirectory(t)
  const server = await fakeServer(t)
  const tokenFile = join(directory, 'auth.json')
  const first = fakeContext()
  first.ctx.webServer.getOrigin = () => 'https://localhost:7044'
  apply(first.ctx, { endpoint: server.endpoint, tokenFile })
  t.after(() => first.dispose())
  const result = await first.registry.get('cloudflare_connector_authorize').execute({})
  assert.equal(new URL(result.authorizationUrl).searchParams.get('redirect_uri'), `https://localhost:7044${CALLBACK_PATH}`)
  await first.registry.get('cloudflare_connector_finish').execute({ code: server.callback(result.authorizationUrl) })
  await first.dispose()
  const second = fakeContext()
  second.ctx.webServer.getOrigin = () => 'https://localhost:7044'
  apply(second.ctx, { endpoint: server.endpoint, tokenFile })
  t.after(() => second.dispose())
  const status = await second.registry.get('cloudflare_connector_test').execute({})
  assert.equal(status.authorized, true)
  assert.equal(status.connected, true)
  assert.equal(status.toolCount, 3)
  assert.equal(server.registrations.length, 1)
})

test('disabled and announcement configuration work; invalid endpoints and config fail before mounting', () => {
  const disabled = fakeContext()
  apply(disabled.ctx, { enabled: false })
  assert.equal(disabled.registry.size, 0)
  assert.equal(disabled.routes.size, 0)
  assert.equal(disabled.ctx.cloudflareConnector, undefined)
  assert.equal(Config['~standard'].validate({}).issues, undefined)
  assert.equal(Config['~standard'].validate(undefined).issues, undefined)
  assert.deepEqual(Config.parse(undefined), Config.parse({}))
  for (const config of [{ scopes: ['contains whitespace'] }, { enabled: 'yes' }, { endpoint: 'http://insecure.example/mcp' }, { endpoint: 'https://user:password@example.com/mcp' }]) {
    const harness = fakeContext()
    assert.throws(() => apply(harness.ctx, config))
    assert.equal(harness.registry.size, 0)
  }
})

test('announcement can be disabled and partial activation rolls back', async (t) => {
  const directory = temporaryDirectory(t)
  const harness = fakeContext()
  apply(harness.ctx, { announceToAgent: false, tokenFile: join(directory, 'auth.json') })
  t.after(() => harness.dispose())
  assert.equal(harness.sections.size, 0)
  const conflict = fakeContext()
  conflict.registry.set('cloudflare_connector_finish', { name: 'cloudflare_connector_finish' })
  assert.throws(() => apply(conflict.ctx, { tokenFile: join(directory, 'other.json') }), /already registered/)
  assert.deepEqual([...conflict.registry.keys()], ['cloudflare_connector_finish'])
  assert.equal(conflict.routes.size, 0)
})

test('connector namespaces leave community tools, service and callback untouched', async (t) => {
  const directory = temporaryDirectory(t)
  const server = await fakeServer(t)
  const harness = fakeContext()
  const legacyNames = ['cloudflare_mcp_authorize', 'cloudflare_mcp_finish', 'cloudflare_mcp_status', 'cloudflare_mcp_test', 'cloudflare_mcp_clear', 'mcp__cloudflare__execute', 'mcp__cloudflare__whoami', 'mcp__cloudflare__search']
  const legacyTools = legacyNames.map((name) => ({ name }))
  for (const tool of legacyTools) harness.registry.set(tool.name, tool)
  const legacyPath = '/api/dsh-cloudflare-mcp/oauth/callback'
  const legacyRoute = { path: legacyPath }
  harness.routes.set(legacyPath, legacyRoute)
  const legacyService = {}
  harness.ctx.cloudflareMcp = legacyService
  apply(harness.ctx, { endpoint: server.endpoint, tokenFile: join(directory, 'auth.json') })
  t.after(() => harness.dispose())
  const service = harness.ctx.cloudflareConnector
  const authorization = await service.authorize()
  await service.finish({ code: server.callback(authorization.authorizationUrl) })
  assert.equal(harness.registry.size, legacyTools.length + 8)
  assert.equal(harness.routes.size, 2)
  assert.ok(harness.registry.has('mcp__cloudflare_connector__execute'))
  await harness.dispose()
  assert.equal(harness.ctx.cloudflareConnector, undefined)
  assert.equal(harness.ctx.cloudflareMcp, legacyService)
  assert.equal(harness.routes.get(legacyPath), legacyRoute)
  assert.equal(harness.routes.size, 1)
  assert.deepEqual([...harness.registry.values()], legacyTools)
})
