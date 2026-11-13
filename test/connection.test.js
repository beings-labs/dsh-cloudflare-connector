import assert from 'node:assert/strict'
import { existsSync } from 'node:fs'
import test from 'node:test'
import { CloudflareConnection, publicToolName } from '../lib/connection.js'
import { DEFAULT_SCOPES } from '../lib/store.js'
import { setup } from './support.js'

test('real MCP SDK paginates tools and preserves input schemas and structured results', async (t) => {
  const { authorize, server, registry, connection } = await setup(t)
  await authorize()
  assert.deepEqual(connection.toolNames, ['mcp__cloudflare_connector__execute', 'mcp__cloudflare_connector__whoami', 'mcp__cloudflare_connector__search'])
  const tool = registry.get('mcp__cloudflare_connector__execute')
  assert.deepEqual(tool.parameters, server.tools[0].inputSchema)
  const result = await tool.execute({ code: 'example', mode: 'structured' })
  assert.deepEqual(result.structuredContent, { success: true, result: [{ id: 'example.com' }] })
  assert.deepEqual(JSON.parse(tool.output.render({}, result)[0].text), result.structuredContent)
  assert.equal(server.toolCalls.at(-1).name, 'execute', 'send raw MCP name, not public DSH name')
})

for (const mode of ['http', 'meta']) {
  test(`${mode} unsupported scope challenges fail explicitly without poisoning consent or replaying requests`, async (t) => {
    const { authorize, server, service, store } = await setup(t)
    await authorize()
    const tokens = { ...store.data.tokens }
    const before = server.tokenRequests.length
    await assert.rejects(
      service.callTool({ name: 'execute', arguments: { code: 'example', requireScope: 'registrar:read', mode } }),
      (error) => error.code === 'invalid_scope',
    )
    assert.equal(server.toolCalls.length, 1)
    assert.equal(server.tokenRequests.length, before)
    assert.equal(store.data.pending, undefined)
    assert.equal(store.data.correctionScopes, undefined)
    assert.deepEqual(store.data.tokens, tokens)
    assert.equal(service.status().pendingStepUp, false)
    assert.equal((await service.request({ path: '/accounts' })).success, true)
  })

  test(`${mode} step-up uses exactly the challenge scopes, never refreshes or automatically replays the operation`, async (t) => {
    const { authorize, server, flow, registry, store, connection } = await setup(t)
    await authorize()
    const before = server.tokenRequests.length
    const oldExecute = registry.get('mcp__cloudflare_connector__execute')
    const args = { code: 'example', requireScope: 'zone.read', mode }
    await assert.rejects(oldExecute.execute(args), /HTTP 403 insufficient_scope.*cloudflare_connector_authorize/)
    assert.equal(server.tokenRequests.length, before, 'step-up must not refresh an existing narrower grant')
    assert.equal(server.toolCalls.length, 1, 'never automatically retry the operation')
    assert.equal(flow.provider.tokens(), undefined)
    assert.deepEqual(store.data.pending.scopes, [...DEFAULT_SCOPES, 'zone.read'])
    assert.equal(store.data.correctionScopes.at(-1), 'zone.read')
    const url = store.data.pending.authorizeUrl
    assert.equal((await registry.get('cloudflare_connector_status').execute({})).pendingStepUp, true)
    const authorization = await registry.get('cloudflare_connector_authorize').execute({})
    assert.equal(authorization.authorizationUrl, url)
    assert.equal(connection.toolNames.length, 0)
    await registry.get('cloudflare_connector_finish').execute({ code: server.callback(url) })
    assert.equal(store.data.pending, undefined)
    const result = await registry.get('mcp__cloudflare_connector__execute').execute(args)
    assert.equal(result.isError, undefined)
    assert.equal(server.toolCalls.length, 2)
    assert.ok(store.data.tokens.scope.includes('zone.read'))
  })
}

test('the challenged scope list is authoritative, not merged with ungranted configured scopes', async (t) => {
  const { flow, store, server } = await setup(t, { scopes: [...DEFAULT_SCOPES, 'dns.write'] })
  await flow.begin()
  await flow.finish(server.callback(store.data.pending.authorizeUrl, DEFAULT_SCOPES.join(' ')))
  const challenged = [...DEFAULT_SCOPES, 'zone.read'].join(' ')
  await flow.challenge(`Bearer error="insufficient_scope", scope="${challenged}"`)
  assert.equal(new URL(store.data.pending.authorizeUrl).searchParams.get('scope'), challenged)
  assert.equal(store.data.pending.scopes.includes('dns.write'), false)
  await assert.rejects(flow.challenge('Bearer error="insufficient_scope"'), /without requested scopes/)
})

test('SDK retries a 401 with rotated tokens and remote tool errors are failures with redacted secrets', async (t) => {
  const { authorize, server, registry, store } = await setup(t)
  await authorize()
  const previous = store.data.tokens.refresh_token
  server.options.rejectAccess = true
  await registry.get('mcp__cloudflare_connector__execute').execute({ code: 'example' })
  assert.notEqual(store.data.tokens.refresh_token, previous)
  const secret = store.data.tokens.access_token
  await assert.rejects(
    registry.get('mcp__cloudflare_connector__execute').execute({ code: 'example', mode: 'error' }),
    (error) => /API failed/.test(error.message) && !error.message.includes(secret),
  )
})

test('clear deletes credentials and remote tools; captured definitions cannot run after disconnect', async (t) => {
  const { authorize, registry, store, connection, logs } = await setup(t)
  await authorize()
  const remote = registry.get('mcp__cloudflare_connector__execute')
  const secrets = [store.data.tokens.access_token, store.data.tokens.refresh_token]
  const result = await registry.get('cloudflare_connector_clear').execute({})
  assert.equal(result.authorized, false)
  assert.equal(result.connected, false)
  assert.equal(result.toolCount, 0)
  assert.equal(existsSync(store.path), false)
  assert.equal(registry.has('mcp__cloudflare_connector__execute'), false)
  assert.equal(connection.client, undefined)
  await assert.rejects(remote.execute({ code: 'example' }), /disconnected/)
  for (const secret of secrets) assert.equal(JSON.stringify({ result, logs }).includes(secret), false)
})

test('concurrent 401 failures share a single SDK refresh and keep the rotated grant', async (t) => {
  const { authorize, server, registry, store } = await setup(t)
  await authorize()
  const previous = store.data.tokens.refresh_token
  server.options.rejectAccess = 2
  server.options.tokenDelay = 30
  const tool = registry.get('mcp__cloudflare_connector__execute')
  await Promise.all([tool.execute({ code: 'first' }), tool.execute({ code: 'second' })])
  assert.notEqual(store.data.tokens.refresh_token, previous)
  assert.equal(server.tokenRequests.filter((request) => request.grant_type === 'refresh_token').length, 1)
})

test('duplicate registrations roll back without deleting another plugin tool', async (t) => {
  const { flow, authorize, connection, ctx, registry } = await setup(t)
  await authorize()
  await connection.disconnect()
  const existing = { name: 'mcp__cloudflare_connector__whoami' }
  registry.set(existing.name, existing)
  const duplicate = new CloudflareConnection(ctx, flow)
  await assert.rejects(duplicate.connect(), /already registered/)
  assert.equal(registry.get(existing.name), existing)
  assert.equal(registry.has('mcp__cloudflare_connector__execute'), false)
  await duplicate.dispose()
})

test('repeated pagination cursors and duplicate server names fail explicitly with no partially registered tools', async (t) => {
  const { authorize, connection, registry, server } = await setup(t)
  await authorize()
  await connection.disconnect()
  server.options.duplicateCursor = true
  await assert.rejects(connection.connect(), /repeated tools pagination cursor/)
  assert.equal(registry.has('mcp__cloudflare_connector__execute'), false)
  server.options.duplicateCursor = false
  server.options.duplicateTools = true
  await assert.rejects(connection.connect(), /duplicate tool names/)
})

test('execution honors cancellation and rejects invalid arguments', async (t) => {
  const { authorize, registry } = await setup(t)
  await authorize()
  const tool = registry.get('mcp__cloudflare_connector__execute')
  await assert.rejects(tool.execute(null), /must be an object/)
  const controller = new AbortController()
  const call = tool.execute({ code: 'example', mode: 'slow' }, { signal: controller.signal })
  controller.abort()
  await assert.rejects(call, /abort|cancel/i)
  await assert.rejects(registry.get('cloudflare_connector_finish').execute({ wrong: 'value' }), /Invalid arguments/)
})

test('test reconnects and discovers fresh tools instead of reporting only cached state', async (t) => {
  const { authorize, registry, server } = await setup(t)
  await authorize()
  server.tools.push({ name: 'docs', inputSchema: { type: 'object', properties: {} } })
  const result = await registry.get('cloudflare_connector_test').execute({})
  assert.equal(result.toolCount, 4)
  assert.ok(result.tools.includes('mcp__cloudflare_connector__docs'))
})

test('transport closure during initial discovery cannot mark a dead connection as ready', async (t) => {
  const { authorize, connection, registry } = await setup(t)
  await authorize()
  await connection.disconnect()
  t.mock.method(connection, 'syncTools', async (client) => { await client.close() })
  await assert.rejects(connection.connect(), /disconnected/)
  assert.equal(connection.connected, false)
  assert.equal(connection.client, undefined)
  assert.equal(registry.has('mcp__cloudflare_connector__execute'), false)
})

test('tool discovery completing after transport closure cannot restore stale registrations', async (t) => {
  const { authorize, connection, registry, server } = await setup(t)
  await authorize()
  const client = connection.client
  const generation = connection.generation
  let completePage
  t.mock.method(client, 'listTools', () => new Promise((resolve) => { completePage = resolve }))
  const discovery = connection.syncTools(client, generation)
  await client.close()
  completePage({ tools: server.tools })
  await assert.rejects(discovery, /disconnected/)
  assert.equal(connection.connected, false)
  assert.equal(registry.has('mcp__cloudflare_connector__execute'), false)
})

for (const method of ['listTools', 'callTool']) {
  test(`${method} reports disconnection if the transport closes before its continuation`, async (t) => {
    const { authorize, connection } = await setup(t)
    await authorize()
    const client = connection.client
    t.after(() => client.close())
    const request = method === 'callTool' ? connection.callTool({ name: 'whoami', arguments: {} }) : connection.listTools()
    client.onclose()
    await assert.rejects(request, /disconnected/)
  })
}

test('public tool names keep downstream names stable and hash lossy normalizations', () => {
  for (const raw of ['execute', 'whoami', 'search']) assert.equal(publicToolName(raw), `mcp__cloudflare_connector__${raw}`)
  const names = ['name.with.dots', 'name/with/slashes', 'a'.repeat(100)].map(publicToolName)
  for (const name of names) {
    assert.ok(name.length <= 64)
    assert.match(name, /^[A-Za-z0-9_-]+_[a-f0-9]{12}$/)
  }
  assert.notEqual(publicToolName('a.b'), publicToolName('a/b'))
})
