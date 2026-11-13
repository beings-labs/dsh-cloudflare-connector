import assert from 'node:assert/strict'
import test from 'node:test'
import { ErrorCode } from '@modelcontextprotocol/sdk/types.js'
import { CloudflareConnectorError, AuthorizationRequiredError } from '../lib/errors.js'
import { createService, decodeJsonResult, requestCode } from '../lib/service.js'
import { setup } from './support.js'

test('public MCP methods preserve pagination, metadata, structured content and isError', async (t) => {
  const { service, authorize, server } = await setup(t)
  await authorize()
  const first = await service.listTools()
  assert.equal(first.nextCursor, 'page-2')
  assert.deepEqual(first._meta, { 'test/page': 'first' })
  assert.deepEqual(first.tools[0].inputSchema, server.tools[0].inputSchema)
  const second = await service.listTools({ cursor: first.nextCursor })
  assert.equal(second.tools[0].name, 'whoami')
  assert.equal(second._meta['test/page'], 'page-2')
  const result = await service.callTool({ name: 'execute', arguments: { code: 'example', mode: 'structured' } })
  assert.equal(result.structuredContent.success, true)
  assert.equal(result._meta['test/result'], 'execute')
  const failure = await service.callTool({ name: 'execute', arguments: { code: 'example', mode: 'error' } })
  assert.equal(failure.isError, true, 'raw MCP tool failures are returned, not converted to transport exceptions')
  await assert.rejects(service.callTool({ name: 'unknown', arguments: { mode: 'protocol-error' } }), (error) => {
    assert.equal(error.code, -32601)
    assert.deepEqual(error.data, { reason: 'test' })
    return true
  })
})

test('raw metadata scope challenges remain visible while preparing step-up', async (t) => {
  const { service, authorize, store } = await setup(t)
  await authorize()
  const result = await service.callTool({ name: 'execute', arguments: { code: 'example', mode: 'meta', requireScope: 'zone.read' } })
  assert.equal(result.isError, true)
  assert.ok(result._meta['mcp/www_authenticate'][0].includes('zone.read'))
  assert.equal(service.status().pendingStepUp, true)
  assert.ok(store.data.pending.authorizeUrl)
  await assert.rejects(service.callTool({ name: 'whoami' }), (error) => {
    assert.ok(error instanceof AuthorizationRequiredError)
    assert.equal(error.code, 'authorization_required')
    assert.equal(error.status, 403)
    assert.ok(error.scopes.includes('zone.read'))
    assert.equal(error.authorizationUrl, store.data.pending.authorizeUrl)
    return true
  })
})

test('the request helper generates safe code, disables truncation and returns JSON', async (t) => {
  const { service, authorize, server, registry } = await setup(t)
  await authorize()
  const body = { domains: ['a"b\\c\n.com'], ...JSON.parse('{"__proto__":{"value":"preserved"}}') }
  const generated = requestCode({ method: 'POST', path: '/example', body })
  const execute = new Function('cloudflare', `return (${generated})()`)
  assert.deepEqual(await execute({ request: async (request) => request.body }), body)
  server.routes.set('POST /accounts/account-1/registrar/domain-check', ({ body: received, query }) => {
    assert.deepEqual(received, body)
    assert.deepEqual(query, { page: '1', archived: 'false' })
    return { success: true, result: { domains: [] } }
  })
  const result = await service.request({
    method: 'post',
    path: '/accounts/account-1/registrar/domain-check',
    query: { page: 1, archived: false, omit: undefined },
    body,
  }, { accountId: 'account-1' })
  assert.deepEqual(result, { success: true, result: { domains: [] } })
  assert.equal(server.toolCalls.at(-1).args.truncate, false)
  assert.equal(server.toolCalls.at(-1).args.account_id, 'account-1')
  assert.equal(registry.has('cloudflare_connector_request'), false, 'the programmatic helper need not add agent tool overhead')
})

test('request errors carry status, code and safe messages, and never retry writes', async (t) => {
  const { service, authorize, server } = await setup(t)
  await authorize()
  const secret = 'epp-code-with-sensitive-content'
  server.failures.set('POST /example', { status: 422, message: `Invalid authorization code ${secret}` })
  const before = server.toolCalls.length
  await assert.rejects(service.request({ method: 'POST', path: '/example' }, { sensitiveValues: [secret] }), (error) => {
    assert.ok(error instanceof CloudflareConnectorError)
    assert.equal(error.code, 'api_error')
    assert.equal(error.status, 422)
    assert.equal(error.message.includes(secret), false)
    assert.equal(error.stack.includes(secret), false)
    return true
  })
  assert.equal(server.toolCalls.length, before + 1)
  server.requiredScopes.set('POST /example', 'registrar-domains.admin')
  await assert.rejects(service.request({ method: 'POST', path: '/example' }), (error) => {
    assert.equal(error.code, 'authorization_required')
    assert.equal(error.status, 403)
    assert.ok(error.authorizationUrl)
    return true
  })
  assert.equal(server.toolCalls.length, before + 2)
})

test('plain Registrar authentication errors do not invent scopes or automatically retry authorization', async (t) => {
  const { service, authorize, server, store } = await setup(t)
  await authorize()
  const path = '/accounts/account-1/registrar/registrations'
  server.failures.set(`GET ${path}`, { status: 401, message: 'Authentication error (10000)' })
  const tokens = { ...store.data.tokens }
  const before = server.tokenRequests.length
  await assert.rejects(service.request({ path }, { accountId: 'account-1' }), (error) => {
    assert.equal(error.code, 'api_error')
    assert.equal(error.status, 401)
    assert.match(error.message, /Authentication error \(10000\)/)
    return true
  })
  assert.equal(server.toolCalls.length, 1)
  assert.equal(server.tokenRequests.length, before)
  assert.deepEqual(store.data.tokens, tokens)
  assert.equal(store.data.pending, undefined)
  assert.equal(store.data.correctionScopes, undefined)
  assert.equal(service.status().pendingStepUp, false)
})

test('the request helper rejects invalid input, non-JSON output and cancelled calls explicitly', async (t) => {
  for (const request of [{ path: 'relative' }, { path: '//attacker.example' }, { path: '/a\nb' }, { path: '/a#fragment' }, { method: 'GET\n', path: '/a' }, { path: '/a', query: { nested: {} } }, { path: '/a', body: { invalid: undefined } }]) {
    assert.throws(() => requestCode(request), (error) => error.code === 'invalid_request')
  }
  const { service, authorize, flow, connection, server } = await setup(t)
  await authorize()
  for (const options of [{ timeoutMs: 0 }, { accountId: 'bad/id' }, { sensitiveValues: [123] }]) {
    await assert.rejects(service.request({ path: '/accounts' }, options), (error) => error.code === 'invalid_request')
  }
  const controller = new AbortController()
  controller.abort()
  const before = server.toolCalls.length
  await assert.rejects(service.request({ path: '/accounts' }, { signal: controller.signal }), /abort/i)
  assert.equal(server.toolCalls.length, before)
  assert.throws(() => decodeJsonResult({ content: [{ type: 'text', text: 'not JSON' }] }), (error) => error.code === 'invalid_result')
  const fake = createService(flow, { ...connection, callTool: async () => ({ content: [{ type: 'text', text: 'secret non-JSON text' }] }) })
  await assert.rejects(fake.request({ path: '/accounts' }), (error) => error.code === 'invalid_result' && !error.message.includes('secret non-JSON text'))
})

test('authorization and status return snapshots rather than mutable internal state', async (t) => {
  const { service, store } = await setup(t)
  await assert.rejects(service.callTool({ name: 'whoami' }), (error) => error.code === 'authorization_required' && error.status === 401)
  const authorization = await service.authorize()
  authorization.scopes.push('unexpected.scope')
  const status = service.status()
  status.requestedScopes.push('another.unexpected.scope')
  assert.equal(store.data.pending.scopes.includes('unexpected.scope'), false)
  assert.equal(store.data.pending.scopes.includes('another.unexpected.scope'), false)
})

test('invalid request and options shapes fail with structured errors before making calls', async (t) => {
  const { service, server } = await setup(t)
  for (const request of [undefined, null, [], 'not-an-object']) {
    assert.throws(() => requestCode(request), (error) => error.code === 'invalid_request')
    await assert.rejects(service.request(request), (error) => error.code === 'invalid_request')
  }
  for (const options of [null, [], 'not-an-object']) {
    await assert.rejects(service.request({ path: '/accounts' }, options), (error) => error.code === 'invalid_request')
  }
  assert.equal(server.requests.length, 0)
})

test('request timeouts are enforced by the MCP SDK and preserve protocol error details', async (t) => {
  const { authorize, service, server } = await setup(t)
  await authorize()
  server.routes.set('GET /slow', async () => {
    await new Promise((resolve) => setTimeout(resolve, 100))
    return { success: true, result: [] }
  })
  await assert.rejects(service.request({ path: '/slow' }, { timeoutMs: 20 }), (error) => {
    assert.equal(error.code, ErrorCode.RequestTimeout)
    assert.equal(error.data.timeout, 20)
    return true
  })
})
