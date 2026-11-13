import assert from 'node:assert/strict'
import { createHash, randomUUID } from 'node:crypto'
import { mkdtempSync, rmSync } from 'node:fs'
import { createServer } from 'node:http'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { once } from 'node:events'
import { CredentialStore } from '../lib/store.js'
import { OAuthFlow } from '../lib/oauth.js'
import { CloudflareConnection } from '../lib/connection.js'
import { buildTools } from '../lib/tools.js'
import { createService } from '../lib/service.js'

export function temporaryDirectory(t) {
  const directory = mkdtempSync(join(tmpdir(), 'dsh-cloudflare-connector-test-'))
  t.after(() => rmSync(directory, { recursive: true, force: true }))
  return directory
}

export function fakeContext() {
  const registry = new Map()
  const routes = new Map()
  const sections = new Map()
  const effects = []
  const logs = []
  const ctx = {
    logger: Object.fromEntries(['info', 'warn', 'error'].map((level) => [level, (message) => logs.push({ level, message })])),
    get(name) { return ctx[name] },
    provide(name, value) {
      if (Object.hasOwn(ctx, name)) throw new Error(`Duplicate service ${name}`)
      ctx[name] = value
      return () => { delete ctx[name] }
    },
    tools: {
      register(tool) {
        if (registry.has(tool.name)) throw new Error(`tool "${tool.name}" is already registered; remove the duplicate plugin entry`)
        registry.set(tool.name, tool)
        return () => registry.delete(tool.name)
      },
      schemas: () => [...registry.values()].map(({ name, description, parameters }) => ({ name, description, parameters })),
      async execute({ calls, signal }) {
        return {
          results: await Promise.all(calls.map(async (call) => {
            try {
              const tool = registry.get(call.name)
              if (!tool) throw new Error(`No tool ${call.name}`)
              const value = await tool.execute(call.arguments, { signal })
              return { callId: call.id, result: { value, content: tool.output.render(call.arguments, value) } }
            } catch (error) {
              return { callId: call.id, result: { isError: true, content: [{ type: 'text', text: error.message }] } }
            }
          })),
        }
      },
    },
    webServer: {
      getOrigin: () => 'http://127.0.0.1:4899',
      register(route) {
        if (routes.has(route.path)) throw new Error('Duplicate route')
        routes.set(route.path, route)
        return () => routes.delete(route.path)
      },
    },
    systemPrompt: {
      section(section) {
        if (sections.has(section.name)) throw new Error('Duplicate section')
        sections.set(section.name, section)
        return () => sections.delete(section.name)
      },
    },
    effect(setup) {
      const dispose = setup()
      effects.push(dispose)
      return dispose
    },
  }
  return {
    ctx, registry, routes, sections, logs,
    async dispose() {
      for (const dispose of effects.splice(0).reverse()) await dispose()
    },
  }
}

export async function serve(t, handler) {
  const server = createServer((req, res) => {
    Promise.resolve(handler(req, res)).catch((error) => {
      res.writeHead(500, { 'content-type': 'application/json' })
      res.end(JSON.stringify({ error: 'test_server_error', message: error.message }))
    })
  })
  server.listen(0, '127.0.0.1')
  await once(server, 'listening')
  t.after(() => new Promise((resolve, reject) => {
    server.close((error) => error ? reject(error) : resolve())
    server.closeAllConnections()
  }))
  return `http://127.0.0.1:${server.address().port}`
}

export async function fakeServer(t) {
  const clients = new Map()
  const codes = new Map()
  const access = new Map()
  const refresh = new Map()
  const requests = []
  const registrations = []
  const tokenRequests = []
  const toolCalls = []
  const requiredScopes = new Map()
  const failures = new Map()
  const options = {
    paginated: true, duplicateCursor: false, duplicateTools: false, refreshInvalid: false, rejectAccess: false, tokenDelay: 0,
    scopesSupported: ['user:read', 'account:read', 'offline_access', 'zone.read', 'dns.read', 'dns.write', 'registrar-domains.read', 'registrar-domains.admin'],
  }
  const routes = new Map([
    ['GET /accounts', { success: true, result: [{ id: 'account-1', name: 'Test account' }] }],
  ])
  const inputSchema = {
    type: 'object',
    properties: {
      code: { type: 'string' },
      account_id: { type: 'string' },
      truncate: { type: 'boolean' },
      requireScope: { type: 'string' },
      mode: { type: 'string' },
      custom: { anyOf: [{ type: 'string' }, { type: 'number' }] },
    },
    required: ['code'],
  }
  const tools = [
    { name: 'execute', description: 'Execute Cloudflare API code', inputSchema },
    { name: 'whoami', description: 'Identity', inputSchema: { type: 'object', properties: {} } },
    { name: 'search', description: 'Search', inputSchema: { type: 'object', properties: { query: { type: 'string' } } } },
  ]
  function json(res, status, value, headers = {}) {
    res.writeHead(status, { 'content-type': 'application/json', ...headers })
    res.end(JSON.stringify(value))
  }
  function callback(authorizationUrl, grantedScopes) {
    const url = new URL(authorizationUrl)
    assert.equal(url.searchParams.get('code_challenge_method'), 'S256')
    assert.equal(url.searchParams.get('resource'), `${origin}/mcp`)
    const clientId = url.searchParams.get('client_id')
    assert.ok(clients.has(clientId))
    const code = `code-${randomUUID()}`
    codes.set(code, {
      clientId,
      redirectUrl: url.searchParams.get('redirect_uri'),
      challenge: url.searchParams.get('code_challenge'),
      scope: grantedScopes ?? url.searchParams.get('scope'),
    })
    const result = new URL(url.searchParams.get('redirect_uri'))
    result.searchParams.set('code', code)
    result.searchParams.set('state', url.searchParams.get('state'))
    result.searchParams.set('iss', origin)
    return result.href
  }
  function issue(scope, clientId) {
    const tokens = {
      access_token: `access-${randomUUID()}`,
      refresh_token: `refresh-${randomUUID()}`,
      token_type: 'bearer',
      expires_in: 3600,
      scope,
    }
    access.set(tokens.access_token, { scope, clientId })
    refresh.set(tokens.refresh_token, { scope, clientId })
    return tokens
  }
  const origin = await serve(t, async (req, res) => {
    const url = new URL(req.url, 'http://localhost')
    requests.push({ method: req.method, path: url.pathname })
    if (url.pathname === '/.well-known/oauth-protected-resource/mcp') {
      return json(res, 200, {
        resource: `${origin}/mcp`, authorization_servers: [origin], scopes_supported: ['user:read', 'account:read'],
      })
    }
    if (url.pathname === '/.well-known/oauth-authorization-server') {
      return json(res, 200, {
        issuer: origin,
        authorization_endpoint: `${origin}/authorize`,
        token_endpoint: `${origin}/token`,
        registration_endpoint: `${origin}/register`,
        response_types_supported: ['code'],
        grant_types_supported: ['authorization_code', 'refresh_token'],
        token_endpoint_auth_methods_supported: ['none'],
        code_challenge_methods_supported: ['S256'],
        authorization_response_iss_parameter_supported: true,
        ...(options.scopesSupported === undefined ? {} : { scopes_supported: options.scopesSupported }),
      })
    }
    if (url.pathname === '/authorize') {
      res.writeHead(302, { location: callback(`${origin}${req.url}`) })
      return res.end()
    }
    if (url.pathname === '/mcp' && req.method === 'GET') return json(res, 405, { error: 'no_sse' })
    const chunks = []
    for await (const chunk of req) chunks.push(chunk)
    const body = Buffer.concat(chunks).toString()
    if (url.pathname === '/register') {
      const metadata = JSON.parse(body)
      assert.equal(metadata.token_endpoint_auth_method, 'none')
      const info = { ...metadata, client_id: `client-${randomUUID()}` }
      registrations.push(metadata)
      clients.set(info.client_id, info)
      return json(res, 201, info)
    }
    if (url.pathname === '/token') {
      const params = new URLSearchParams(body)
      tokenRequests.push(Object.fromEntries(params))
      if (options.tokenDelay) await new Promise((resolve) => setTimeout(resolve, options.tokenDelay))
      if (params.get('grant_type') === 'refresh_token') {
        const grant = refresh.get(params.get('refresh_token'))
        if (!grant || options.refreshInvalid) return json(res, 400, { error: 'invalid_grant' })
        assert.equal(params.get('client_id'), grant.clientId)
        return json(res, 200, issue(grant.scope, grant.clientId))
      }
      const code = params.get('code')
      const grant = codes.get(code)
      if (!grant) return json(res, 400, { error: 'invalid_grant', error_description: `invalid code ${code}` })
      assert.equal(params.get('client_id'), grant.clientId)
      assert.equal(params.get('redirect_uri'), grant.redirectUrl)
      assert.equal(createHash('sha256').update(params.get('code_verifier')).digest('base64url'), grant.challenge)
      codes.delete(code)
      return json(res, 200, issue(grant.scope, grant.clientId))
    }
    if (url.pathname !== '/mcp') return json(res, 404, { error: 'not_found' })
    if (req.method === 'DELETE') {
      res.writeHead(405)
      return res.end()
    }
    const grant = access.get(req.headers.authorization?.replace(/^Bearer /, ''))
    const resource = `${origin}/.well-known/oauth-protected-resource/mcp`
    if (!grant || options.rejectAccess) {
      options.rejectAccess = typeof options.rejectAccess === 'number' ? options.rejectAccess - 1 : false
      return json(res, 401, { error: 'unauthorized' }, {
        'www-authenticate': `Bearer realm="OAuth", resource_metadata="${resource}", scope="user:read account:read"`,
      })
    }
    const rpc = JSON.parse(body)
    const reply = (result) => json(res, 200, { jsonrpc: '2.0', id: rpc.id, result })
    if (rpc.method === 'initialize') {
      return reply({ protocolVersion: rpc.params.protocolVersion, capabilities: { tools: { listChanged: true } }, serverInfo: { name: 'fake-cloudflare', version: '1' } })
    }
    if (rpc.method === 'notifications/initialized' || rpc.method === 'notifications/cancelled') {
      res.writeHead(202)
      return res.end()
    }
    if (rpc.method === 'tools/list') {
      if (options.duplicateCursor) return reply({ tools: [tools[0]], nextCursor: 'same' })
      if (options.duplicateTools) return reply({ tools: [tools[0], tools[0]] })
      const page = options.paginated
        ? (rpc.params?.cursor ? { tools: tools.slice(1) } : { tools: tools.slice(0, 1), nextCursor: 'page-2' })
        : { tools }
      return reply({ ...page, _meta: { 'test/page': rpc.params?.cursor ?? 'first' } })
    }
    if (rpc.method === 'tools/call') {
      const { name, arguments: args } = rpc.params
      const call = { name, args }
      toolCalls.push(call)
      if (args.mode === 'protocol-error') {
        return json(res, 200, { jsonrpc: '2.0', id: rpc.id, error: { code: -32601, message: 'Tool not found', data: { reason: 'test' } } })
      }
      const request = /^async \(\) => cloudflare\.request\(JSON\.parse\((.*)\)\)$/.exec(args.code ?? '')
      const invocation = request ? JSON.parse(JSON.parse(request[1])) : undefined
      if (invocation) call.request = invocation
      const requiredScope = args.requireScope ?? (invocation && requiredScopes.get(`${invocation.method} ${invocation.path}`))
      if (requiredScope && !grant.scope.split(' ').includes(requiredScope)) {
        const scopes = [...new Set([...grant.scope.split(' ').filter((scope) => scope !== 'offline_access'), requiredScope])]
        const header = `Bearer realm="OAuth", error="insufficient_scope", scope="${scopes.join(' ')}", resource_metadata="${resource}"`
        if (args.mode === 'meta') {
          return reply({ isError: true, content: [{ type: 'text', text: 'Permission required' }], _meta: { 'mcp/www_authenticate': [header] } })
        }
        return json(res, 403, { error: 'insufficient_scope' }, { 'www-authenticate': header })
      }
      if (args.mode === 'error') {
        return reply({ isError: true, content: [{ type: 'text', text: `API failed; Bearer ${[...access.keys()].at(-1)}` }] })
      }
      const failure = invocation && failures.get(`${invocation.method} ${invocation.path}`)
      if (failure) return reply({
        isError: true,
        content: [{ type: 'text', text: `Cloudflare API error: ${invocation.method} ${invocation.path} returned HTTP ${failure.status}. ${failure.message}` }],
        _meta: { 'test/failure': true },
      })
      if (args.mode === 'slow') await new Promise((resolve) => setTimeout(resolve, 150))
      let value = name === 'whoami' ? { id: 'account:account-1' } : { success: true, result: [{ id: 'example.com' }] }
      if (invocation) {
        const route = routes.get(`${invocation.method} ${invocation.path}`)
        value = typeof route === 'function' ? await route(invocation) : route
        if (value === undefined) throw new Error(`No fake API route for ${invocation.method} ${invocation.path}`)
      }
      return reply({
        content: [{ type: 'text', text: JSON.stringify(value) }],
        ...(args.mode === 'structured' ? { structuredContent: value } : {}),
        _meta: { 'test/result': name },
      })
    }
    return json(res, 400, { error: `Unknown RPC method ${rpc.method}` })
  })
  return { origin, endpoint: `${origin}/mcp`, options, clients, access, refresh, codes, requests, registrations, tokenRequests, toolCalls, tools, routes, requiredScopes, failures, callback }
}

export async function setup(t, overrides = {}) {
  const directory = temporaryDirectory(t)
  const server = await fakeServer(t)
  const context = fakeContext()
  const store = new CredentialStore({ endpoint: server.endpoint, tokenFile: join(directory, 'auth.json') })
  const flow = new OAuthFlow(store, { redirectUrl: 'http://127.0.0.1:4899/api/dsh-cloudflare-connector/oauth/callback', ...overrides })
  const connection = new CloudflareConnection(context.ctx, flow)
  const service = createService(flow, connection)
  const removeService = context.ctx.provide('cloudflareConnector', service)
  for (const tool of buildTools(flow, connection, service)) context.ctx.tools.register(tool)
  t.after(async () => {
    flow.dispose()
    await connection.dispose()
    removeService()
  })
  async function authorize(scopes) {
    const result = await flow.begin()
    await flow.finish(server.callback(result.authorizationUrl, scopes))
    await connection.connect()
    return result
  }
  return { ...context, server, store, flow, connection, service, authorize, directory }
}
