import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { setTimeout as delay } from 'node:timers/promises'
import { pathToFileURL } from 'node:url'
import test from 'node:test'
import * as connector from '../index.js'
import { fakeContext, fakeServer, temporaryDirectory } from './support.js'

test('real DSH service injection, native tools and optional-consumer removal lifecycle', {
  skip: process.env.DSH_HOST_PACKAGE_JSON ? false : 'Optional: set DSH_HOST_PACKAGE_JSON and use the DSH host Node runtime',
}, async (t) => {
  const { createRequire, registerHooks } = await import('node:module')
  const hostRequire = createRequire(process.env.DSH_HOST_PACKAGE_JSON)
  const hostImport = (name) => import(pathToFileURL(hostRequire.resolve(`@deepseek-ai/${name}`)).href)
  const { Context } = await hostImport('cordis')
  const { ToolsService } = await hostImport('dsh-tools')
  const { SystemPrompt } = await hostImport('dsh-system-prompt')
  const { NativeToolExecutor } = await hostImport('dsh-tool-executor-native')
  const entries = new Map(['@deepseek-ai/dsh-tools', '@deepseek-ai/schemastery']
    .map((name) => [name, pathToFileURL(hostRequire.resolve(name)).href]))
  const hooks = registerHooks({
    resolve(specifier, context, next) {
      const url = entries.get(specifier)
      return url ? { url, shortCircuit: true } : next(specifier, context)
    },
  })
  t.after(() => hooks.deregister())
  const domainManager = await import('../../dsh-domain-manager/index.js')
  const server = await fakeServer(t)
  const directory = temporaryDirectory(t)
  const root = new Context()
  new SystemPrompt(root, {})
  new ToolsService(root)
  root.tools.setExecutor(new NativeToolExecutor(root))
  const removeWebServer = root.provide('webServer', fakeContext().ctx.webServer)
  let consumerFiber
  let exampleFiber
  let connectorFiber
  let injectedService
  let sequence = 0
  const dependentFiber = root.inject(['cloudflareConnector'], (ctx) => {
    injectedService = ctx.cloudflareConnector
    ctx.effect(() => () => { injectedService = undefined })
  })
  t.after(async () => {
    try {
      if (exampleFiber) await exampleFiber.dispose()
      if (consumerFiber) await consumerFiber.dispose()
    } finally {
      await dependentFiber.dispose()
      if (connectorFiber) await connectorFiber.dispose()
      await removeWebServer()
    }
  })
  const hasTool = (name) => root.tools.schemas().some((tool) => tool.name === name)
  async function ready(predicate, description) {
    for (let attempt = 0; attempt < 200; attempt++) {
      if (predicate()) return
      await delay(10)
    }
    throw new Error(`Timed out: ${description}`)
  }
  consumerFiber = root.plugin(domainManager, {
    dataFile: join(directory, 'domains.json'),
    providers: { cloudflare: 'mcp', namecheap: 'api' },
  })
  await consumerFiber
  assert.equal(consumerFiber.state, 2, consumerFiber._error?.stack ?? 'Consumer must be active')
  await ready(() => hasTool('domain_manager_list'), 'consumer starts without optional connector')
  assert.equal(root.cloudflareConnector, undefined)
  const readme = readFileSync(new URL('../README.md', import.meta.url), 'utf8')
  const exampleSource = [...readme.matchAll(/```js\n([\s\S]*?)\n```/g)]
    .map((match) => match[1]).find((source) => source.includes("export const name = 'cloudflare-account-example'"))
  assert.ok(exampleSource, 'README must include a complete account-listing plugin')
  const example = await import(`data:text/javascript;base64,${Buffer.from(exampleSource).toString('base64')}`)
  exampleFiber = root.plugin(example)
  await exampleFiber
  assert.equal(exampleFiber.state, 2, exampleFiber._error?.stack)
  await assert.rejects(execute('cloudflare_list_accounts', {}), /Install @beings-labs\/dsh-cloudflare-connector/)
  connectorFiber = root.plugin(connector, { endpoint: server.endpoint, tokenFile: join(directory, 'auth.json') })
  await connectorFiber
  assert.equal(connectorFiber.state, 2, connectorFiber._error?.stack ?? 'Connector must be active')
  await ready(() => root.cloudflareConnector && injectedService && hasTool('cloudflare_connector_authorize') && hasTool('domain_manager_sync'), 'connector and consumers activate')
  const service = root.cloudflareConnector
  assert.equal(service.status().authorized, false)
  const authorization = await service.authorize()
  await service.finish({ code: server.callback(authorization.authorizationUrl) })
  assert.equal(service.status().connected, true)
  assert.equal(injectedService.status().connected, true)
  server.routes.set('GET /accounts/account-1/registrar/registrations', {
    success: true,
    result: [{ domain_name: 'example.com', expires_at: '2027-03-15T12:00:00.000Z', auto_renew: true, status: 'active' }],
    result_info: { cursor: '' },
  })
  async function execute(name, args) {
    const batch = await root.tools.execute({
      calls: [{ id: `smoke-${++sequence}`, name, arguments: args }],
      signal: new AbortController().signal,
    })
    const result = batch.results[0].result
    if (result.isError) throw new Error(JSON.stringify(result.content))
    return result.value
  }
  assert.equal((await execute('cloudflare_connector_status', {})).connected, true)
  assert.ok((await execute('mcp__cloudflare_connector__execute', { code: 'async () => ({})' })).content.length)
  const synced = await execute('domain_manager_sync', { registrar: 'cloudflare', dryRun: true })
  assert.equal(synced.added, 1)
  assert.equal(synced.count, 0)
  assert.equal(server.toolCalls.filter((call) => call.request?.path === '/accounts').length, 1)
  const accounts = await execute('cloudflare_list_accounts', {})
  assert.equal(accounts.result[0].id, 'account-1')
  assert.equal(server.toolCalls.filter((call) => call.request?.path === '/accounts').length, 2)
  await connectorFiber.dispose()
  connectorFiber = undefined
  await ready(() => !root.cloudflareConnector && !injectedService && hasTool('domain_manager_list'), 'optional consumer survives while required dependency deactivates')
  assert.equal(hasTool('cloudflare_connector_status'), false)
  assert.equal(hasTool('mcp__cloudflare_connector__execute'), false)
  await assert.rejects(service.callTool({ name: 'whoami' }), /disposed/)
  await assert.rejects(execute('cloudflare_list_accounts', {}), /Install @beings-labs\/dsh-cloudflare-connector/)
  await assert.rejects(execute('domain_manager_sync', { registrar: 'cloudflare', dryRun: true }), /Cloudflare MCP connector service is not available/)
  await execute('domain_manager_list', {})
})
