import assert from 'node:assert/strict'
import { existsSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import test from 'node:test'
import { setup } from './support.js'

const providerUrl = new URL('../../dsh-domain-manager/lib/providers/cloudflare-mcp.js', import.meta.url)
const registrarUrl = new URL('../../dsh-domain-manager/lib/registrars/cloudflare.js', import.meta.url)
const available = existsSync(fileURLToPath(providerUrl)) && existsSync(fileURLToPath(registrarUrl))

test('sibling domain-manager uses the real connector for account discovery, portfolio reads, availability and search without an API token', {
  skip: available ? false : 'Optional: check out dsh-domain-manager beside this repository for downstream integration',
}, async (t) => {
  const provider = await import(providerUrl.href)
  const registrar = await import(registrarUrl.href)
  const { authorize, server, ctx, registry } = await setup(t)
  await authorize()
  const transport = provider.createTransport(ctx)
  assert.equal(transport.isAvailable(), true)
  const accountId = await transport.resolveAccountId()
  assert.equal(accountId, 'account-1')
  const config = { accountId, transport: transport.request }
  server.routes.set('GET /accounts/account-1/registrar/registrations', {
    success: true,
    result: [{ domain_name: 'example.com', expires_at: '2027-03-15T12:00:00.000Z', auto_renew: true, status: 'active' }],
    result_info: { cursor: '' },
  })
  server.requiredScopes.set('GET /accounts/account-1/registrar/registrations', 'registrar-domains.read')
  await assert.rejects(registrar.listDomains(config), /cloudflare_connector_authorize/)
  assert.equal(server.toolCalls.filter((call) => call.request?.path.includes('/registrar/registrations')).length, 1, 'No automatic replay of the refused read')
  const readConsent = await registry.get('cloudflare_connector_authorize').execute({})
  assert.deepEqual(readConsent.scopes, ['user:read', 'account:read', 'registrar-domains.read'])
  await registry.get('cloudflare_connector_finish').execute({ code: server.callback(readConsent.authorizationUrl) })
  const domains = await registrar.listDomains(config)
  assert.equal(domains[0].name, 'example.com')
  assert.equal(Object.hasOwn(domains[0], 'renewalPrice'), false)
  const candidate = { name: 'available-example.com', registrable: true, tier: 'standard', pricing: { registration_cost: 10, renewal_cost: 11, currency: 'USD' } }
  server.routes.set('POST /accounts/account-1/registrar/domain-check', { success: true, result: { domains: [candidate] } })
  server.routes.set('GET /accounts/account-1/registrar/domain-search?q=example&limit=5', { success: true, result: { domains: [candidate] } })
  server.requiredScopes.set('POST /accounts/account-1/registrar/domain-check', 'registrar-domains.admin')
  await assert.rejects(registrar.checkAvailability(config, ['available-example.com']), /cloudflare_connector_authorize/)
  const stepUp = await registry.get('cloudflare_connector_authorize').execute({})
  assert.ok(stepUp.scopes.includes('registrar-domains.admin'))
  await registry.get('cloudflare_connector_finish').execute({ code: server.callback(stepUp.authorizationUrl) })
  const availability = await registrar.checkAvailability(config, ['available-example.com'])
  const search = await registrar.searchDomains(config, 'example')
  assert.equal(availability[0].available, true)
  assert.equal(search[0].renewalPrice, 11)
  for (const call of server.toolCalls.filter((call) => call.name === 'execute')) {
    assert.equal(call.args.truncate, false)
    if (call.request?.path !== '/accounts') assert.equal(call.args.account_id, 'account-1')
  }
})
