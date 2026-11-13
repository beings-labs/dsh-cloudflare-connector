import { z } from 'zod'
import { CredentialStore, DEFAULT_SCOPES, MCP_URL } from './lib/store.js'
import { CALLBACK_PATH, isLoopback, OAuthFlow, scopesOf } from './lib/oauth.js'
import { CloudflareConnection } from './lib/connection.js'
import { buildTools, makeCallbackRoute } from './lib/tools.js'
import { createService } from './lib/service.js'

export { CloudflareConnectorError, AuthorizationRequiredError } from './lib/errors.js'

export const name = 'beings-labs-cloudflare-connector'
export const inject = ['tools', 'systemPrompt', 'webServer']

export const Config = z.object({
  enabled: z.boolean().default(true),
  announceToAgent: z.boolean().default(true),
  scopes: z.array(z.string()).default(DEFAULT_SCOPES),
  endpoint: z.string().url().default(MCP_URL),
  tokenFile: z.string().optional(),
}).prefault({})

export const GUIDANCE = `Cloudflare is available through the official API MCP server after browser OAuth.
Use cloudflare_connector_status to check the connection, cloudflare_connector_authorize to get an authorization URL,
and cloudflare_connector_finish only if the automatic callback cannot complete. Ask the user to open the URL;
never ask for API tokens. cloudflare_connector_test connects and lists the actual mcp__cloudflare_connector__* tools.
For HTTP 403 insufficient_scope, call cloudflare_connector_authorize, have the user approve the requested
permissions, then retry the original operation after authorization completes. Never automatically replay writes.
The default grant supports identity and account discovery; resource access may require additional consent.
Use only OAuth scopes actually advertised by the server. Registrar reads use registrar-domains.read, not registrar:read.
If invalid_scope is reported, correct the requested scopes instead of repeatedly reconnecting. Use only tool names
actually registered. cloudflare_connector_clear removes local credentials and remote tools. Credentials are stored
privately under $DSH_HOME/dsh-cloudflare-connector/auth.json unless tokenFile overrides that path.`

export function apply(ctx, input = {}) {
  const parsed = Config.safeParse(input)
  if (!parsed.success) throw new Error('Invalid Cloudflare MCP configuration; check enabled, announceToAgent, endpoint, scopes, and tokenFile')
  const config = parsed.data
  if (!config.enabled) return
  scopesOf(config.scopes)
  const endpoint = new URL(config.endpoint)
  if ((endpoint.protocol !== 'https:' && !(endpoint.protocol === 'http:' && isLoopback(endpoint.hostname))) ||
      endpoint.username || endpoint.password || endpoint.hash) {
    throw new Error('Cloudflare MCP endpoint must use HTTPS (or loopback HTTP for development), without credentials or a fragment')
  }
  const origin = new URL(ctx.webServer.getOrigin())
  if (!['http:', 'https:'].includes(origin.protocol) || !isLoopback(origin.hostname)) {
    throw new Error('Cloudflare OAuth requires a loopback DSH web server origin')
  }
  const store = new CredentialStore({ endpoint: endpoint.href, tokenFile: config.tokenFile })
  const flow = new OAuthFlow(store, { redirectUrl: new URL(CALLBACK_PATH, origin).href, scopes: config.scopes })
  const connection = new CloudflareConnection(ctx, flow)
  const service = createService(flow, connection)
  ctx.effect(() => {
    const disposers = []
    try {
      for (const tool of buildTools(flow, connection, service)) disposers.push(ctx.tools.register(tool))
      disposers.push(ctx.webServer.register(makeCallbackRoute(ctx, flow, connection)))
      if (config.announceToAgent) {
        disposers.push(ctx.systemPrompt.section({
          name: 'plugin:beings-labs-cloudflare-connector',
          order: 161,
          text: GUIDANCE,
          interpolate: false,
        }))
      }
      disposers.push(ctx.provide('cloudflareConnector', service))
    } catch (error) {
      for (const dispose of disposers.reverse()) dispose()
      flow.dispose()
      throw error
    }
    const startup = store.data.tokens && !store.data.pending
      ? connection.connect().catch((error) => ctx.logger.warn(`Cloudflare MCP startup failed: ${store.redact(error.message)}`))
      : Promise.resolve()
    return async () => {
      flow.dispose()
      try {
        await connection.dispose()
      } finally {
        await startup
        for (const dispose of disposers.reverse()) await dispose()
      }
    }
  }, 'beings-labs-cloudflare-connector')
}
