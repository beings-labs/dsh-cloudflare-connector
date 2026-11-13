import { z } from 'zod'
import { CALLBACK_PATH, isLoopback } from './oauth.js'
import { CloudflareConnectorError } from './errors.js'
import { createService } from './service.js'

export function buildTools(flow, connection, service = createService(flow, connection)) {
  const definitions = [
    {
      name: 'cloudflare_connector_authorize',
      description: 'Authorize Cloudflare through browser OAuth, using supported OAuth scope names, or grant scopes requested by a failed call. Registrar reads use registrar-domains.read, not registrar:read. Returns the existing URL if authorization is pending.',
      schema: z.object({ scopes: z.array(z.string()).optional() }).strict(),
      execute: service.authorize,
    },
    {
      name: 'cloudflare_connector_finish',
      description: 'Manual OAuth fallback: supply the full callback URL, or the raw authorization code. Never paste an access token or refresh token.',
      schema: z.object({ code: z.string().min(1), state: z.string().optional() }).strict(),
      execute: service.finish,
    },
    {
      name: 'cloudflare_connector_status',
      description: 'Show Cloudflare authorization, granted scopes, connection, tool count, and pending step-up status. Never returns credentials.',
      schema: z.object({}).strict(),
      execute: service.status,
    },
    {
      name: 'cloudflare_connector_test',
      description: 'Connect to Cloudflare and list the available mcp__cloudflare_connector__* tools without making Cloudflare API changes.',
      schema: z.object({}).strict(),
      execute: service.test,
    },
    {
      name: 'cloudflare_connector_clear',
      description: 'Remove locally stored Cloudflare OAuth credentials and pending authorization, disconnect, and unregister remote tools. Does not revoke the grant at Cloudflare.',
      schema: z.object({}).strict(),
      execute: service.clear,
    },
  ]
  return definitions.map(({ schema, execute, ...definition }) => ({
    ...definition,
    // Zod attaches non-enumerable ~standard functions; DSH requires lossless JSON.
    parameters: { ...z.toJSONSchema(schema) },
    output: {
      schema: { type: 'object', additionalProperties: true },
      render: (_args, value) => [{ type: 'text', text: JSON.stringify(value) }],
    },
    execute: async (args = {}, exec = {}) => {
      exec.signal?.throwIfAborted()
      const result = schema.safeParse(args)
      if (!result.success) throw new Error(`Invalid arguments for ${definition.name}: ${result.error.issues.map((issue) => `${issue.path.join('.') || 'arguments'}: ${issue.message}`).join('; ')}`)
      return execute(result.data)
    },
  }))
}

function sendPage(res, status, message) {
  res.writeHead(status, {
    'content-type': 'text/html; charset=utf-8',
    'cache-control': 'no-store',
    'referrer-policy': 'no-referrer',
    'x-content-type-options': 'nosniff',
    'content-security-policy': "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
  })
  res.end(`<!doctype html><html lang="en"><meta charset="utf-8"><title>Cloudflare authorization</title><body><h1>Cloudflare authorization</h1><p>${message}</p></body></html>`)
}

export function makeCallbackRoute(ctx, flow, connection) {
  return {
    kind: 'exact',
    path: CALLBACK_PATH,
    handler: async (req, res) => {
      const peer = req.socket?.remoteAddress?.replace(/^::ffff:/, '')
      const origin = new URL(ctx.webServer.getOrigin())
      if (!isLoopback(peer) || req.headers.host !== origin.host || !isLoopback(origin.hostname)) {
        sendPage(res, 403, 'Only the local DSH callback is accepted.')
        return
      }
      if (req.method !== 'GET') {
        res.setHeader('allow', 'GET')
        sendPage(res, 405, 'This callback requires GET.')
        return
      }
      try {
        const url = new URL(req.url, origin)
        await flow.finish(url.href, { callback: true })
      } catch (error) {
        if (error instanceof CloudflareConnectorError && error.code === 'invalid_scope') {
          ctx.logger.warn('Cloudflare OAuth callback failed with invalid_scope. Run cloudflare_connector_authorize with supported OAuth scopes.')
          sendPage(res, 400, 'Cloudflare rejected the requested OAuth scopes (invalid_scope). Return to DSH and run cloudflare_connector_authorize with supported OAuth scopes. Retrying unchanged scopes will not help.')
          return
        }
        ctx.logger.warn('Cloudflare OAuth callback was rejected or the token exchange failed. Run cloudflare_connector_authorize to retry.')
        sendPage(res, 400, 'Authorization failed, expired, or was denied. Return to DSH and run cloudflare_connector_authorize again, or use cloudflare_connector_finish with the current callback URL.')
        return
      }
      try {
        await connection.disconnect()
        await connection.connect()
      } catch (error) {
        ctx.logger.warn(`Cloudflare OAuth completed but MCP connection failed: ${flow.store.redact(error.message)}`)
        sendPage(res, 502, 'Authorization was saved, but the MCP connection failed. Return to DSH and run cloudflare_connector_test.')
        return
      }
      sendPage(res, 200, 'Authorization complete. You can close this page and return to DSH.')
    },
  }
}

export { statusOf } from './service.js'
