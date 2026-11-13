import type { CallToolResult, ListToolsResult } from '@modelcontextprotocol/sdk/types.js'
import { AuthorizationRequiredError, CloudflareConnectorError, Config } from '@beings-labs/dsh-cloudflare-connector'
import type { CloudflareConnectorContext, CloudflareConnectorService, JsonValue } from '@beings-labs/dsh-cloudflare-connector'

declare const service: CloudflareConnectorService
declare const context: CloudflareConnectorContext

const tools: Promise<ListToolsResult> = service.listTools({ cursor: 'next' }, { timeout: 1_000 })
const result: Promise<CallToolResult> = service.callTool({ name: 'execute', arguments: { code: 'async () => ({})' } }, { signal: new AbortController().signal })
const value: Promise<JsonValue> = service.request({ method: 'GET', path: '/accounts', query: { page: 1 } }, { timeoutMs: 1_000 })
service.authorize({ scopes: ['zone.read'] })
service.finish({ code: 'manual-code' })
service.clear()
service.test()
context.cloudflareConnector?.status()
context.get('cloudflareConnector')?.status()
// @ts-expect-error Legacy service names are not aliases for this connector.
context.get('cloudflareMcp')
Config.parse({}).enabled satisfies boolean
new CloudflareConnectorError('failure', { code: 'api_error', status: 422 })
new CloudflareConnectorError('unsupported scope', { code: 'invalid_scope', status: 400 })
new AuthorizationRequiredError().code satisfies 'authorization_required'
void [tools, result, value]

// @ts-expect-error Raw tool calls use official MCP request parameters.
service.callTool('execute')
// @ts-expect-error The convenience method needs an API path.
service.request({ method: 'GET' })
// @ts-expect-error The convenience method accepts JSON, not executable functions.
service.request({ path: '/accounts', body: () => true })
// @ts-expect-error Query values must be scalar.
service.request({ path: '/accounts', query: { nested: {} } })
