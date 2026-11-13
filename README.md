# @beings-labs/dsh-cloudflare-connector

**Cloudflare access for DeepSeek Harness agents and plugin developers.**
Sign in through your browser, use the official MCP tools, or call a typed
shared service from your own plugin. No Cloudflare API token to create or manage.

The connector talks to the [official Cloudflare API MCP server](https://developers.cloudflare.com/agents/model-context-protocol/cloudflare/servers-for-cloudflare/).
It keeps the upstream MCP protocol and tool contracts; the shared plugin API is
an additional local integration, not a new server or replacement protocol.

## Why use it?

- **Browser sign-in:** Cloudflare OAuth with PKCE, using DSH's existing local web server.
- **Agent-ready tools:** upstream tools exposed as `mcp__cloudflare_connector__*`, with their input schemas preserved.
- **Built for plugin developers:** one shared connection, public TypeScript types, and direct API requests without nested model-facing tool calls.
- **Explicit permissions:** identity and account discovery by default; resource access requires additional browser consent.
- **Persistent sessions:** private credential storage, automatic token refresh, and reconnection after restart.

[Quick start](#quick-start) · [Permissions](#permissions-and-authorization) · [Configuration](#configuration) · [Troubleshooting](#troubleshooting) · [Plugin API](#plugin-api)

## Quick start

### 1. Install in your DSH profile

Install the released package in your DSH profile:

```sh
dsh plugin --profile <profile> add @beings-labs/dsh-cloudflare-connector
```

To use a local development checkout instead, run this from the repository:

```sh
npm ci
dsh plugin --profile <profile> add link:/absolute/path/to/dsh-cloudflare-connector
```

Replace `<profile>` with the profile you actually run, then restart DSH.
This connector uses its own tool, service, callback, and credential namespaces.
It is not a drop-in replacement for integrations built around another connector's tools.

**Before you start:** use Node.js 20 or newer and a DSH 0.2.x Desktop or local
Web profile with `tools`, `systemPrompt`, and `webServer` services. Browser OAuth requires a loopback
origin; a remotely hosted DSH Web server is not supported. To invoke tools
through chat, you also need a working model connection in DSH. That is separate
from Cloudflare authorization.

### 2. Sign in to Cloudflare

Ask your agent:

> Call cloudflare_connector_status and cloudflare_connector_authorize.

Open the returned `authorizationUrl` and approve the requested permissions.
The browser callback completes authorization automatically; return to DSH.
Never paste API tokens, access tokens, or refresh tokens into chat.

The default grant is:

```text
user:read account:read
```

This allows identity and account discovery, not access to every Cloudflare
resource. Other resource operations may require additional consent.
Cloudflare can also grant `offline_access` for token refresh; status reports the
actual granted scopes.

### 3. Verify with a read-only request

Ask your agent:

> Test the Cloudflare connection, then list the accounts I can access. Do not modify any resources.

`cloudflare_connector_status` should report `authorized: true` and `connected: true`;
`cloudflare_connector_test` lists the discovered tools. Upstream tools such as
`mcp__cloudflare_connector__execute`, `mcp__cloudflare_connector__whoami`, and
`mcp__cloudflare_connector__search` are available when advertised by the server.

If the browser callback cannot reach DSH, call `cloudflare_connector_finish` with
`{"code":"<full callback URL>"}` through the local DSH tool. A raw code with
optional `state` is also accepted. Callback URLs contain sensitive, short-lived
parameters: do not share them in issues, logs, or other chats.

## Permissions and authorization

When Cloudflare requests another scope, the connector prepares a consent URL
and reports `authorization_required` or `HTTP 403 insufficient_scope`.

1. Call `cloudflare_connector_authorize` to retrieve the pending URL.
2. Open it and approve the requested permissions.
3. Retry the original operation after authorization and reconnection complete.

The connector uses the server's exact challenged scope list and does not
automatically replay the refused operation.
A plain API `403` without a scope challenge does not start consent automatically.
Check the endpoint's documented permissions and availability rather than
repeatedly reconnecting with the same grant.

To request a known scope proactively, pass `{"scopes":["zone.read"]}` to
`cloudflare_connector_authorize` when no flow is pending. Repeated calls during a
pending flow return the same URL; they do not change its scopes. Pending flows
expire after ten minutes.

Scope names are not inferred from product names or API token permission labels.
The connector validates them against the authorization server's
`scopes_supported` discovery metadata when advertised, before registering a
client or returning a consent URL. For the default server, inspect its
[OAuth metadata](https://mcp.cloudflare.com/.well-known/oauth-authorization-server).
Unsupported scopes produce `invalid_scope`, not a new consent flow. Correct the
scope list; reconnecting with the same invalid scope will not help.

`authorized` means credentials are stored, not that every permission is granted.
Pending consent blocks remote calls. To abandon a flow or reduce permissions,
run `cloudflare_connector_clear` and authorize again with the desired configured scopes.
Clear deletes local credentials; revoke the upstream grant in Cloudflare separately
if needed. Clearing the connector does not sign you out of Cloudflare in your browser.

### Agent helper tools

| Tool | Purpose |
| --- | --- |
| `cloudflare_connector_authorize` | Start OAuth or return the pending URL; optional `scopes` array |
| `cloudflare_connector_finish` | Complete OAuth manually with `code` and optional `state` |
| `cloudflare_connector_status` | Check authorization, connection, scopes, tool count, and pending consent |
| `cloudflare_connector_test` | Reconnect and list available tools without changing Cloudflare resources |
| `cloudflare_connector_clear` | Delete local credentials, disconnect, and unregister remote tools |

## Configuration

Defaults work without configuration. To customize the connector, edit your
profile's `cordis.patch.yml`:

```yaml
- id: beings-labs-cloudflare-connector
  config:
    enabled: true
    announceToAgent: true
    scopes:
      - user:read
      - account:read
    # tokenFile: /absolute/path/to/private/auth.json
```

| Option | Default | Purpose |
| --- | --- | --- |
| `enabled` | `true` | Enable tools, service, callback, and guidance |
| `announceToAgent` | `true` | Include authorization guidance in the agent's prompt |
| `scopes` | `user:read account:read` | Replace the initial scope list |
| `endpoint` | `https://mcp.cloudflare.com/mcp` | MCP endpoint; HTTPS required except loopback development |
| `tokenFile` | Default private path below | Absolute path for stored OAuth credentials |

Credentials default to `$DSH_HOME/dsh-cloudflare-connector/auth.json`, or
`~/.dsh/dsh-cloudflare-connector/auth.json` when `DSH_HOME` is unset. Files use mode
`0600`, with private directories created as `0700`. Never commit or share them.
Concurrent profiles should use separate `tokenFile` paths.

Credentials are bound to the configured endpoint. To change endpoints, use a
different credential file or remove the old one and authorize again.

Only install plugins you trust: consumers share the authorized Cloudflare access.
Authorizing or clearing credentials affects all consumers in the profile. The
connector does not enforce read-only access or approval policies for your agent.

## Troubleshooting

| Symptom | What to do |
| --- | --- |
| Helper tools are missing | Confirm installation in the running profile, restart DSH, and check the required services |
| Chat fails with "no API key for provider route" | Configure the selected model in DSH's Models page; this is not a Cloudflare OAuth error |
| `authorized: true`, `connected: false` | Call `cloudflare_connector_test` to reconnect and refresh tool discovery |
| Missing permission / `insufficient_scope` | Complete the consent flow, then retry; repeated API calls will not grant permissions |
| `invalid_scope` | Use exact scope names from the server's OAuth metadata and retry authorization with corrected scopes |
| API authentication or permission error without a scope challenge | Check the account, granted scopes, and endpoint permissions; reconnecting with an unchanged grant may not help |
| Callback cannot reach DSH | Use `cloudflare_connector_finish` with the original full callback URL, especially if the GUI port changed |
| Pending flow expired | Call `cloudflare_connector_authorize` for a new URL |
| Refresh grant revoked or expired | Authorize again; clear first if client registration is invalid |
| Credential file is corrupt or belongs to another endpoint | Restore or remove that specific file, then authorize again; do not hand-edit tokens |
| Duplicate tool names | Remove duplicate entries of this connector or tools using its namespace |

Saved credentials reconnect after restart. Remote tools are unregistered on
disconnect; `cloudflare_connector_test` reconnects explicitly.

## Plugin API

Other DSH plugins can share the connector's browser-authorized connection
without handling tokens. Install them in the same profile and resolve the
`cloudflareConnector` Cordis service when a tool runs:

```js
export const name = 'cloudflare-account-example'
export const inject = ['tools']

export function apply(ctx) {
  ctx.tools.register({
    name: 'cloudflare_list_accounts',
    description: 'List accessible Cloudflare accounts without changing resources.',
    parameters: { type: 'object', properties: {}, additionalProperties: false },
    output: {
      schema: { type: 'object', additionalProperties: true },
      render: (_args, value) => [{ type: 'text', text: JSON.stringify(value) }],
    },
    async execute(_args, exec = {}) {
      const mcp = ctx.get('cloudflareConnector')
      if (!mcp) {
        throw new Error('Install @beings-labs/dsh-cloudflare-connector in this profile.')
      }
      return mcp.request({ path: '/accounts' }, { signal: exec.signal })
    },
  })
}
```

For a mandatory dependency, add `'cloudflareConnector'` to `inject` and use
`ctx.cloudflareConnector`. The service exists before authorization and is
removed when the connector is disposed.

| Method | Purpose |
| --- | --- |
| `status()` | Read secret-free connection and authorization status |
| `authorize({ scopes? }?)` | Start consent or retrieve the pending URL |
| `finish({ code, state? })` | Complete authorization and connect |
| `test()` | Reconnect and list available tool names |
| `clear()` | Remove local credentials and disconnect |
| `listTools(params?, options?)` | Get one upstream MCP tools page |
| `callTool(params, options?)` | Call an upstream MCP tool |
| `request(request, options?)` | Make a JSON Cloudflare API request |

`request` accepts `{ method?, path, query?, body? }`. The method defaults to
`GET`; the path must be an absolute API path, not a URL. Query values are scalars
and the body must be JSON. It uses the upstream Code Mode `execute` tool with
truncation disabled and preserves Cloudflare's `result` envelope.

Options include `accountId`, `signal`, `timeoutMs`, and `sensitiveValues`.
Declare request secrets in `sensitiveValues` to redact them from thrown messages
and stacks. Tool calls default to a 120-second timeout. Your plugin handles
account selection, pagination, caching, and approval for resource changes.

Raw `listTools` and `callTool` preserve upstream schemas, pagination, metadata,
and results. **Check `callTool` results for `isError`: tool failures are returned,
not thrown.** Protocol and transport failures reject. Raw request options
include `signal`, `timeout`, and `onprogress`.

Helper errors expose `code` and `status`. On `authorization_required`, direct
the user to the consent flow and retry only after it completes. On
`invalid_scope`, correct the scope list before authorizing again.

Public TypeScript types and error classes are exported from the package root:

```ts
import type { CloudflareConnectorService } from '@beings-labs/dsh-cloudflare-connector'

async function readAccounts(mcp: CloudflareConnectorService) {
  return mcp.request({ path: '/accounts' })
}
```

## Feedback and contributions

[Open an issue](https://github.com/beings-labs/dsh-cloudflare-connector/issues) with
reproduction steps, your operating system, profile type, and redacted errors.
Never include tokens, authorization codes, callback URLs, or credential files.

Pull requests are welcome. Before submitting a change, run:

```sh
npm ci
npm test
npm run check
npm run test:package
```

Runtime tests use local fake OAuth/MCP servers and need no Cloudflare credentials.
The package check installs a generated tarball in a temporary project and needs
npm registry access.

## Acknowledgments

The community [dsh-cloudflare-mcp](https://github.com/zhengjy01/dsh-cloudflare-mcp)
project provided a useful reference for DeepSeek Harness integration.
This project offers its own typed plugin service and authorization lifecycle.

## License

[MIT](./LICENSE), including attribution for adapted portions of the community project.
