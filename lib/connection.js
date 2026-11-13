import { createHash } from 'node:crypto'
import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js'
import { ToolListChangedNotificationSchema } from '@modelcontextprotocol/sdk/types.js'
import { AuthorizationRequiredError } from './oauth.js'
import { redactError } from './errors.js'

export function publicToolName(rawName) {
  const name = `mcp__cloudflare_connector__${rawName}`
  if (/^[A-Za-z0-9_-]+$/.test(name) && name.length <= 64) return name
  const hash = createHash('sha256').update(`cloudflare_connector\0${rawName}`).digest('hex').slice(0, 12)
  return `${name.replace(/[^A-Za-z0-9_-]/g, '_').slice(0, 51)}_${hash}`
}

export const MCP_OUTPUT_SCHEMA = {
  type: 'object',
  properties: {
    content: { type: 'array', items: {} },
    structuredContent: {},
  },
  required: ['content'],
  additionalProperties: false,
}

function renderResult(_args, value) {
  if (value.content.length) {
    return value.content.map((block) => block.type === 'text'
      ? { type: 'text', text: block.text }
      : { type: 'text', text: JSON.stringify(block) })
  }
  return [{ type: 'text', text: value.structuredContent === undefined ? '(empty MCP result)' : JSON.stringify(value.structuredContent) }]
}

export class CloudflareConnection {
  constructor(ctx, flow) {
    this.ctx = ctx
    this.flow = flow
    this.disposers = []
    this.toolNames = []
    this.generation = 0
    this.connected = false
    this.disposed = false
  }

  assertCurrent(generation) {
    if (this.disposed || generation !== this.generation) throw new Error('Cloudflare MCP connection was disconnected')
  }

  connect() {
    if (this.disposed) return Promise.reject(new Error('Cloudflare MCP connector has been disposed'))
    if (this.flow.store.data.pending) return Promise.reject(this.flow.requiredError())
    if (this.connecting) return this.connecting
    if (this.connected) return Promise.resolve()
    const generation = ++this.generation
    const task = this.open(generation).finally(() => {
      if (this.connecting === task) this.connecting = undefined
    })
    this.connecting = task
    return task
  }

  async open(generation) {
    let client
    try {
      await this.flow.refreshIfNeeded()
      this.assertCurrent(generation)
      client = new Client({ name: '@beings-labs/dsh-cloudflare-connector', version: '0.1.1' })
      const transport = new StreamableHTTPClientTransport(new URL(this.flow.store.endpoint), {
        authProvider: this.flow.provider,
        fetch: this.flow.transportFetch(),
      })
      this.client = client
      client.onclose = () => {
        if (generation !== this.generation || this.disposed) return
        this.generation++
        this.connected = false
        this.client = undefined
        this.unregisterTools()
        this.ctx.logger.warn('Cloudflare MCP disconnected; run cloudflare_connector_test to reconnect.')
      }
      client.onerror = () => {
        if (generation !== this.generation || this.disposed || this.flow.store.data.pending) return
        this.ctx.logger.warn('Cloudflare MCP transport reported an error; run cloudflare_connector_test if calls fail.')
      }
      client.setNotificationHandler(ToolListChangedNotificationSchema, async () => {
        try {
          await this.syncTools(client, generation)
        } catch (error) {
          this.ctx.logger.warn(`Cloudflare MCP tool refresh failed: ${this.flow.store.redact(error.message)}`)
        }
      })
      await client.connect(transport, { timeout: 30_000 })
      this.assertCurrent(generation)
      await this.syncTools(client, generation)
      this.assertCurrent(generation)
      this.connected = true
    } catch (error) {
      if (generation === this.generation) {
        this.connected = false
        this.client = undefined
        this.unregisterTools()
      }
      if (client) {
        client.onclose = undefined
        await client.close()
      }
      if (this.flow.store.data.pending) throw this.flow.requiredError()
      throw redactError(error, (message) => this.flow.store.redact(message))
    }
  }

  async syncTools(client, generation) {
    const tools = []
    const cursors = new Set()
    let cursor
    do {
      const page = await client.listTools(cursor ? { cursor } : undefined)
      this.assertCurrent(generation)
      tools.push(...page.tools)
      cursor = page.nextCursor
      if (cursor && cursors.has(cursor)) throw new Error('Cloudflare MCP returned a repeated tools pagination cursor')
      if (cursor) cursors.add(cursor)
    } while (cursor)
    const names = tools.map((tool) => publicToolName(tool.name))
    if (new Set(names).size !== names.length) throw new Error('Cloudflare MCP advertised duplicate tool names')
    this.assertCurrent(generation)
    this.unregisterTools()
    try {
      for (const tool of tools) {
        this.disposers.push(this.ctx.tools.register({
          name: publicToolName(tool.name),
          description: tool.description ?? '',
          parameters: tool.inputSchema,
          timeoutMs: 120_000,
          output: { schema: MCP_OUTPUT_SCHEMA, render: renderResult },
          execute: (args, exec = {}) => this.call(client, generation, tool.name, args, exec.signal),
        }))
      }
      this.toolNames = names
    } catch (error) {
      this.unregisterTools()
      throw error
    }
  }

  async call(client, generation, name, args, signal) {
    const result = await this.invoke(client, generation, { name, arguments: args }, { signal })
    if (this.flow.store.data.pending) throw this.flow.requiredError()
    if (result.isError) {
      const text = result.content.filter((block) => block.type === 'text').map((block) => block.text).join('\n')
      throw new Error(this.flow.store.redact(text || 'Cloudflare MCP tool returned an error without a message'))
    }
    return {
      content: result.content,
      ...(result.structuredContent === undefined ? {} : { structuredContent: result.structuredContent }),
    }
  }

  async listTools(params, options = {}) {
    options.signal?.throwIfAborted()
    await this.connect()
    const generation = this.generation
    const client = this.client
    if (!client) throw new Error('Cloudflare MCP connection was disconnected')
    try {
      await this.flow.refreshIfNeeded()
      this.assertCurrent(generation)
      const result = await client.listTools(params, options)
      this.assertCurrent(generation)
      return result
    } catch (error) {
      if (this.flow.store.data.pending) throw this.flow.requiredError()
      throw redactError(error, (message) => this.flow.store.redact(message))
    }
  }

  async callTool(params, options = {}) {
    options.signal?.throwIfAborted()
    await this.connect()
    const client = this.client
    if (!client) throw new Error('Cloudflare MCP connection was disconnected')
    return this.invoke(client, this.generation, params, options)
  }

  async invoke(client, generation, params, options = {}) {
    this.assertCurrent(generation)
    if (this.flow.store.data.pending) throw this.flow.requiredError()
    if (typeof params?.name !== 'string' || !params.name) throw new Error('Cloudflare MCP tool name must be a nonempty string')
    const args = params.arguments === undefined ? {} : params.arguments
    if (!args || typeof args !== 'object' || Array.isArray(args)) throw new Error('Cloudflare MCP tool arguments must be an object')
    options.signal?.throwIfAborted()
    try {
      await this.flow.refreshIfNeeded()
      this.assertCurrent(generation)
      const result = await client.callTool(params, undefined, { timeout: 120_000, ...options })
      this.assertCurrent(generation)
      const challenge = result._meta?.['mcp/www_authenticate']
      if (challenge !== undefined) {
        const headers = typeof challenge === 'string' ? [challenge] : challenge
        if (!Array.isArray(headers) || headers.some((header) => typeof header !== 'string')) {
          throw new Error('Cloudflare MCP returned an invalid authorization challenge')
        }
        for (const header of headers) {
          await this.flow.challenge(header)
        }
      }
      if (!Array.isArray(result.content)) throw new Error('Cloudflare MCP returned a result without content')
      return result
    } catch (error) {
      if (this.flow.store.data.pending) throw this.flow.requiredError()
      if (error instanceof AuthorizationRequiredError) throw error
      throw redactError(error, (message) => this.flow.store.redact(message))
    }
  }

  unregisterTools() {
    for (const dispose of this.disposers.splice(0).reverse()) dispose()
    this.toolNames = []
  }

  async disconnect() {
    this.generation++
    this.connected = false
    this.unregisterTools()
    const client = this.client
    this.client = undefined
    if (client) await client.close()
    if (this.connecting) {
      try {
        await this.connecting
      } catch (error) {
        this.ctx.logger.info('Cloudflare MCP connection attempt stopped during disconnect.')
      }
    }
  }

  async dispose() {
    this.disposed = true
    await this.disconnect()
  }
}
