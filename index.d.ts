import type { z } from 'zod'
import type { CallToolRequest, CallToolResult, ListToolsRequest, ListToolsResult } from '@modelcontextprotocol/sdk/types.js'
import type { RequestOptions } from '@modelcontextprotocol/sdk/shared/protocol.js'

export type JsonValue = null | boolean | number | string | JsonValue[] | { [key: string]: JsonValue }
export type McpRequestOptions = Pick<RequestOptions, 'signal' | 'timeout' | 'onprogress' | 'resetTimeoutOnProgress' | 'maxTotalTimeout'>

export interface CloudflareConnectorConfig {
  enabled?: boolean
  announceToAgent?: boolean
  scopes?: string[]
  endpoint?: string
  tokenFile?: string
}

export interface CloudflareConnectorStatus {
  authorized: boolean
  connected: boolean
  scopes: string[]
  toolCount: number
  pendingAuthorization: boolean
  authorizationExpired: boolean
  pendingStepUp: boolean
  requestedScopes: string[]
  expiresAt?: string
}

export interface CloudflareAuthorization {
  authorizationUrl: string
  scopes: string[]
  stepUp: boolean
  instructions: string
}

export interface CloudflareApiRequest {
  method?: string
  path: string
  query?: Record<string, string | number | boolean | null | undefined>
  body?: JsonValue
}

export interface CloudflareApiRequestOptions {
  accountId?: string
  signal?: AbortSignal
  timeoutMs?: number
  sensitiveValues?: string[]
}

export interface CloudflareConnectorService {
  status(): CloudflareConnectorStatus
  listTools(params?: ListToolsRequest['params'], options?: McpRequestOptions): Promise<ListToolsResult>
  callTool(params: CallToolRequest['params'], options?: McpRequestOptions): Promise<CallToolResult>
  request(request: CloudflareApiRequest, options?: CloudflareApiRequestOptions): Promise<JsonValue>
  authorize(options?: { scopes?: string[] }): Promise<CloudflareAuthorization>
  finish(options: { code: string; state?: string }): Promise<CloudflareConnectorStatus>
  test(): Promise<CloudflareConnectorStatus & { tools: string[] }>
  clear(): Promise<CloudflareConnectorStatus>
}

export interface CloudflareConnectorContext {
  cloudflareConnector?: CloudflareConnectorService
  get(name: 'cloudflareConnector'): CloudflareConnectorService | undefined
}

export type CloudflareConnectorErrorCode = 'mcp_error' | 'api_error' | 'invalid_request' | 'invalid_result' | 'invalid_scope' | 'authorization_required'

export class CloudflareConnectorError extends Error {
  constructor(message: string, options?: { code?: CloudflareConnectorErrorCode; status?: number | null })
  readonly code: CloudflareConnectorErrorCode
  readonly status: number | null
}

export class AuthorizationRequiredError extends CloudflareConnectorError {
  constructor(pending?: { scopes: string[]; stepUp?: boolean; authorizeUrl?: string })
  readonly code: 'authorization_required'
  readonly scopes: string[]
  readonly authorizationUrl: string | undefined
}

export const name: string
export const inject: string[]
export const GUIDANCE: string
export const Config: z.ZodType<Required<Omit<CloudflareConnectorConfig, 'tokenFile'>> & { tokenFile?: string }, CloudflareConnectorConfig | undefined>
export function apply(context: object, config?: CloudflareConnectorConfig): void
