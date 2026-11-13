import assert from 'node:assert/strict'
import { chmodSync, existsSync, readFileSync, readdirSync, statSync, symlinkSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import test from 'node:test'
import { configPath, CredentialStore, MCP_URL } from '../lib/store.js'
import { temporaryDirectory } from './support.js'

test('store uses DSH_HOME and requires an absolute override', () => {
  const previous = process.env.DSH_HOME
  try {
    process.env.DSH_HOME = '/tmp/example-dsh-home'
    assert.equal(configPath(), '/tmp/example-dsh-home/dsh-cloudflare-connector/auth.json')
    assert.throws(() => configPath('relative.json'), /absolute/)
  } finally {
    if (previous === undefined) delete process.env.DSH_HOME
    else process.env.DSH_HOME = previous
  }
})

test('default storage never imports, overwrites or clears the old connector credentials', (t) => {
  const directory = temporaryDirectory(t)
  const previous = process.env.DSH_HOME
  try {
    process.env.DSH_HOME = directory
    const legacy = new CredentialStore({ tokenFile: join(directory, 'dsh-cloudflare-mcp', 'auth.json') })
    legacy.update({ tokens: { access_token: 'legacy-access', token_type: 'bearer' } })
    const original = readFileSync(legacy.path, 'utf8')
    const current = new CredentialStore()
    assert.equal(current.path, join(directory, 'dsh-cloudflare-connector', 'auth.json'))
    assert.equal(current.data.tokens, undefined)
    current.update({ tokens: { access_token: 'new-access', token_type: 'bearer' } })
    current.clear()
    assert.equal(readFileSync(legacy.path, 'utf8'), original)
  } finally {
    if (previous === undefined) delete process.env.DSH_HOME
    else process.env.DSH_HOME = previous
  }
})

test('credentials are atomic, private, durable and removed by clear', (t) => {
  const directory = temporaryDirectory(t)
  const tokenFile = join(directory, 'private', 'auth.json')
  const store = new CredentialStore({ tokenFile })
  store.update({ tokens: { access_token: 'secret-access', refresh_token: 'secret-refresh', token_type: 'bearer', issuer: 'https://mcp.cloudflare.com' } })
  assert.equal(statSync(tokenFile).mode & 0o777, 0o600)
  assert.equal(statSync(join(directory, 'private')).mode & 0o777, 0o700)
  store.update({ expiresAt: 1234 })
  assert.deepEqual(readdirSync(join(directory, 'private')), ['auth.json'])
  assert.equal(JSON.parse(readFileSync(tokenFile)).tokens.refresh_token, 'secret-refresh')
  chmodSync(tokenFile, 0o644)
  const restored = new CredentialStore({ tokenFile })
  assert.equal(statSync(tokenFile).mode & 0o777, 0o600)
  assert.equal(restored.data.expiresAt, 1234)
  assert.equal(restored.redact('secret-access secret-refresh Bearer unknown ?code=my-code&state=s'), '[redacted] [redacted] Bearer [redacted] ?code=[redacted]&state=[redacted]')
  restored.clear()
  restored.clear()
  assert.equal(existsSync(tokenFile), false)
  assert.deepEqual(restored.data, { version: 1, endpoint: MCP_URL })
})

test('corrupt files, symlinks, endpoint mismatches and invalid writes fail explicitly without secret echoes', (t) => {
  const directory = temporaryDirectory(t)
  const tokenFile = join(directory, 'auth.json')
  writeFileSync(tokenFile, '{"access_token":"sensitive-value",')
  assert.throws(() => new CredentialStore({ tokenFile }), (error) => /invalid JSON/.test(error.message) && !error.message.includes('sensitive-value'))
  writeFileSync(tokenFile, '{"tokens":{"access_token":"sensitive-value"}}')
  assert.throws(() => new CredentialStore({ tokenFile }), /invalid format/)
  const store = new CredentialStore({ tokenFile: join(directory, 'valid.json') })
  store.update({})
  assert.throws(() => new CredentialStore({ tokenFile: store.path, endpoint: 'https://other.example/mcp' }), /another endpoint/)
  assert.throws(() => store.update({ tokens: { access_token: 'sensitive-value' } }), /invalid Cloudflare credential state/)
  assert.equal(store.data.tokens, undefined)
  symlinkSync(store.path, join(directory, 'link.json'))
  assert.throws(() => new CredentialStore({ tokenFile: join(directory, 'link.json') }), /regular file/)
})
