import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { mkdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'
import ts from 'typescript'
import { temporaryDirectory } from './support.js'

test('published tarball installs independently and exposes working runtime, types and DSH bundle', (t) => {
  const root = fileURLToPath(new URL('..', import.meta.url))
  const directory = temporaryDirectory(t)
  const project = join(directory, 'consumer')
  mkdirSync(project)
  const npm = process.platform === 'win32' ? 'npm.cmd' : 'npm'
  const run = (args, cwd) => execFileSync(npm, args, { cwd, encoding: 'utf8', timeout: 120_000, maxBuffer: 4 * 1024 * 1024 })
  const [packed] = JSON.parse(run(['pack', '--json', '--ignore-scripts', '--pack-destination', directory], root))
  assert.equal(packed.name, '@beings-labs/dsh-cloudflare-connector')
  const files = new Set(packed.files.map(({ path }) => path))
  for (const path of ['package.json', 'index.js', 'index.d.ts', 'lib/service.js', 'cordis.patch.yml', 'README.md', 'LICENSE']) {
    assert.ok(files.has(path), `Missing package file: ${path}`)
  }
  for (const path of files) {
    assert.ok(/^(?:package\.json|index\.js|index\.d\.ts|lib\/[^/]+\.js|cordis\.patch\.yml|README\.md|LICENSE)$/.test(path), `Unexpected package file: ${path}`)
  }
  run(['install', '--prefix', project, '--ignore-scripts', '--no-audit', '--no-fund', '--omit=dev', '--omit=optional', join(directory, packed.filename)], project)
  const installed = join(project, 'node_modules', '@beings-labs', 'dsh-cloudflare-connector')
  const manifest = JSON.parse(readFileSync(join(installed, 'package.json'), 'utf8'))
  assert.equal(manifest.version, packed.version)
  assert.equal(manifest.types, 'index.d.ts')
  const patch = readFileSync(join(installed, manifest.dsh.bundle.patch), 'utf8')
  assert.match(patch, /id: beings-labs-cloudflare-connector/)
  assert.match(patch, /name: '@beings-labs\/dsh-cloudflare-connector'/)
  const output = execFileSync(process.execPath, ['--input-type=module', '--eval', `
    import assert from 'node:assert/strict'
    import { apply, Config, name, CloudflareConnectorError, AuthorizationRequiredError } from '@beings-labs/dsh-cloudflare-connector'
    assert.equal(name, 'beings-labs-cloudflare-connector')
    assert.deepEqual(Config.parse({}).scopes, ['user:read', 'account:read'])
    assert.deepEqual(Config.parse(undefined), Config.parse({}))
    assert.ok(new AuthorizationRequiredError() instanceof CloudflareConnectorError)
    const tools = new Map()
    const routes = new Map()
    const effects = []
    const ctx = {
      logger: { warn(message) { throw new Error(message) } },
      get(key) { return this[key] },
      provide(key, value) { this[key] = value; return () => { delete this[key] } },
      tools: { register(tool) { tools.set(tool.name, tool); return () => tools.delete(tool.name) } },
      webServer: {
        getOrigin: () => 'http://127.0.0.1:4899',
        register(route) { routes.set(route.path, route); return () => routes.delete(route.path) },
      },
      systemPrompt: { section: () => () => {} },
      effect(setup) { effects.push(setup()) },
    }
    apply(ctx)
    assert.deepEqual([...tools.keys()], [
      'cloudflare_connector_authorize', 'cloudflare_connector_finish', 'cloudflare_connector_status',
      'cloudflare_connector_test', 'cloudflare_connector_clear',
    ])
    assert.ok(routes.has('/api/dsh-cloudflare-connector/oauth/callback'))
    assert.equal(ctx.get('cloudflareConnector').status().authorized, false)
    assert.equal((await tools.get('cloudflare_connector_status').execute({})).connected, false)
    for (const dispose of effects.reverse()) await dispose()
    assert.equal(ctx.get('cloudflareConnector'), undefined)
    assert.equal(tools.size, 0)
    assert.equal(routes.size, 0)
    console.log('Installed package runtime verified.')
  `], {
    cwd: project,
    env: { ...process.env, DSH_HOME: join(directory, 'profile') },
    encoding: 'utf8',
    timeout: 30_000,
  })
  assert.match(output, /Installed package runtime verified/)
  const filename = join(project, 'public-api.mts')
  const readme = readFileSync(new URL('../README.md', import.meta.url), 'utf8')
  const documentedTypes = [...readme.matchAll(/```ts\n([\s\S]*?)\n```/g)].map((match) => match[1]).join('\n')
  assert.ok(documentedTypes, 'README must demonstrate the public TypeScript API')
  const headings = new Set([...readme.matchAll(/^#{1,6} (.+)$/gm)]
    .map((match) => match[1].toLowerCase().replace(/[^\w\s-]/g, '').replace(/\s+/g, '-')))
  for (const match of readme.matchAll(/\[[^\]]+\]\((#[^)]+)\)/g)) {
    assert.ok(headings.has(match[1].slice(1)), `Missing README anchor: ${match[1]}`)
  }
  const source = documentedTypes + `
    import { AuthorizationRequiredError, CloudflareConnectorError } from '@beings-labs/dsh-cloudflare-connector'
    import type { CloudflareConnectorContext, JsonValue } from '@beings-labs/dsh-cloudflare-connector'
    declare const ctx: CloudflareConnectorContext
    const result: Promise<JsonValue> | undefined = ctx.get('cloudflareConnector')?.request({ path: '/accounts' })
    new CloudflareConnectorError('example', { code: 'api_error' })
    new AuthorizationRequiredError().code satisfies 'authorization_required'
    void result
  `
  const options = { strict: true, noEmit: true, module: ts.ModuleKind.NodeNext, target: ts.ScriptTarget.ES2022 }
  const host = ts.createCompilerHost(options)
  const original = host.getSourceFile.bind(host)
  host.getSourceFile = (name, languageVersion, onError, shouldCreateNewSourceFile) => name === filename
    ? ts.createSourceFile(name, source, languageVersion, true)
    : original(name, languageVersion, onError, shouldCreateNewSourceFile)
  const diagnostics = ts.getPreEmitDiagnostics(ts.createProgram([filename], options, host))
  assert.equal(diagnostics.length, 0, ts.formatDiagnosticsWithColorAndContext(diagnostics, {
    getCanonicalFileName: (name) => name,
    getCurrentDirectory: () => project,
    getNewLine: () => '\n',
  }))
})
