// DeepSeek Harness 插件的测试：模拟 Cordis 的 ctx.on 与 waterfall 的 next。
import assert from 'node:assert/strict'
import { dirname, join } from 'node:path'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'

import { fake, guard, haveGuard, load, missing, recorded } from '../../testing/helpers.mjs'

const file = join(dirname(fileURLToPath(import.meta.url)), '..', 'h-guard.mjs')
const KEY = 'deploy with aws_access_key_id = AKIAIOSFODNN7EXAMPL0'
const NEXT = { kind: 'from-next' }

// plugin 加载插件，返回事件处理函数；logs 收集 ctx.logger.warn
async function plugin(command) {
  const mod = await load(file, 'dsh', command)
  assert.equal(mod.name, 'h-guard')
  const handlers = {}
  const logs = []
  mod.apply({ on: (name, fn) => (handlers[name] = fn), logger: { warn: (m) => logs.push(m) } })
  return { handlers, logs }
}

const agent = (header = {}) => ({ session: { header: { id: 'ses-1', cwd: '/w', ...header } } })
const exec = (name, args) => ({ name, callId: 'c1', arguments: args, agent: agent(), signal: undefined })
const next = async () => NEXT

test('tools/pre-execute: deny, ask and pass', { skip: !haveGuard }, async () => {
  const { handlers } = await plugin(guard('dsh'))
  const deny = await handlers['tools/pre-execute'](exec('bash', { command: 'rm -rf /' }), next)
  assert.equal(deny.kind, 'deny')
  assert.match(deny.reason, /^h-guard: /)
  const ask = await handlers['tools/pre-execute'](exec('read', { file_path: '/w/.env' }), next)
  assert.equal(ask.kind, 'ask')
  assert.equal(ask.displayReason.en, ask.reason)
  assert.equal(await handlers['tools/pre-execute'](exec('bash', { command: 'ls' }), next), NEXT)
  assert.equal(await handlers['tools/pre-execute'](exec('glob', { pattern: '*' }), next), NEXT)
})

test('tools/pre-execute: a guard that cannot run asks', async () => {
  const { handlers } = await plugin(missing)
  const r = await handlers['tools/pre-execute'](exec('bash', { command: 'ls' }), next)
  assert.equal(r.kind, 'ask')
  assert.match(r.reason, /could not run its check/)
})

test('request: session id and cwd from the session header, nested calls marked', async () => {
  const { command, record } = await fake({ action: 'pass' })
  const { handlers } = await plugin(command)
  await handlers['tools/pre-execute']({ ...exec('bash', { command: 'ls' }), parent: { callId: 'p' } }, next)
  const [r] = await recorded(record)
  assert.deepEqual(r.request, {
    protocol: 'h-guard.ext/v1', harness: 'dsh', hook: 'tools/pre-execute', session: { id: 'ses-1', cwd: '/w' },
    data: { name: 'bash', callId: 'c1', arguments: { command: 'ls' }, nested: true },
  })
})

test('tools/post-execute: deny blocks with the reason; a guard that cannot run lets it through and logs', async () => {
  const { command } = await fake({ action: 'deny', message: 'contains a credential' })
  const { handlers } = await plugin(command)
  const result = { isError: false, content: [{ type: 'text', text: 'SECRET' }] }
  assert.deepEqual(await handlers['tools/post-execute'](exec('read', { file_path: 'a' }), result, next), {
    kind: 'block', feedback: [{ type: 'text', text: 'h-guard: contains a credential' }],
  })
  const broken = await plugin(missing)
  assert.equal(await broken.handlers['tools/post-execute'](exec('read', { file_path: 'a' }), result, next), NEXT)
  assert.match(broken.logs[0], /could not finish its check/)
})

test('agent/pre-step: a prompt with a credential is rejected; steps without new messages are skipped', { skip: !haveGuard }, async () => {
  const { handlers } = await plugin(guard('dsh'))
  const step = (text) => ({ agent: agent(), messages: [{ role: 'user', source: { kind: 'user' }, content: [{ type: 'text', text }] }], turn: 1, step: 0 })
  assert.deepEqual(await handlers['agent/pre-step'](step(KEY), next), { kind: 'reject' })
  assert.equal(await handlers['agent/pre-step'](step('fix the test'), next), NEXT)
  assert.equal(await handlers['agent/pre-step']({ agent: agent(), messages: [] }, next), NEXT)
})

test('agent/pre-step: the subagent header is passed on', async () => {
  const { command, record } = await fake({ action: 'pass' })
  const { handlers } = await plugin(command)
  await handlers['agent/pre-step']({ agent: agent({ origin: 'subagent', delegationDepth: 1 }), messages: [{ source: { kind: 'user' }, content: 'task' }] }, next)
  const [r] = await recorded(record)
  assert.deepEqual(r.request.data, {
    messages: [{ source: { kind: 'user' }, content: [{ type: 'text', text: 'task' }] }],
    session: { origin: 'subagent', delegationDepth: 1 },
  })
})

test('tools/pre-execute: a cancelled call stops waiting for the guard', async () => {
  const { command } = await fake({ action: 'pass' }, 'slow')
  const { handlers } = await plugin(command)
  const ac = new AbortController()
  const started = Date.now()
  setTimeout(() => ac.abort(), 200)
  const r = await handlers['tools/pre-execute']({ ...exec('bash', { command: 'ls' }), signal: ac.signal }, next)
  assert.ok(Date.now() - started < 5000, 'returned only after ' + (Date.now() - started) + 'ms')
  assert.equal(r.kind, 'ask')
  const pre = new AbortController()
  pre.abort()
  assert.equal((await handlers['tools/pre-execute']({ ...exec('bash', { command: 'ls' }), signal: pre.signal }, next)).kind, 'ask')
})

test('request: cwd follows the session working directory when dsh provides it', async () => {
  const { command, record } = await fake({ action: 'pass' })
  const mod = await load(file, 'dsh', command)
  const handlers = {}
  const wd = { get: (session) => (session.header.id === 'ses-1' ? '/w/sub' : undefined) }
  mod.apply({ on: (name, fn) => (handlers[name] = fn), logger: { warn: () => {} }, get: (name) => (name === 'workingDirectory' ? wd : undefined) })
  await handlers['tools/pre-execute'](exec('bash', { command: 'ls' }), next)
  const [r] = await recorded(record)
  assert.equal(r.request.session.cwd, '/w/sub')
})
