// pi / omp 扩展的测试：模拟扩展 API（pi.on 注册事件，ctx 带界面与会话管理器）。
import assert from 'node:assert/strict'
import { dirname, join } from 'node:path'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'

import { fake, guard, haveGuard, load, missing, recorded } from '../../testing/helpers.mjs'

const file = join(dirname(fileURLToPath(import.meta.url)), '..', 'h-guard.js')
const KEY = 'deploy with aws_access_key_id = AKIAIOSFODNN7EXAMPL0'

// extension 加载扩展，返回事件处理函数与 ctx 工厂；confirms、notes 收集 ctx.ui 的调用
async function extension(command, harness = 'pi') {
  const mod = await load(file, harness, command)
  const handlers = {}
  mod.default({ on: (name, fn) => (handlers[name] = fn) })
  const confirms = []
  const notes = []
  const ctx = ({ hasUI = true, answer = false } = {}) => ({
    cwd: '/w',
    hasUI,
    sessionManager: { getSessionId: () => 'sess-1' },
    ui: {
      confirm: async (title, message) => {
        confirms.push({ title, message })
        return answer
      },
      notify: (message, level) => notes.push({ message, level }),
    },
  })
  return { handlers, ctx, confirms, notes }
}

const call = (h, ctx, toolName, input) => h.tool_call({ type: 'tool_call', toolCallId: 'c1', toolName, input }, ctx)

test('tool_call: a catastrophic command is blocked', { skip: !haveGuard }, async () => {
  const { handlers, ctx } = await extension(guard('pi'))
  const r = await call(handlers, ctx(), 'bash', { command: 'rm -rf /' })
  assert.equal(r.block, true)
  assert.match(r.reason, /^h-guard: /)
  assert.equal(await call(handlers, ctx(), 'bash', { command: 'ls' }), undefined)
  assert.equal(await call(handlers, ctx(), 'ls', { path: '.' }), undefined)
})

test('tool_call: ask asks the user; a yes runs the call, a no or no UI blocks it', { skip: !haveGuard }, async () => {
  const { handlers, ctx, confirms } = await extension(guard('pi'))
  assert.equal(await call(handlers, ctx({ answer: true }), 'read', { path: '.env' }), undefined)
  assert.equal(confirms.length, 1)
  assert.equal(confirms[0].title, 'h-guard')
  assert.match(confirms[0].message, /\.env/)
  const no = await call(handlers, ctx({ answer: false }), 'read', { path: '.env' })
  assert.equal(no.block, true)
  assert.match(no.reason, /did not confirm/)
  const headless = await call(handlers, ctx({ hasUI: false, answer: true }), 'read', { path: '.env' })
  assert.equal(headless.block, true)
  assert.equal(confirms.length, 2, 'no confirm without a UI')
})

test('tool_call: a guard that cannot run asks for confirmation', async () => {
  const { handlers, ctx, confirms } = await extension(missing)
  assert.equal((await call(handlers, ctx({ hasUI: false }), 'bash', { command: 'ls' })).block, true)
  assert.equal(await call(handlers, ctx({ answer: true }), 'bash', { command: 'ls' }), undefined)
  assert.match(confirms[0].message, /could not run its check/)
})

test('tool_call: a deny without a message still blocks; warn notifies and runs', async () => {
  let { command } = await fake({ action: 'deny' })
  let { handlers, ctx } = await extension(command)
  assert.match((await call(handlers, ctx(), 'bash', { command: 'ls' })).reason, /without giving a reason/)
  ;({ command } = await fake({ action: 'warn', message: 'careful' }))
  const e = await extension(command)
  assert.equal(await call(e.handlers, e.ctx(), 'bash', { command: 'ls' }), undefined)
  assert.deepEqual(e.notes, [{ message: 'h-guard: careful', level: 'warning' }])
})

test('request: harness from the install, session id and cwd from ctx', async () => {
  for (const harness of ['pi', 'omp']) {
    const { command, record } = await fake({ action: 'pass' })
    const { handlers, ctx } = await extension(command, harness)
    await call(handlers, ctx(), 'bash', { command: 'ls' })
    const [r] = await recorded(record)
    assert.deepEqual(r.argv.slice(-2), ['--event', 'tool_call'])
    assert.deepEqual(r.request, {
      protocol: 'h-guard.ext/v1', harness, hook: 'tool_call', session: { id: 'sess-1', cwd: '/w' },
      data: { toolCallId: 'c1', toolName: 'bash', input: { command: 'ls' } },
    })
  }
})

test('tool_result: deny replaces the content; a guard that cannot run lets it through and notifies', async () => {
  const { command } = await fake({ action: 'deny', message: 'contains a credential' })
  const { handlers, ctx } = await extension(command)
  const ev = { toolCallId: 'c1', toolName: 'read', input: { path: 'a' }, content: [{ type: 'text', text: 'SECRET' }], isError: false }
  assert.deepEqual(await handlers.tool_result(ev, ctx()), { content: [{ type: 'text', text: 'h-guard: contains a credential' }] })
  const broken = await extension(missing)
  assert.equal(await broken.handlers.tool_result(ev, broken.ctx()), undefined)
  assert.match(broken.notes[0].message, /could not finish its check/)
})

test('tool_result: a credential in file content is replaced by the real guard', { skip: !haveGuard }, async () => {
  const { handlers, ctx } = await extension(guard('omp'), 'omp')
  const r = await handlers.tool_result({ toolCallId: 'c1', toolName: 'read', input: { path: 'notes.txt:1-5' }, content: [{ type: 'text', text: KEY }] }, ctx())
  assert.match(r.content[0].text, /^h-guard: Contains credentials/)
})

test('input: a prompt with a credential is handled (not sent) in both pi and omp form', { skip: !haveGuard }, async () => {
  const { handlers, ctx, notes } = await extension(guard('pi'))
  assert.deepEqual(await handlers.input({ text: KEY, source: 'interactive' }, ctx()), { action: 'handled', handled: true })
  assert.equal(notes[0].level, 'error')
  assert.equal(await handlers.input({ text: 'fix the test', source: 'interactive' }, ctx()), undefined)
})

test('input: a guard that cannot run sends the prompt; without a UI the note goes to stderr', async () => {
  const { handlers, ctx, notes } = await extension(missing)
  assert.equal(await handlers.input({ text: 'hi', source: 'interactive' }, ctx({ hasUI: false })), undefined)
  assert.equal(notes.length, 0)
})
