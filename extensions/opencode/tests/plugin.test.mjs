// opencode 插件的测试：模拟 opencode 1.x 调用插件 hook 的方式（就地改 output，抛出错误阻止）。
import assert from 'node:assert/strict'
import { dirname, join } from 'node:path'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'

import { fake, guard, haveGuard, load, missing, recorded } from '../../testing/helpers.mjs'

const file = join(dirname(fileURLToPath(import.meta.url)), '..', 'h-guard.js')
const KEY = 'deploy with aws_access_key_id = AKIAIOSFODNN7EXAMPL0'

// plugin 加载插件并返回它的 hooks；toasts 收集 client.tui.showToast 的参数；mcp 是 client.mcp.status 返回的 MCP 服务
async function plugin(command, { parentID = '', mcp = { 'my.github': { status: 'connected' } } } = {}) {
  const mod = await load(file, 'opencode', command)
  assert.deepEqual(Object.keys(mod), ['HGuard'], 'opencode requires every export to be a plugin function')
  const toasts = []
  const client = {
    tui: { showToast: async (o) => toasts.push(o.body) },
    session: { get: async () => ({ data: { id: 'ses_1', parentID } }) },
    mcp: { status: async () => ({ data: mcp }) },
  }
  const hooks = await mod.HGuard({ client, directory: '/w', worktree: '/w', project: {}, $: null })
  return { hooks, toasts }
}

const before = (hooks, tool, args) => hooks['tool.execute.before']({ tool, sessionID: 'ses_1', callID: 'call_1' }, { args })

test('tool.execute.before: a catastrophic command is blocked with h-guard\'s reason', { skip: !haveGuard }, async () => {
  const { hooks } = await plugin(guard('opencode'))
  await assert.rejects(before(hooks, 'bash', { command: 'rm -rf /' }), /^Error: h-guard: /)
})

test('tool.execute.before: ordinary commands and tools without actions pass', { skip: !haveGuard }, async () => {
  const { hooks } = await plugin(guard('opencode'))
  await before(hooks, 'bash', { command: 'ls' })
  await before(hooks, 'glob', { pattern: '**/*.go' })
  await before(hooks, 'notes_search', { query: 'x' })
})

test('tool.execute.before: an MCP tool is blocked until it is listed as read-only', { skip: !haveGuard }, async () => {
  const { hooks } = await plugin(guard('opencode'))
  await assert.rejects(before(hooks, 'my_github_create_issue', { title: 'x' }), /harnesses\.opencode\.read_only_tools/)
})

test('request: the tool\'s source comes from the MCP servers opencode reports', async () => {
  const { command, record } = await fake({ action: 'pass' })
  const { hooks } = await plugin(command)
  await before(hooks, 'my_github_create_issue', {})
  await before(hooks, 'notes_search', {})
  const { hooks: failed } = await plugin(command, { mcp: null })
  await before(failed, 'notes_search', {})
  const mod = await load(file, 'opencode', command)
  const thrown = await mod.HGuard({ client: { mcp: { status: async () => { throw new Error('server down') } } }, directory: '/w' })
  await before(thrown, 'notes_search', {})
  const errored = await mod.HGuard({ client: { mcp: { status: async () => ({ error: { name: 'x' } }) } }, directory: '/w' })
  await before(errored, 'notes_search', {})
  const short = await load(file, 'opencode', command, 1000)
  const stalled = await short.HGuard({ client: { mcp: { status: () => new Promise(() => {}) } }, directory: '/w' })
  await before(stalled, 'notes_search', {})
  const got = (await recorded(record)).map((r) => r.request.data.source)
  assert.deepEqual(got, ['mcp', 'opencode', '?', '?', '?', '?'])
})

test('tool.execute.before: a guard that cannot run blocks the call', async () => {
  const { hooks } = await plugin(missing)
  await assert.rejects(before(hooks, 'bash', { command: 'ls' }), /could not run its check, so this tool call was blocked/)
})

test('tool.execute.before: an empty or unreadable reply blocks the call', async () => {
  for (const reply of ['', 'not json', '{"protocol":"h-guard.ext/v1","action":"allow"}']) {
    const { command } = await fake(reply)
    const { hooks } = await plugin(command)
    await assert.rejects(before(hooks, 'bash', { command: 'ls' }), /could not run its check/)
  }
})

test('tool.execute.before: a deny without a message still blocks', async () => {
  const { command } = await fake({ action: 'deny' })
  const { hooks } = await plugin(command)
  await assert.rejects(before(hooks, 'bash', { command: 'ls' }), /without giving a reason/)
})

test('tool.execute.before: warn shows a toast and lets the call run', async () => {
  const { command } = await fake({ action: 'warn', message: 'careful' })
  const { hooks, toasts } = await plugin(command)
  await before(hooks, 'bash', { command: 'ls' })
  assert.deepEqual(toasts, [{ title: 'h-guard', message: 'careful', variant: 'warning' }])
})

test('request: protocol, harness, session and the hook arguments', async () => {
  const { command, record } = await fake({ action: 'pass' })
  const { hooks } = await plugin(command, { parentID: 'ses_parent' })
  await before(hooks, 'bash', { command: 'ls', workdir: 'sub' })
  await hooks['chat.message']({ sessionID: 'ses_1', agent: 'build' }, { message: {}, parts: [{ type: 'text', text: 'hi' }, { type: 'file', url: 'x' }] })
  const [pre, msg] = await recorded(record)
  assert.deepEqual(pre.argv.slice(-2), ['--event', 'tool.execute.before'])
  assert.deepEqual(pre.request, {
    protocol: 'h-guard.ext/v1', harness: 'opencode', hook: 'tool.execute.before', session: { id: 'ses_1', cwd: '/w' },
    data: { tool: 'bash', sessionID: 'ses_1', callID: 'call_1', args: { command: 'ls', workdir: 'sub' }, source: 'opencode' },
  })
  assert.equal(msg.request.data.parentID, 'ses_parent')
  assert.deepEqual(msg.request.data.parts, [{ type: 'text', text: 'hi', synthetic: false }, { type: 'file', synthetic: false }])
})

test('tool.execute.after: deny replaces the output the model sees', async () => {
  const { command } = await fake({ action: 'deny', message: 'contains a credential' })
  const { hooks } = await plugin(command)
  const output = { title: 'cat', output: 'SECRET', metadata: { output: 'SECRET', exit: 0 }, attachments: [{ type: 'file' }] }
  await hooks['tool.execute.after']({ tool: 'bash', sessionID: 'ses_1', callID: 'c', args: { command: 'cat .env' } }, output)
  assert.equal(output.output, 'h-guard: contains a credential')
  assert.equal(output.metadata.output, 'h-guard: contains a credential')
  assert.deepEqual(output.attachments, [])
  const mcp = { title: '', output: '', metadata: {}, content: [{ type: 'text', text: 'SECRET' }] }
  await hooks['tool.execute.after']({ tool: 'srv_q', sessionID: 'ses_1', callID: 'c', args: {} }, mcp)
  assert.deepEqual(mcp.content, [{ type: 'text', text: 'h-guard: contains a credential' }])
})

test('tool.execute.after: a credential in file content is replaced by the real guard', { skip: !haveGuard }, async () => {
  const { hooks } = await plugin(guard('opencode'))
  const output = { title: '', output: KEY, metadata: {} }
  await hooks['tool.execute.after']({ tool: 'read', sessionID: 'ses_1', callID: 'c', args: { filePath: '/w/notes.txt' } }, output)
  assert.match(output.output, /^h-guard: Contains credentials/)
})

test('tool.execute.after: a guard that cannot run lets the output through and says so', async () => {
  const { hooks, toasts } = await plugin(missing)
  const output = { title: '', output: 'ordinary', metadata: {} }
  await hooks['tool.execute.after']({ tool: 'bash', sessionID: 'ses_1', callID: 'c', args: {} }, output)
  assert.equal(output.output, 'ordinary')
  assert.equal(toasts.length, 1)
  assert.match(toasts[0].message, /could not finish its check/)
})

test('chat.message: a prompt with a credential is not sent', { skip: !haveGuard }, async () => {
  const { hooks, toasts } = await plugin(guard('opencode'))
  const output = { message: {}, parts: [{ type: 'text', text: KEY }, { type: 'text', text: KEY, synthetic: true }] }
  await assert.rejects(hooks['chat.message']({ sessionID: 'ses_1' }, output), /Contains credentials/)
  assert.equal(toasts[0].variant, 'error')
  assert.match(output.parts[0].text, /^h-guard: .*The prompt was withheld\.$/)
  assert.equal(output.parts[1].text, '')
  await hooks['chat.message']({ sessionID: 'ses_1' }, { message: {}, parts: [{ type: 'text', text: 'fix the test' }] })
})

test('chat.message: a guard that cannot run sends the prompt and says so', async () => {
  const { hooks, toasts } = await plugin(missing)
  await hooks['chat.message']({ sessionID: 'ses_1' }, { message: {}, parts: [{ type: 'text', text: 'hi' }] })
  assert.match(toasts[0].message, /could not finish its check/)
})

test('timeout: a guard that does not answer in time blocks the call', async () => {
  const { command } = await fake({ action: 'pass' }, 'slow')
  const mod = await load(file, 'opencode', command, 300)
  const hooks = await mod.HGuard({ client: { tui: { showToast: async () => {} }, session: { get: async () => ({}) } }, directory: '/w' })
  await assert.rejects(before(hooks, 'bash', { command: 'ls' }), /exit code -1/)
})

test('tool.execute.after: text in an embedded MCP resource is passed on for scanning', async () => {
  const { command, record } = await fake({ action: 'pass' })
  const { hooks } = await plugin(command)
  const output = { title: '', output: '', metadata: {}, content: [{ type: 'text', text: 'a' }, { type: 'resource', resource: { uri: 'x://y', text: 'SECRET' } }, { type: 'image', data: 'AA==' }] }
  await hooks['tool.execute.after']({ tool: 'srv_q', sessionID: 'ses_1', callID: 'c', args: {} }, output)
  const [r] = await recorded(record)
  assert.deepEqual(r.request.result.content, [{ type: 'text', text: 'a' }, { type: 'text', text: 'SECRET' }])
})

test('chat.message: a failed session lookup marks the prompt as possibly automated', async () => {
  const { command, record } = await fake({ action: 'pass' })
  const mod = await load(file, 'opencode', command)
  const client = { tui: { showToast: async () => {} }, session: { get: async () => { throw new Error('server down') } } }
  const hooks = await mod.HGuard({ client, directory: '/w' })
  await hooks['chat.message']({ sessionID: 'ses_1' }, { message: {}, parts: [{ type: 'text', text: 'push it' }] })
  const [r] = await recorded(record)
  assert.equal(r.request.data.parentID, '?')
})
