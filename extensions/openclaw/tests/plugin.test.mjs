// OpenClaw 插件的测试：模拟插件 API 的 api.on、registerAgentToolResultMiddleware 与 runtime.system.runCommandWithTimeout。
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { dirname, join } from 'node:path'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'

import { fake, guard, haveGuard, load, missing, recorded } from '../../testing/helpers.mjs'

const file = join(dirname(fileURLToPath(import.meta.url)), '..', 'index.mjs')
const KEY = 'deploy with aws_access_key_id = AKIAIOSFODNN7EXAMPL0'

// runCommandWithTimeout 按 OpenClaw 的约定运行命令：不经 shell，input 写到 stdin，超时或取消时 code 为 null
function runCommandWithTimeout(argv, opts) {
  return new Promise((resolve, reject) => {
    const child = spawn(argv[0], argv.slice(1), { stdio: ['pipe', 'pipe', 'ignore'] })
    let stdout = ''
    let termination = 'exit'
    const timer = setTimeout(() => {
      termination = 'timeout'
      child.kill()
    }, opts.timeoutMs)
    const abort = () => {
      termination = 'signal'
      child.kill()
    }
    if (opts.signal) opts.signal.addEventListener('abort', abort, { once: true })
    child.on('error', (err) => {
      clearTimeout(timer)
      reject(err)
    })
    child.on('close', (code) => {
      clearTimeout(timer)
      resolve({ code: termination === 'exit' ? code : null, stdout, termination })
    })
    child.stdout.setEncoding('utf8')
    child.stdout.on('data', (d) => (stdout += d))
    child.stdin.on('error', () => {})
    child.stdin.end(opts.input || '')
  })
}

// plugin 加载插件并注册，返回 hook、middleware、日志与发出的通知；opts.runtime 替换模拟的 runtime
async function plugin(command, opts = {}) {
  const mod = await load(file, 'openclaw', command)
  const entry = mod.default
  assert.equal(entry.id, 'h-guard')
  const hooks = {}
  const logs = []
  const sent = []
  let middleware
  let middlewareOpts
  const run = (argv, o) => {
    const i = argv.indexOf('message')
    if (i >= 0 && argv[i + 1] === 'send') {
      sent.push(argv)
      return Promise.resolve({ code: 0, stdout: '', termination: 'exit' })
    }
    return runCommandWithTimeout(argv, o)
  }
  const api = {
    id: 'h-guard',
    pluginConfig: opts.pluginConfig,
    logger: { warn: (m) => logs.push(m), info: () => {} },
    runtime: opts.runtime || {
      version: '2026.10.4',
      system: { runCommandWithTimeout: run },
      config: { current: () => opts.config || { agents: {} } },
      agent: {
        resolveAgentWorkspaceDir: (cfg, id) => '/ws/' + id,
        session: { getSessionEntryAsync: opts.session || (async () => undefined) },
      },
    },
    on: (name, fn) => (hooks[name] = fn),
    registerAgentToolResultMiddleware: (fn, o) => {
      middleware = fn
      middlewareOpts = o
    },
  }
  entry.register(api)
  return { hooks, middleware: (e, c) => middleware(e, c), middlewareOpts, logs, sent }
}

const ctx = (extra = {}) => ({ agentId: 'main', sessionKey: 'agent:main:main', sessionId: 'ses-1', toolName: 'exec', toolCallId: 'c1', ...extra })
const call = (toolName, params, extra = {}) => ({ toolName, params, toolCallId: 'c1', ...extra })
const result = (toolName, args, text) => ({ toolName, toolCallId: 'c1', args, isError: false, result: { content: [{ type: 'text', text }], details: { aggregated: text } } })

test('before_tool_call: deny blocks, ask requires one-time approval, pass returns nothing', { skip: !haveGuard }, async () => {
  const { hooks } = await plugin(guard('openclaw'))
  const deny = await hooks.before_tool_call(call('exec', { command: 'rm -rf /' }), ctx())
  assert.equal(deny.block, true)
  assert.match(deny.blockReason, /^h-guard: /)
  const ask = await hooks.before_tool_call(call('read', { path: '/w/.env' }), ctx({ toolName: 'read' }))
  assert.equal(ask.requireApproval.title, 'h-guard: confirm this tool call')
  assert.deepEqual(ask.requireApproval.allowedDecisions, ['allow-once', 'deny'])
  assert.match(ask.requireApproval.description, /\nread: file_read \/w\/\.env$/)
  assert.ok(ask.requireApproval.description.length <= 512)
  assert.equal(await hooks.before_tool_call(call('exec', { command: 'ls' }), ctx()), undefined)
  assert.equal(await hooks.before_tool_call(call('sessions_list', {}), ctx()), undefined)
  const unknown = await hooks.before_tool_call(call('my_plugin_tool', {}), ctx())
  assert.match(unknown.requireApproval.description, /read_only_tools/)
})

test("before_tool_call: approvals show h-guard's masked summary, never the raw arguments", { skip: !haveGuard }, async () => {
  const token = 'abcdefghijklmnopqrstuv'
  // tools.exec.host 配置成 node：命令在远端设备上运行，h-guard 请求确认
  const { hooks } = await plugin(guard('openclaw'), { config: { tools: { exec: { host: 'node' } } } })
  const ask = await hooks.before_tool_call(call('exec', { command: 'curl -H "Authorization: Bearer ' + token + '" https://example.com' }), ctx())
  assert.ok(ask.requireApproval, 'a command for a node asks')
  assert.equal(ask.requireApproval.description.includes(token), false)
  assert.match(ask.requireApproval.description, /\nexec: curl -H "Authorization: Bearer \[redacted\]" https:\/\/example\.com$/)
})

test('before_tool_call: a guard that cannot run asks and logs why', async () => {
  const { hooks, logs } = await plugin(missing)
  const r = await hooks.before_tool_call(call('exec', { command: 'curl -H "Authorization: Bearer abcdefghijklmnopqrstuv" x' }), ctx())
  assert.match(r.requireApproval.description, /could not run its check/)
  assert.match(r.requireApproval.description, /\nexec$/) // 没有 h-guard 遮蔽时只写工具名
  assert.equal(r.requireApproval.description.includes('abcdefghijklmnopqrstuv'), false)
  assert.match(logs[0], /could not finish its check/)
  // OpenClaw 没有提供 runCommandWithTimeout 时同样请求确认
  const bare = await plugin(missing, { runtime: {} })
  assert.ok((await bare.hooks.before_tool_call(call('exec', { command: 'ls' }), ctx())).requireApproval)
})

test('request: session id, workspace cwd, platform and the tool kind are passed on', async () => {
  const { command, record } = await fake({ action: 'pass' })
  const { hooks } = await plugin(command)
  await hooks.before_tool_call(call('exec', { code: 'await tools.read({path: "a"})', command: 'x' }, { toolKind: 'code_mode_exec', toolInputKind: 'javascript' }), ctx())
  const [r] = await recorded(record)
  assert.deepEqual(r.argv, ['--event', 'before_tool_call'])
  assert.deepEqual(r.request, {
    protocol: 'h-guard.ext/v1', harness: 'openclaw', harness_version: '2026.10.4', hook: 'before_tool_call', session: { id: 'ses-1', cwd: '/ws/main' },
    data: {
      toolName: 'exec', toolCallId: 'c1', params: { code: 'await tools.read({path: "a"})', command: 'x' },
      toolKind: 'code_mode_exec', toolInputKind: 'javascript', platform: process.platform,
    },
  })
})

test("request: execHost follows the call, the session's /exec setting and the configuration", async () => {
  const { command, record } = await fake({ action: 'pass' })
  const host = async (opts, params, c = ctx()) => {
    const { hooks } = await plugin(command, opts)
    await hooks.before_tool_call(call('exec', { command: 'ls', ...params }), c)
    const all = await recorded(record)
    return all[all.length - 1].request.data.execHost
  }
  assert.equal(await host({}, {}), 'auto')
  assert.equal(await host({}, { host: 'sandbox' }), 'sandbox')
  assert.equal(await host({}, { node: 'phone' }), 'node')
  assert.equal(await host({ config: { tools: { exec: { host: 'node' } } } }, { host: 'auto' }), 'node')
  assert.equal(await host({ config: { tools: { exec: { host: 'gateway' } }, agents: { entries: { Main: { tools: { exec: { host: 'node' } } } } } } }, {}), 'node')
  assert.equal(await host({ config: { agents: { list: [{ id: 'main', tools: { exec: { host: 'sandbox' } } }] } } }, {}), 'sandbox')
  assert.equal(await host({ session: async (p) => (p.sessionKey === 'agent:main:main' ? { execHost: 'node' } : undefined) }, {}), 'node')
  assert.equal(await host({ session: async () => ({ execNode: 'phone' }) }, {}), 'node')
  assert.equal(await host({ session: async () => { throw new Error('store busy') } }, {}), 'unknown')
  const { hooks } = await plugin(command)
  await hooks.before_tool_call(call('read', { path: 'a' }), ctx())
  const all = await recorded(record)
  assert.equal('execHost' in all[all.length - 1].request.data, false)
})

test('request: toolSource is mcp only for tools of a server in mcp.servers', async () => {
  const { command, record } = await fake({ action: 'pass' })
  const source = async (name, config) => {
    const { hooks } = await plugin(command, { config })
    await hooks.before_tool_call(call(name, {}), ctx())
    const all = await recorded(record)
    return all[all.length - 1].request.data.toolSource
  }
  const servers = { mcp: { servers: { github: {}, 'my docs': {}, '1st': {}, off: { enabled: false } } } }
  assert.equal(await source('github__create_issue', servers), 'mcp')
  assert.equal(await source('my-docs__search', servers), 'mcp')
  assert.equal(await source('mcp-1st__x', servers), 'mcp')
  assert.equal(await source('off__x', servers), undefined)
  assert.equal(await source('calendar__delete', servers), undefined)
  assert.equal(await source('github__create_issue', { agents: {} }), undefined)
  assert.equal(await source('read', servers), undefined)
})

test('request: cwd follows the workspace before_agent_run reported for the session', async () => {
  const { command, record } = await fake({ action: 'pass' })
  const { hooks } = await plugin(command)
  await hooks.before_agent_run({ prompt: 'hi', messages: [] }, ctx({ workspaceDir: '/proj', trigger: 'user', inputProvenance: { kind: 'external_user' }, channel: 'telegram' }))
  await hooks.before_tool_call(call('exec', { command: 'ls' }), ctx())
  const [run, tool] = await recorded(record)
  assert.deepEqual(run.request.data, { prompt: 'hi', trigger: 'user', provenance: 'external_user', sessionKey: 'agent:main:main', channel: 'telegram' })
  assert.equal(tool.request.session.cwd, '/proj')
})

test('tool result middleware: deny replaces the result; a guard that cannot run lets it through and logs', async () => {
  const { command, record } = await fake({ action: 'deny', message: 'contains a credential' })
  const p = await plugin(command)
  assert.deepEqual(p.middlewareOpts, { runtimes: ['openclaw'] })
  const out = await p.middleware({ ...result('read', { path: 'a' }, 'SECRET'), cwd: '/run' }, { runtime: 'openclaw', agentId: 'main', sessionId: 'ses-1' })
  assert.deepEqual(out.result.content, [{ type: 'text', text: 'h-guard: contains a credential' }])
  assert.equal(JSON.stringify(out.result.details).includes('SECRET'), false)
  const [r] = await recorded(record)
  assert.equal(r.request.hook, 'tool_result')
  assert.equal(r.request.session.cwd, '/run')
  assert.deepEqual(r.request.result, { content: [{ type: 'text', text: 'SECRET' }] })
  const broken = await plugin(missing)
  assert.equal(await broken.middleware(result('read', { path: 'a' }, 'SECRET'), { runtime: 'openclaw' }), undefined)
  assert.match(broken.logs[0], /could not finish its check/)
})

test('before_agent_run: a prompt with a credential is blocked; other prompts pass', { skip: !haveGuard }, async () => {
  const { hooks } = await plugin(guard('openclaw'))
  const blocked = await hooks.before_agent_run({ prompt: KEY, messages: [] }, ctx({ trigger: 'user' }))
  assert.equal(blocked.outcome, 'block')
  assert.match(blocked.reason, /^h-guard: /)
  assert.ok(blocked.message.length > 0)
  assert.equal(await hooks.before_agent_run({ prompt: 'fix the test', messages: [] }, ctx({ trigger: 'user' })), undefined)
  assert.equal(await hooks.before_agent_run({ prompt: '  ', messages: [] }, ctx()), undefined)
})

test('before_agent_run: a guard that cannot run lets the prompt through and logs', async () => {
  const { hooks, logs } = await plugin(missing)
  assert.equal(await hooks.before_agent_run({ prompt: KEY, messages: [] }, ctx({ trigger: 'user' })), undefined)
  assert.match(logs[0], /could not finish its check/)
})

test('before_tool_call: a cancelled call stops waiting for the guard', async () => {
  const { command } = await fake({ action: 'pass' }, 'slow')
  const { hooks } = await plugin(command)
  const ac = new AbortController()
  const started = Date.now()
  setTimeout(() => ac.abort(), 200)
  const r = await hooks.before_tool_call(call('exec', { command: 'ls' }), ctx({ abortSignal: ac.signal }))
  assert.ok(Date.now() - started < 5000, 'returned only after ' + (Date.now() - started) + 'ms')
  assert.ok(r.requireApproval)
})

test('notify: deny, warn and ask go to the configured targets; nothing without targets', async () => {
  const notify = { on: ['deny', 'ask'], targets: [{ channel: 'telegram', to: '123', thread: '7' }, { channel: 'slack', to: 'channel:C1', account: 'work' }], command: ['/opt/openclaw'] }
  const deny = await fake({ action: 'deny', message: 'Blocked: deletes files' })
  const p = await plugin(deny.command, { pluginConfig: { notify } })
  await p.hooks.before_tool_call(call('exec', { command: 'rm -rf / --token=abc' }), ctx())
  await new Promise((r) => setTimeout(r, 50))
  assert.deepEqual(p.sent, [
    ['/opt/openclaw', 'message', 'send', '--channel', 'telegram', '--target', '123', '--message', 'h-guard blocked a tool call (exec) (agent main): Blocked: deletes files', '--thread-id', '7'],
    ['/opt/openclaw', 'message', 'send', '--channel', 'slack', '--target', 'channel:C1', '--message', 'h-guard blocked a tool call (exec) (agent main): Blocked: deletes files', '--account', 'work'],
  ])
  // 说明之外不带命令或参数
  assert.equal(p.sent.some((a) => a.join(' ').includes('--token=abc')), false)

  const warn = await fake({ action: 'warn', message: 'heads up' })
  const w = await plugin(warn.command, { pluginConfig: { notify } })
  assert.equal(await w.hooks.before_tool_call(call('exec', { command: 'ls' }), ctx()), undefined)
  await new Promise((r) => setTimeout(r, 50))
  assert.equal(w.sent.length, 0) // warn 不在 on 里

  const off = await plugin(deny.command, { pluginConfig: {} })
  await off.hooks.before_tool_call(call('exec', { command: 'rm -rf /' }), ctx())
  const prompt = await plugin(deny.command, { pluginConfig: { notify: { targets: [{ channel: 'telegram', to: '1' }] } } })
  await prompt.hooks.before_agent_run({ prompt: 'x', messages: [] }, ctx())
  await new Promise((r) => setTimeout(r, 50))
  assert.equal(off.sent.length, 0)
  assert.equal(prompt.sent.length, 1) // 默认 on 是 deny 与 warn
  assert.match(prompt.sent[0].join(' '), /h-guard blocked a message \(agent main\): Blocked: deletes files/)
})
