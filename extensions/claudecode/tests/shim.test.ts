import { expect, test } from 'claude-code/testing'

const CONFIG = JSON.stringify({
  commands: {
    'tool.check': ['h-guard', 'hook', 'claudecode'],
    'tool.result': ['h-guard', 'hook', 'claudecode'],
    'prompt.submit': ['h-guard', 'hook', 'claudecode'],
  },
  timeout_ms: 1000,
})

// guard 注册接入层用到的全部 API 桩；reply 为 null 时让 $.process.run 失败，模拟 h-guard 无法运行
function guard(on, reply, calls = []) {
  on('fs.read', () => ({ value: CONFIG }))
  on('session.id', () => ({ value: 'sess-1' }))
  on('session.cwd', () => ({ value: '/work' }))
  on('session.version', () => ({ value: '2.1.296' }))
  on('ui.log', () => ({ value: undefined }))
  on('process.run', ($, e) => {
    calls.push(e)
    if (reply === null) return { deny: 'cannot start' }
    return { value: { exitCode: 0, stdout: JSON.stringify({ protocol: 'h-guard.ext/v1', ...reply }), stderr: '' } }
  })
}

test('tool.check: pass keeps Claude Code decision and sends a v1 request', async ($, on) => {
  const calls = []
  guard(on, { action: 'pass' }, calls)
  on('tool.check', () => ({ decision: 'allow' }))
  const out = await $.tool.check({ tool: 'Bash', input: { command: 'ls' } })
  expect(out).toMatchObject({ decision: 'allow' })
  expect(calls[0].argv.slice(-2)).toEqual(['--event', 'tool.check'])
  const req = JSON.parse(calls[0].init.stdin)
  expect(req).toMatchObject({ protocol: 'h-guard.ext/v1', harness: 'claudecode', hook: 'tool.check', decided: 'allow', session: { id: 'sess-1', cwd: '/work' } })
  expect(req.data.tool).toBe('Bash')
})

test('tool.check: deny refuses with the h-guard message', async ($, on) => {
  guard(on, { action: 'deny', message: 'blocked by h-guard' })
  on('tool.check', () => ({ decision: 'allow' }))
  expect(await $.tool.check({ tool: 'Bash', input: { command: 'rm -rf /' } })).toEqual({ decision: 'deny', reason: 'blocked by h-guard' })
})

test('tool.check: ask never loosens an existing deny', async ($, on) => {
  guard(on, { action: 'ask', message: 'confirm' })
  on('tool.check', () => ({ decision: 'deny', reason: 'rule' }))
  expect(await $.tool.check({ tool: 'Bash', input: { command: 'git push' } })).toMatchObject({ decision: 'deny' })
})

test('tool.check: ask turns allow into ask', async ($, on) => {
  guard(on, { action: 'ask', message: 'confirm' })
  on('tool.check', () => ({ decision: 'allow' }))
  expect(await $.tool.check({ tool: 'Bash', input: { command: 'git push' } })).toEqual({ decision: 'ask', reason: 'confirm' })
})

test('tool.check: a guard that cannot run asks instead of passing', async ($, on) => {
  guard(on, null)
  on('tool.check', () => ({ decision: 'allow' }))
  expect(await $.tool.check({ tool: 'Bash', input: { command: 'ls' } })).toMatchObject({ decision: 'ask' })
})

test('tool.result: deny withholds the result', async ($, on) => {
  guard(on, { action: 'deny', message: 'output withheld by h-guard' })
  on('tool.call', () => ({ result: 'SECRET-OUTPUT' }))
  expect(await $.tool.call({ tool: 'Bash', command: 'cat token.txt' })).toEqual({ deny: 'output withheld by h-guard' })
})

test('tool.result: a guard that cannot run lets the result through', async ($, on) => {
  guard(on, null)
  on('tool.call', () => ({ result: 'ordinary' }))
  expect(await $.tool.call({ tool: 'Bash', command: 'ls' })).toEqual({ result: 'ordinary' })
})

test('prompt.submit: deny drops the prompt', async ($, on) => {
  guard(on, { action: 'deny', message: 'contains a credential' })
  on('prompt.submit', ($, e) => ({ text: e.text }))
  expect(await $.prompt.submit({ text: 'key=AKIA...', origin: { kind: 'composer' } })).toEqual({ drop: 'contains a credential' })
})

test('prompt.submit: pass sends the prompt unchanged', async ($, on) => {
  guard(on, { action: 'pass' })
  on('prompt.submit', ($, e) => ({ text: e.text }))
  expect(await $.prompt.submit({ text: 'hello', origin: { kind: 'composer' } })).toEqual({ text: 'hello' })
})
