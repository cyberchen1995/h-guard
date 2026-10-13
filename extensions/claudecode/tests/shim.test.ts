import { expect, test } from 'claude-code/testing'

const CONFIG = JSON.stringify({
  commands: {
    'tool.result': ['h-guard', 'hook', 'claudecode'],
    'prompt.submit': ['h-guard', 'hook', 'claudecode'],
  },
  timeout_ms: 1000,
})

// guard 注册接入层用到的全部 API 桩；reply 为 null 时让 $.process.run 失败，模拟 h-guard 无法运行。
// calls、logs、paths 分别收集 $.process.run、$.ui.log、$.fs.read 的参数。
function guard(on, reply, calls = [], logs = [], paths = []) {
  on('fs.read', ($, e) => {
    paths.push(e)
    return { value: CONFIG }
  })
  on('session.id', () => ({ value: 'sess-1' }))
  on('session.cwd', () => ({ value: '/work' }))
  // 与真实 API 一致：session.version() 返回对象
  on('session.version', () => ({ value: { version: '2.1.296', base: '2.1.296' } }))
  on('ui.log', ($, e) => {
    logs.push(e)
    return { value: undefined }
  })
  on('process.run', ($, e) => {
    calls.push(e)
    if (reply === null) return { deny: 'cannot start' }
    return { value: { exitCode: 0, stdout: JSON.stringify({ protocol: 'h-guard.ext/v1', ...reply }), stderr: '' } }
  })
}

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

test('request: a v1 request with the version string, read from the mod root config', async ($, on) => {
  const calls = []
  const paths = []
  guard(on, { action: 'pass' }, calls, [], paths)
  on('tool.call', () => ({ result: 'ordinary' }))
  await $.tool.call({ tool: 'Bash', command: 'ls' })
  expect(calls[0].argv.slice(-2)).toEqual(['--event', 'tool.result'])
  const req = JSON.parse(calls[0].init.stdin)
  expect(req).toMatchObject({ protocol: 'h-guard.ext/v1', harness: 'claudecode', hook: 'tool.result', harness_version: '2.1.296', session: { id: 'sess-1', cwd: '/work' } })
  expect(req.result).toEqual({ result: 'ordinary' })
  expect(JSON.stringify(paths[0])).toContain('/hguard.json')
})

test('tool.check: the mod registers no tool.check hook and never runs h-guard for it', async ($, on) => {
  const calls = []
  guard(on, { action: 'deny', message: 'must not be asked' }, calls)
  on('tool.check', () => ({ decision: 'allow' }))
  expect(await $.tool.check({ tool: 'Bash', input: { command: 'git push' } })).toEqual({ decision: 'allow' })
  expect(calls.length).toBe(0)
})

test('tool.result: pass returns the result unchanged', async ($, on) => {
  guard(on, { action: 'pass' })
  on('tool.call', () => ({ result: 'ordinary' }))
  expect(await $.tool.call({ tool: 'Bash', command: 'ls' })).toEqual({ result: 'ordinary' })
})

test('tool.result: ask withholds the result', async ($, on) => {
  guard(on, { action: 'ask', message: 'held' })
  on('tool.call', () => ({ result: 'SECRET-OUTPUT' }))
  expect(await $.tool.call({ tool: 'Bash', command: 'cat x' })).toEqual({ deny: 'held' })
})

test('tool.result: warn passes the result and tells the user', async ($, on) => {
  const logs = []
  guard(on, { action: 'warn', message: 'careful' }, [], logs)
  on('tool.call', () => ({ result: 'ordinary' }))
  expect(await $.tool.call({ tool: 'Bash', command: 'ls' })).toEqual({ result: 'ordinary' })
  expect(JSON.stringify(logs)).toContain('careful')
})

test('tool.result: deny without a message still withholds the result', async ($, on) => {
  guard(on, { action: 'deny' })
  on('tool.call', () => ({ result: 'SECRET-OUTPUT' }))
  const out = await $.tool.call({ tool: 'Bash', command: 'cat x' })
  expect(out.deny).toBeTruthy()
  expect(JSON.stringify(out)).not.toContain('SECRET-OUTPUT')
})

test('tool.result: an errored result is checked like any other', async ($, on) => {
  const calls = []
  guard(on, { action: 'deny', message: 'withheld' }, calls)
  on('tool.call', () => ({ isError: true, result: 'Exit code 1\nSECRET-OUTPUT', text: 'Exit code 1\nSECRET-OUTPUT' }))
  expect(await $.tool.call({ tool: 'Bash', command: 'cat x missing' })).toEqual({ deny: 'withheld' })
  expect(calls.length).toBe(1)
})

test('tool.result: when the hook fails the user is told the result was not checked', async ($, on) => {
  const logs = []
  guard(on, { action: 'pass' }, [], logs)
  on('tool.call', () => {
    throw new Error('core failed')
  })
  try {
    await $.tool.call({ tool: 'Bash', command: 'ls' })
  } catch (err) {
    // 下层自身的错误照常传出；这里只关心用户是否得到提示
  }
  expect(JSON.stringify(logs)).toContain('could not finish')
})

test('prompt.submit: when the hook fails the user is told the prompt was not checked', async ($, on) => {
  const logs = []
  guard(on, { action: 'pass' }, [], logs)
  on('prompt.submit', () => {
    throw new Error('core failed')
  })
  try {
    await $.prompt.submit({ text: 'hello', origin: { kind: 'composer' } })
  } catch (err) {
    // 同上
  }
  expect(JSON.stringify(logs)).toContain('could not finish')
})

test('prompt.submit: ask drops the prompt', async ($, on) => {
  guard(on, { action: 'ask', message: 'held' })
  on('prompt.submit', ($, e) => ({ text: e.text }))
  expect(await $.prompt.submit({ text: 'hello', origin: { kind: 'composer' } })).toEqual({ drop: 'held' })
})

test('prompt.submit: warn sends the prompt with the message as context', async ($, on) => {
  let seen
  guard(on, { action: 'warn', message: 'note for claude' })
  on('prompt.submit', ($, e) => {
    seen = e
    return { text: e.text, context: e.context }
  })
  await $.prompt.submit({ text: 'hello', origin: { kind: 'composer' } })
  expect(seen.context).toEqual(['note for claude'])
})

test('prompt.submit: deny without a message still drops the prompt', async ($, on) => {
  guard(on, { action: 'deny' })
  on('prompt.submit', ($, e) => ({ text: e.text }))
  const out = await $.prompt.submit({ text: 'SECRET-PROMPT', origin: { kind: 'composer' } })
  expect(out.drop).toBeTruthy()
})

test('prompt.submit: a guard that cannot run sends the prompt and tells the user', async ($, on) => {
  const logs = []
  guard(on, null, [], logs)
  on('prompt.submit', ($, e) => ({ text: e.text }))
  expect(await $.prompt.submit({ text: 'hello', origin: { kind: 'composer' } })).toEqual({ text: 'hello' })
  expect(logs.length).toBe(1)
})
