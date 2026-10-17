// h-guard 的 pi / oh-my-pi（omp）接入（扩展）。它只把工具调用、工具结果与提示词按「扩展接入协议 v1」交给
// h-guard 二进制，再把回复翻译成扩展的返回值与界面上的确认、提示；所有判断都在 h-guard 里。
//
// 本文件由 h-guard install pi（或 omp）写入扩展目录，HARNESS 与 CONFIG 两行由 install 填写。pi 与 omp 的事件、
// 返回值相同，只有 input 的「已处理」写法不同（pi：action: 'handled'，omp：handled: true），两种都返回。
import { spawn } from 'node:child_process'

const PROTOCOL = 'h-guard.ext/v1'
const HARNESS = 'pi' // h-guard install
const ACTIONS = ['pass', 'deny', 'ask', 'warn']
const CONFIG = null // h-guard install
const DEFAULT_TIMEOUT_MS = 20000
const FAILED = 'h-guard could not finish its check'
const NO_REASON = 'h-guard stopped this without giving a reason'
const UNCHECKED = 'h-guard could not run its check, so this tool call needs your confirmation'

export default function (pi) {
  // 动作：工具执行之前检查。deny 阻止工具调用，模型读到说明；ask 请求用户确认，没有界面（-p、json 模式）时拒绝；
  // h-guard 无法运行时按 ask 处理
  pi.on('tool_call', async (event, ctx) => {
    let reply = await callGuard('tool_call', ctx, {
      data: { toolCallId: event.toolCallId, toolName: event.toolName, input: event.input },
    })
    if (reply.action === 'error') reply = { action: 'ask', message: UNCHECKED + ' (' + reply.message + ')' }
    if (reply.action === 'warn') notify(ctx, 'warning', messageOf(reply))
    if (reply.action === 'deny') return { block: true, reason: textOf(reply) }
    if (reply.action === 'ask') {
      const text = textOf(reply)
      if (!ctx.hasUI) return { block: true, reason: text }
      let ok = false
      try {
        ok = await ctx.ui.confirm('h-guard', text + '\n\nAllow this ' + event.toolName + ' call?')
      } catch (err) {
        ok = false
      }
      if (!ok) return { block: true, reason: text + ' The user did not confirm it.' }
    }
    return undefined
  })

  // 工具结果：交给模型之前检查；deny 用说明代替结果。接入层故障放行结果并提示用户
  pi.on('tool_result', async (event, ctx) => {
    try {
      const reply = await callGuard('tool_result', ctx, {
        data: { toolCallId: event.toolCallId, toolName: event.toolName, input: event.input, isError: !!event.isError },
        result: { content: textBlocks(event.content) },
      })
      if (reply.action === 'deny' || reply.action === 'ask') return { content: [{ type: 'text', text: textOf(reply) }] }
      if (reply.action === 'warn') notify(ctx, 'warning', messageOf(reply))
      if (reply.action === 'error') notify(ctx, 'warning', reply.message)
    } catch (err) {
      notify(ctx, 'warning', FAILED)
    }
    return undefined
  })

  // 提示词：发送之前检查；deny 时不发送，并告诉用户原因。接入层故障放行并提示用户
  pi.on('input', async (event, ctx) => {
    const verdict = await checkPrompt(ctx, event.text, event.source)
    checked.set(event.text, verdict)
    if (verdict !== null) return { action: 'handled', handled: true }
    return undefined
  })

  // omp 只在交互界面与 RPC 模式里触发 input，-p 与 SDK 的提示词不经过它。每次请求模型之前的 context 事件补上：
  // 没检查过的用户消息照样交给 h-guard，被拒的消息换成说明再交给模型（只改这一次请求，不改会话记录，所以每次都要换）
  if (HARNESS === 'omp') {
    pi.on('context', async (event, ctx) => {
      const messages = Array.isArray(event.messages) ? event.messages : []
      let changed = false
      const out = []
      for (const m of messages) {
        const text = m && m.role === 'user' ? userText(m.content) : ''
        if (text === '') {
          out.push(m)
          continue
        }
        if (!checked.has(text)) checked.set(text, await checkPrompt(ctx, text, 'context'))
        const verdict = checked.get(text)
        if (verdict === null) {
          out.push(m)
          continue
        }
        out.push({ ...m, content: [{ type: 'text', text: verdict }] })
        changed = true
      }
      return changed ? { messages: out } : undefined
    })
  }
}

// checked 记下检查过的提示词（文本 → null 放行，或代替它的说明），同一段文本不重复检查
const checked = new Map()

// checkPrompt 检查一段提示词：deny 时提示用户并返回写给模型的说明，其余返回 null。接入层故障放行并提示用户
async function checkPrompt(ctx, text, source) {
  try {
    const reply = await callGuard('input', ctx, { data: { text, source } })
    if (reply.action === 'deny' || reply.action === 'ask') {
      notify(ctx, 'error', messageOf(reply))
      return textOf(reply) + ' The prompt was withheld.'
    }
    if (reply.action === 'warn') notify(ctx, 'warning', messageOf(reply))
    if (reply.action === 'error') notify(ctx, 'warning', reply.message)
  } catch (err) {
    notify(ctx, 'warning', FAILED)
  }
  return null
}

// userText 返回用户消息的文本：字符串原样，内容块取各文本块以换行连接
function userText(content) {
  if (typeof content === 'string') return content
  if (!Array.isArray(content)) return ''
  return content
    .filter((b) => b && b.type === 'text' && typeof b.text === 'string')
    .map((b) => b.text)
    .join('\n')
}

// notify 尽力提示用户：有界面时用 ctx.ui.notify，没有时写到 stderr（json 模式的 stdout 是事件流）
function notify(ctx, level, text) {
  try {
    if (ctx.hasUI) {
      ctx.ui.notify('h-guard: ' + text, level)
      return
    }
  } catch (err) {
    // 退回 stderr
  }
  try {
    process.stderr.write('h-guard: ' + text + '\n')
  } catch (err) {
    // 无法提示时只能放弃
  }
}

// textBlocks 只转交文本块：图片等内容不参与检查
function textBlocks(content) {
  if (!Array.isArray(content)) return []
  return content.filter((b) => b && b.type === 'text').map((b) => ({ type: 'text', text: b.text }))
}

function sessionOf(ctx) {
  try {
    const id = ctx.sessionManager.getSessionId()
    if (typeof id === 'string' && id !== '') return id
  } catch (err) {
    // 没有会话管理器时用进程号
  }
  return HARNESS + '-' + process.pid
}

// callGuard 按协议组装请求、运行 h-guard、校验回复。任何失败都返回 { action: 'error' }，由各事件按固定规则处理
async function callGuard(hook, ctx, extra) {
  try {
    const config = CONFIG || { command: ['h-guard', 'hook', HARNESS], timeout_ms: DEFAULT_TIMEOUT_MS }
    const request = {
      protocol: PROTOCOL,
      harness: HARNESS,
      hook,
      session: { id: sessionOf(ctx), cwd: ctx.cwd || process.cwd() },
      ...extra,
    }
    const out = await run([...config.command, '--event', hook], JSON.stringify(request), config.timeout_ms || DEFAULT_TIMEOUT_MS)
    if (out.code !== 0) return failure('exit code ' + out.code)
    const reply = JSON.parse(out.stdout)
    if (!reply || reply.protocol !== PROTOCOL || !ACTIONS.includes(reply.action)) return failure('unrecognized reply')
    return reply
  } catch (err) {
    return failure(err)
  }
}

// run 不经 shell 启动 h-guard，把请求写到 stdin；超时、启动失败都返回非零的 code
function run(argv, input, timeoutMs) {
  return new Promise((resolve) => {
    let stdout = ''
    let done = false
    const finish = (code) => {
      if (done) return
      done = true
      clearTimeout(timer)
      resolve({ code, stdout })
    }
    const child = spawn(argv[0], argv.slice(1), { stdio: ['pipe', 'pipe', 'ignore'], windowsHide: true })
    const timer = setTimeout(() => {
      child.kill()
      finish(-1)
    }, timeoutMs)
    child.on('error', () => finish(-1))
    child.on('close', (code) => finish(code === null ? -1 : code))
    child.stdout.setEncoding('utf8')
    child.stdout.on('data', (d) => {
      stdout += d
    })
    child.stdin.on('error', () => {})
    child.stdin.end(input)
  })
}

function failure(detail) {
  const text = detail && detail.message ? detail.message : String(detail)
  return { action: 'error', message: FAILED + ': ' + text }
}

// messageOf 返回回复的说明；说明缺失时用固定文本，不能因为缺说明而让 deny 失效
function messageOf(reply) {
  return typeof reply.message === 'string' && reply.message.trim() !== '' ? reply.message : NO_REASON
}

// textOf 是写给模型的说明：前缀表明来源，后接原因与前进路径
function textOf(reply) {
  const msg = messageOf(reply)
  let s = msg.startsWith('h-guard') ? msg : 'h-guard: ' + msg
  if (typeof reply.hint === 'string' && reply.hint !== '') s += ' ' + reply.hint
  return s
}
