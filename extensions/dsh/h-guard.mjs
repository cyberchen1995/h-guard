// h-guard 的 DeepSeek Harness（dsh）接入（Cordis 插件）。它只把工具调用、工具结果与提示词按「扩展接入协议 v1」
// 交给 h-guard 二进制，再把回复翻译成 dsh 的决定；所有判断都在 h-guard 里。
//
// 本文件由 h-guard install dsh 写到 h-guard 的配置目录，并在 $DSH_HOME/cordis.patch.yml 里以绝对路径挂载；CONFIG
// 一行由 install 填写。h-guard 直接以子进程启动，不经 dsh 的 shell 沙箱。
import { spawn } from 'node:child_process'

const PROTOCOL = 'h-guard.ext/v1'
const HARNESS = 'dsh'
const ACTIONS = ['pass', 'deny', 'ask', 'warn']
const CONFIG = null // h-guard install
const DEFAULT_TIMEOUT_MS = 20000
const FAILED = 'h-guard could not finish its check'
const NO_REASON = 'h-guard stopped this without giving a reason'
const UNCHECKED = 'h-guard could not run its check, so this tool call needs your confirmation'

export const name = 'h-guard'

export function apply(ctx) {
  // 动作：工具执行之前检查。deny 阻止工具调用，模型读到说明；ask 交给 dsh 的确认服务（没有能回答的界面时 dsh
  // 自己拒绝）；h-guard 无法运行时按 ask 处理。pass 与 warn 交给后面的监听者，h-guard 从不放行
  ctx.on('tools/pre-execute', async (exec, next) => {
    const reply = await callGuard('tools/pre-execute', exec.agent, {
      data: { name: exec.name, callId: exec.callId, arguments: exec.arguments, nested: exec.parent !== undefined },
    })
    if (reply.action === 'deny') return { kind: 'deny', reason: textOf(reply) }
    if (reply.action === 'ask' || reply.action === 'error') {
      const text = reply.action === 'error' ? UNCHECKED + ' (' + reply.message + ')' : textOf(reply)
      return { kind: 'ask', reason: text, displayReason: { en: text } }
    }
    if (reply.action === 'warn') log(ctx, messageOf(reply))
    return next()
  })

  // 工具结果：交给模型之前检查；deny 用说明代替结果（结果标为出错）。接入层故障放行结果并记一行日志
  ctx.on('tools/post-execute', async (exec, result, next) => {
    try {
      const reply = await callGuard('tools/post-execute', exec.agent, {
        data: { name: exec.name, callId: exec.callId, arguments: exec.arguments, nested: exec.parent !== undefined },
        result: { isError: !!(result && result.isError), content: textBlocks(result && result.content) },
      })
      if (reply.action === 'deny' || reply.action === 'ask') return { kind: 'block', feedback: [{ type: 'text', text: textOf(reply) }] }
      if (reply.action === 'warn') log(ctx, messageOf(reply))
      if (reply.action === 'error') log(ctx, reply.message)
    } catch (err) {
      log(ctx, FAILED)
    }
    return next()
  })

  // 提示词：每一步把新消息交给模型之前检查（没有新消息的步骤跳过）；deny 时丢弃这一步。接入层故障放行并记一行日志
  ctx.on('agent/pre-step', async (step, next) => {
    const messages = step && Array.isArray(step.messages) ? step.messages : []
    if (messages.length === 0) return next()
    try {
      const header = headerOf(step.agent)
      const reply = await callGuard('agent/pre-step', step.agent, {
        data: {
          messages: messages.map((m) => ({ source: { kind: m && m.source ? m.source.kind : undefined }, content: textBlocks(m && m.content) })),
          session: { origin: header.origin, delegationDepth: header.delegationDepth },
        },
      })
      if (reply.action === 'deny' || reply.action === 'ask') {
        log(ctx, messageOf(reply))
        return { kind: 'reject' }
      }
      if (reply.action === 'warn') log(ctx, messageOf(reply))
      if (reply.action === 'error') log(ctx, reply.message)
    } catch (err) {
      log(ctx, FAILED)
    }
    return next()
  })
}

// log 把提示写进 dsh 的日志：dsh 没有向用户显示提示的接口
function log(ctx, text) {
  try {
    ctx.logger.warn('h-guard: ' + text)
  } catch (err) {
    // 无法记录时只能放弃
  }
}

function headerOf(agent) {
  try {
    const h = agent && agent.session && agent.session.header
    if (h) return h
  } catch (err) {
    // 没有会话头时按普通会话
  }
  return {}
}

// textBlocks 只转交文本块：图片等内容不参与检查；字符串内容当作一个文本块
function textBlocks(content) {
  if (typeof content === 'string') return [{ type: 'text', text: content }]
  if (!Array.isArray(content)) return []
  return content.filter((b) => b && b.type === 'text').map((b) => ({ type: 'text', text: b.text }))
}

// callGuard 按协议组装请求、运行 h-guard、校验回复。任何失败都返回 { action: 'error' }，由各事件按固定规则处理
async function callGuard(hook, agent, extra) {
  try {
    const config = CONFIG || { command: ['h-guard', 'hook', HARNESS], timeout_ms: DEFAULT_TIMEOUT_MS }
    const header = headerOf(agent)
    const request = {
      protocol: PROTOCOL,
      harness: HARNESS,
      hook,
      session: { id: header.id || HARNESS + '-' + process.pid, cwd: header.cwd || process.cwd() },
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
