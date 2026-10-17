// h-guard 的 opencode 接入（插件，opencode 1.x）。它只把工具调用、工具结果与提示词按「扩展接入协议 v1」交给
// h-guard 二进制，再把回复翻译成 opencode 的行为；所有判断都在 h-guard 里。
//
// 本文件由 h-guard install opencode 写入 opencode 的插件目录，CONFIG 一行由 install 填写。opencode 要求插件文件的
// 每个导出都是插件函数，所以这里只导出 HGuard。
import { spawn } from 'node:child_process'

const PROTOCOL = 'h-guard.ext/v1'
const HARNESS = 'opencode'
const ACTIONS = ['pass', 'deny', 'ask', 'warn']
const CONFIG = null // h-guard install
const DEFAULT_TIMEOUT_MS = 20000
const FAILED = 'h-guard could not finish its check'
const NO_REASON = 'h-guard stopped this without giving a reason'
const UNCHECKED = 'h-guard could not run its check, so this tool call was blocked; ask the user to run h-guard status'

export const HGuard = async ({ client, directory }) => {
  // toast 只在 TUI 里可见；显示失败不影响结论
  const toast = async (variant, message) => {
    try {
      await client.tui.showToast({ body: { title: 'h-guard', message, variant } })
    } catch (err) {
      // 无法提示时只能放弃
    }
  }

  return {
    // 动作：工具执行之前检查；deny（及 opencode 做不到的 ask）抛出错误，工具不执行，模型读到说明。
    // h-guard 无法运行时同样阻止：动作不能因为检查失败而放行
    'tool.execute.before': async (input, output) => {
      const reply = await callGuard('tool.execute.before', input.sessionID, directory, {
        data: { tool: input.tool, sessionID: input.sessionID, callID: input.callID, args: output.args },
      })
      if (reply.action === 'error') throw new Error(UNCHECKED + ' (' + reply.message + ')')
      if (reply.action === 'deny' || reply.action === 'ask') throw new Error(textOf(reply))
      if (reply.action === 'warn') await toast('warning', messageOf(reply))
    },

    // 工具结果：执行之后、交给模型之前检查；deny 用说明代替结果。接入层故障放行结果并提示用户
    'tool.execute.after': async (input, output) => {
      try {
        const reply = await callGuard('tool.execute.after', input.sessionID, directory, {
          data: { tool: input.tool, sessionID: input.sessionID, callID: input.callID, args: input.args },
          result: {
            output: typeof output.output === 'string' ? output.output : undefined,
            content: Array.isArray(output.content) ? textBlocks(output.content) : undefined,
          },
        })
        if (reply.action === 'deny' || reply.action === 'ask') return replace(output, textOf(reply))
        if (reply.action === 'warn') await toast('warning', messageOf(reply))
        if (reply.action === 'error') await toast('warning', reply.message)
      } catch (err) {
        await toast('warning', FAILED)
      }
    },

    // 提示词：保存与发送之前检查；deny 抛出错误，消息不保存、不发送。接入层故障放行并提示用户
    'chat.message': async (input, output) => {
      let reply
      try {
        const parts = (output.parts || []).map((p) => ({
          type: p.type,
          text: p.type === 'text' ? p.text : undefined,
          synthetic: !!p.synthetic,
        }))
        reply = await callGuard('chat.message', input.sessionID, directory, {
          data: { sessionID: input.sessionID, agent: input.agent, parts, parentID: await parentOf(client, input.sessionID) },
        })
      } catch (err) {
        reply = failure(err)
      }
      if (reply.action === 'deny' || reply.action === 'ask') {
        await toast('error', messageOf(reply))
        throw new Error(textOf(reply))
      }
      if (reply.action === 'warn') await toast('warning', messageOf(reply))
      if (reply.action === 'error') await toast('warning', reply.message)
    },
  }
}

// parentOf 返回会话的父会话（子 agent 的会话不为空）。查询失败时返回 '?'：看不出是不是子 agent 的会话，按自动消息处理，
// 不能让父 agent 写的任务被当作用户本人的指令
async function parentOf(client, id) {
  try {
    const res = await client.session.get({ path: { id } })
    const s = res && res.data ? res.data : res
    if (!s || typeof s !== 'object') return '?'
    return typeof s.parentID === 'string' ? s.parentID : ''
  } catch (err) {
    return '?'
  }
}

// replace 让说明代替工具结果：内置工具的 output，MCP 工具的 content；附带的 output 与附件一并换掉
function replace(output, text) {
  output.output = text
  if (Array.isArray(output.content)) output.content = [{ type: 'text', text }]
  if (Array.isArray(output.attachments)) output.attachments = []
  if (output.metadata && typeof output.metadata.output === 'string') output.metadata.output = text
}

// textBlocks 只转交文本：文本块，以及 MCP 结果里嵌入的资源的文本（harness 同样把它交给模型）；图片等内容不参与检查
function textBlocks(content) {
  if (!Array.isArray(content)) return []
  const out = []
  for (const b of content) {
    if (b && b.type === 'text') out.push({ type: 'text', text: b.text })
    else if (b && b.type === 'resource' && b.resource && typeof b.resource.text === 'string') out.push({ type: 'text', text: b.resource.text })
  }
  return out
}

// callGuard 按协议组装请求、运行 h-guard、校验回复。任何失败都返回 { action: 'error' }，由各 hook 按固定规则处理
async function callGuard(hook, sessionID, cwd, extra) {
  try {
    const config = CONFIG || { command: ['h-guard', 'hook', HARNESS], timeout_ms: DEFAULT_TIMEOUT_MS }
    const request = {
      protocol: PROTOCOL,
      harness: HARNESS,
      hook,
      session: { id: sessionID || 'opencode-' + process.pid, cwd: cwd || process.cwd() },
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
