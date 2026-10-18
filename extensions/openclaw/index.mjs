// h-guard 的 OpenClaw 接入（原生插件）。它只把工具调用、工具结果与提示词按「扩展接入协议 v1」交给 h-guard 二进制，
// 再把回复翻译成 OpenClaw 的决定；所有判断都在 h-guard 里。
//
// 本目录由 h-guard install openclaw 写到 h-guard 的配置目录，并加进 openclaw.json 的 plugins.load.paths；CONFIG
// 一行由 install 填写。插件在 Gateway 进程里运行，经 OpenClaw 的 runtime.system.runCommandWithTimeout 启动 h-guard
// （不经 shell），不依赖 npm 包，也不导入 node:child_process。
//
// 被拦下的调用另外可以经频道通知（plugins.entries.h-guard.config.notify，默认关闭）：插件运行
// openclaw message send，不等它结束，也不影响决定。
import { basename } from 'node:path'

const PROTOCOL = 'h-guard.ext/v1'
const HARNESS = 'openclaw'
const ACTIONS = ['pass', 'deny', 'ask', 'warn']
const CONFIG = null // h-guard install
const DEFAULT_TIMEOUT_MS = 20000
const FAILED = 'h-guard could not finish its check'
const NO_REASON = 'h-guard stopped this without giving a reason'
const UNCHECKED = 'h-guard could not run its check, so this tool call needs your confirmation'
const TITLE = 'h-guard: confirm this tool call'
const MAX_DESCRIPTION = 512 // Gateway 截断审批说明的长度
const NOTIFY_TIMEOUT_MS = 60000
const NOTIFY_MAX_PENDING = 20

export default {
  id: 'h-guard',
  name: 'h-guard',
  description: 'Checks tool calls, tool output and prompts with h-guard.',
  register(api) {
    const workspaces = new Map() // sessionKey → before_agent_run 报告的工作区
    const notify = notifier(api)

    // 动作：工具执行之前检查。deny 阻止工具调用，模型读到说明；ask 交给 OpenClaw 的插件审批（没有能回答的界面时
    // OpenClaw 自己拦下）；h-guard 无法运行时按 ask 处理。pass 与 warn 不返回决定，h-guard 从不放行
    api.on('before_tool_call', async (event, ctx = {}) => {
      const reply = await callGuard(api, 'before_tool_call', sessionOf(api, workspaces, ctx), {
        data: {
          toolName: event.toolName,
          toolCallId: event.toolCallId || ctx.toolCallId,
          params: event.params,
          toolKind: event.toolKind,
          toolInputKind: event.toolInputKind,
          derivedPaths: event.derivedPaths,
          platform: process.platform,
          execHost: event.toolName === 'exec' && event.toolKind !== 'code_mode_exec' ? await execHost(api, event, ctx) : undefined,
          toolSource: mcpTool(api, event.toolName) ? 'mcp' : undefined,
        },
      }, ctx.abortSignal)
      if (reply.action === 'deny') {
        notify('deny', 'blocked a tool call (' + event.toolName + ')', ctx, reply)
        return { block: true, blockReason: textOf(reply) }
      }
      if (reply.action === 'ask' || reply.action === 'error') {
        const reason = reply.action === 'error' ? UNCHECKED + ' (' + reply.message + ')' : textOf(reply)
        if (reply.action === 'error') log(api, reply.message)
        if (reply.action === 'ask') notify('ask', 'asks for approval of a tool call (' + event.toolName + ')', ctx, reply)
        return {
          requireApproval: {
            title: TITLE,
            description: clip(reason + describe(event, reply)),
            severity: 'warning',
            // OpenClaw 不替插件记住 allow-always，只给一次性的放行
            allowedDecisions: ['allow-once', 'deny'],
          },
        }
      }
      if (reply.action === 'warn') {
        log(api, messageOf(reply))
        notify('warn', 'warns about a tool call (' + event.toolName + ')', ctx, reply)
      }
      return undefined
    })

    // 工具结果：交给模型之前检查；deny 用说明代替结果。接入层故障放行结果并记一行日志
    api.registerAgentToolResultMiddleware(async (event, ctx = {}) => {
      try {
        const session = sessionOf(api, workspaces, ctx)
        if (typeof event.cwd === 'string' && event.cwd !== '') session.cwd = event.cwd
        const reply = await callGuard(api, 'tool_result', session, {
          data: { toolName: event.toolName, toolCallId: event.toolCallId, args: event.args, isError: !!event.isError, platform: process.platform },
          result: { content: textBlocks(event.result && event.result.content) },
        })
        if (reply.action === 'deny' || reply.action === 'ask') {
          notify('deny', 'withheld the output of ' + event.toolName, ctx, reply)
          return { result: { content: [{ type: 'text', text: textOf(reply) }], details: { status: 'error', hguard: 'withheld' } } }
        }
        if (reply.action === 'warn') {
          log(api, messageOf(reply))
          notify('warn', 'warns about the output of ' + event.toolName, ctx, reply)
        }
        if (reply.action === 'error') log(api, reply.message)
      } catch (err) {
        log(api, FAILED)
      }
      return undefined
    }, { runtimes: ['openclaw'] })

    // 提示词：模型收到这一轮的输入之前检查；deny 时拦下这一轮（OpenClaw 在会话里用说明代替原来的消息）。
    // 接入层故障放行并记一行日志。需要 plugins.entries.h-guard.hooks.allowConversationAccess（install 写入）
    api.on('before_agent_run', async (event, ctx = {}) => {
      if (ctx.sessionKey && typeof ctx.workspaceDir === 'string' && ctx.workspaceDir !== '') {
        workspaces.set(ctx.sessionKey, ctx.workspaceDir)
        if (workspaces.size > 1000) workspaces.delete(workspaces.keys().next().value)
      }
      if (!event || typeof event.prompt !== 'string' || event.prompt.trim() === '') return undefined
      try {
        const reply = await callGuard(api, 'before_agent_run', sessionOf(api, workspaces, ctx), {
          data: {
            prompt: event.prompt,
            trigger: ctx.trigger,
            provenance: ctx.inputProvenance ? ctx.inputProvenance.kind : undefined,
            sessionKey: ctx.sessionKey,
            channel: ctx.channel || event.channelId,
          },
        })
        if (reply.action === 'deny' || reply.action === 'ask') {
          log(api, messageOf(reply))
          notify('deny', 'blocked a message', ctx, reply)
          return { outcome: 'block', reason: textOf(reply), message: messageOf(reply) }
        }
        if (reply.action === 'warn') {
          log(api, messageOf(reply))
          notify('warn', 'warns about a message', ctx, reply)
        }
        if (reply.action === 'error') log(api, reply.message)
      } catch (err) {
        log(api, FAILED)
      }
      return undefined
    })
  },
}

// log 把提示写进 Gateway 的日志：插件没有向用户显示提示的接口
function log(api, text) {
  try {
    api.logger.warn('h-guard: ' + text)
  } catch (err) {
    // 无法记录时只能放弃
  }
}

// sessionOf 返回请求的 session：id 是 OpenClaw 的会话 id（/new、/reset 时换新），工作目录依次取 before_agent_run 报告的
// 工作区、agent 配置的工作区、Gateway 的当前目录
function sessionOf(api, workspaces, ctx) {
  const c = ctx || {}
  let cwd = c.sessionKey ? workspaces.get(c.sessionKey) : undefined
  if (!cwd && c.agentId) {
    try {
      cwd = api.runtime.agent.resolveAgentWorkspaceDir(api.runtime.config.current(), c.agentId)
    } catch (err) {
      cwd = undefined
    }
  }
  return { id: c.sessionId || c.sessionKey || HARNESS + '-' + process.pid, cwd: typeof cwd === 'string' && cwd !== '' ? cwd : process.cwd() }
}

// describe 是审批说明里的调用本身。审批说明会出现在聊天里，所以不放原始参数：用 h-guard 回复里的摘要（subject，命令与
// 文件，认出的凭据已遮蔽）；没有摘要时（h-guard 无法运行）只写工具名
function describe(event, reply) {
  if (reply && typeof reply.subject === 'string' && reply.subject.trim() !== '') return '\n' + reply.subject
  return '\n' + event.toolName
}

// execHost 返回 exec 实际运行的位置：调用自己给了 node 或 host（auto 以外）时就是它；否则依次是会话的 /exec 设置、
// agent 的 tools.exec.host、全局的 tools.exec.host，都没有时是 auto。读这些设置出错时是 unknown，h-guard 请求确认
// mcpTool 报告工具是不是配置里的 MCP 服务器提供的：OpenClaw 把 MCP 工具命名为 <服务器的安全名>__<工具>
// （src/agents/agent-bundle-mcp-names.ts：非 [A-Za-z0-9_-] 的字符换成 -，不以字母开头时加 mcp- 前缀，截到 30 个字符，
// 按声明顺序给重名的加 -2、-3）。只认 mcp.servers 里的服务器；插件随包带的 MCP 服务器与读不到配置时都不算，按不认识
// 的工具处理（请求确认）。
function mcpTool(api, name) {
  if (typeof name !== 'string' || !name.includes('__')) return false
  try {
    const servers = (api.runtime.config.current() || {}).mcp?.servers
    if (!servers || typeof servers !== 'object') return false
    const used = new Set()
    for (const server of Object.keys(servers)) {
      let base = server.trim().replace(/[^A-Za-z0-9_-]/g, '-') || 'mcp'
      if (!/^[A-Za-z]/.test(base)) base = 'mcp-' + base
      base = base.slice(0, 30)
      let safe = base
      for (let n = 2; used.has(safe.toLowerCase()); n++) safe = base.slice(0, Math.max(1, 30 - String(n).length - 1)) + '-' + n
      used.add(safe.toLowerCase())
      if (servers[server] && servers[server].enabled !== false && name.startsWith(safe + '__')) return true
    }
  } catch (err) {
    return false
  }
  return false
}

async function execHost(api, event, ctx) {
  const p = event && event.params && typeof event.params === 'object' ? event.params : {}
  if (typeof p.node === 'string' && p.node.trim() !== '') return 'node'
  if (typeof p.host === 'string' && p.host !== '' && p.host !== 'auto') return p.host
  try {
    if (ctx.sessionKey) {
      // 2026.10.4 只有同步的 getSessionEntry；之后的版本另有 getSessionEntryAsync。两个都没有时读不到，按 unknown 处理
      const store = api.runtime.agent.session
      const params = { agentId: ctx.agentId, sessionKey: ctx.sessionKey }
      const entry = typeof store.getSessionEntryAsync === 'function' ? await store.getSessionEntryAsync(params) : store.getSessionEntry(params)
      if (entry && typeof entry.execNode === 'string' && entry.execNode !== '') return 'node'
      if (entry && typeof entry.execHost === 'string' && entry.execHost !== '' && entry.execHost !== 'auto') return entry.execHost
    }
    const cfg = api.runtime.config.current() || {}
    const agent = agentEntry(cfg, ctx.agentId) || {}
    for (const exec of [agent.tools && agent.tools.exec, cfg.tools && cfg.tools.exec]) {
      if (exec && typeof exec.host === 'string' && exec.host !== '' && exec.host !== 'auto') return exec.host
    }
    return 'auto'
  } catch (err) {
    return 'unknown'
  }
}

// agentEntry 按 id（不分大小写）找 agent 的配置：agents.entries 是以 id 为键的对象，旧写法 agents.list 是带 id 的列表
function agentEntry(cfg, id) {
  if (typeof id !== 'string' || id === '' || !cfg.agents) return undefined
  const want = id.toLowerCase()
  const { entries, list } = cfg.agents
  if (entries && typeof entries === 'object') {
    for (const [k, v] of Object.entries(entries)) if (k.toLowerCase() === want) return v
  }
  if (Array.isArray(list)) return list.find((a) => a && typeof a.id === 'string' && a.id.toLowerCase() === want)
  return undefined
}

function clip(s) {
  return s.length > MAX_DESCRIPTION ? s.slice(0, MAX_DESCRIPTION - 1) + '…' : s
}

// textBlocks 只转交文本块；图片等内容不参与检查
function textBlocks(content) {
  if (typeof content === 'string') return [{ type: 'text', text: content }]
  if (!Array.isArray(content)) return []
  const out = []
  for (const b of content) {
    if (b && b.type === 'text' && typeof b.text === 'string') out.push({ type: 'text', text: b.text })
  }
  return out
}

// callGuard 按协议组装请求、运行 h-guard、校验回复。任何失败都返回 { action: 'error' }，由各事件按固定规则处理
async function callGuard(api, hook, session, extra, signal) {
  try {
    const config = CONFIG || { command: ['h-guard', 'hook', HARNESS], timeout_ms: DEFAULT_TIMEOUT_MS }
    const request = { protocol: PROTOCOL, harness: HARNESS, hook, session, ...extra }
    const version = runtimeVersion(api)
    if (version) request.harness_version = version
    const timeoutMs = config.timeout_ms || DEFAULT_TIMEOUT_MS
    const out = await run(api, [...config.command, '--event', hook], JSON.stringify(request), timeoutMs, signal)
    if (out.code !== 0) return failure('exit code ' + out.code)
    const reply = JSON.parse(out.stdout)
    if (!reply || reply.protocol !== PROTOCOL || !ACTIONS.includes(reply.action)) return failure('unrecognized reply')
    return reply
  } catch (err) {
    return failure(err)
  }
}

function runtimeVersion(api) {
  try {
    return typeof api.runtime.version === 'string' ? api.runtime.version : ''
  } catch (err) {
    return ''
  }
}

// run 经 OpenClaw 的 runCommandWithTimeout 启动命令（不经 shell），把 input 写到 stdin；超时、取消、启动失败都返回非零的 code
async function run(api, argv, input, timeoutMs, signal) {
  if (signal && signal.aborted) return { code: -1, stdout: '' }
  const runCommand = api && api.runtime && api.runtime.system ? api.runtime.system.runCommandWithTimeout : undefined
  if (typeof runCommand !== 'function') throw new Error('OpenClaw does not provide runtime.system.runCommandWithTimeout')
  const opts = { timeoutMs, input }
  if (signal) opts.signal = signal
  let res
  try {
    res = await runCommand(argv, opts)
  } catch (err) {
    return { code: -1, stdout: '' }
  }
  const code = res && typeof res.code === 'number' && (!res.termination || res.termination === 'exit') ? res.code : -1
  return { code, stdout: res && typeof res.stdout === 'string' ? res.stdout : '' }
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

// notifier 读 plugins.entries.h-guard.config.notify，返回 notify(kind, what, ctx, reply)：kind（deny、warn、ask）在
// notify.on 里（默认 deny 与 warn）时，向每个目标运行 openclaw message send。消息只有 h-guard 的说明（已遮蔽认出的凭据）、
// 工具名与 agent，不带命令、参数或会话内容。发送不等待、限时，失败只记日志；排队太多时丢弃
function notifier(api) {
  const cfg = api && api.pluginConfig && typeof api.pluginConfig.notify === 'object' ? api.pluginConfig.notify : null
  const targets = cfg && Array.isArray(cfg.targets) ? cfg.targets.filter((t) => t && typeof t.channel === 'string' && typeof t.to === 'string') : []
  if (targets.length === 0) return () => {}
  const on = Array.isArray(cfg.on) ? cfg.on : ['deny', 'warn']
  const command = Array.isArray(cfg.command) && cfg.command.length > 0 ? cfg.command : openclawCommand()
  let pending = 0
  return (kind, what, ctx, reply) => {
    if (!on.includes(kind)) return
    const agent = ctx && ctx.agentId ? ' (agent ' + ctx.agentId + ')' : ''
    const text = 'h-guard ' + what + agent + ': ' + messageOf(reply)
    for (const t of targets) {
      if (pending >= NOTIFY_MAX_PENDING) {
        log(api, 'too many notifications pending; this one was dropped')
        return
      }
      const argv = [...command, 'message', 'send', '--channel', t.channel, '--target', t.to, '--message', text]
      if (typeof t.account === 'string' && t.account !== '') argv.push('--account', t.account)
      if (typeof t.thread === 'string' && t.thread !== '') argv.push('--thread-id', t.thread)
      pending++
      run(api, argv, '', NOTIFY_TIMEOUT_MS)
        .then((out) => {
          if (out.code !== 0) log(api, 'could not send the notification to ' + t.channel + ' (exit code ' + out.code + ')')
        })
        .catch(() => log(api, 'could not send the notification to ' + t.channel))
        .finally(() => {
          pending--
        })
    }
  }
}

// openclawCommand 是运行 OpenClaw 命令行的方式：Gateway 本身由 node 运行 openclaw.mjs 时用同一个 node 与脚本，
// 否则用 PATH 里的 openclaw
function openclawCommand() {
  const script = process.argv[1]
  if (typeof script === 'string' && /^openclaw(\.m?js)?$/.test(basename(script))) return [process.execPath, script]
  return ['openclaw']
}
