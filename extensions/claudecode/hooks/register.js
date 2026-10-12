// h-guard 的 Claude Code 接入（mod）。它只把事件按「扩展接入协议 v1」交给 h-guard 二进制，
// 再把回复翻译成 mods 的返回值；所有判断都在 h-guard 里（spec §7.6、§7.7）。
const PROTOCOL = 'h-guard.ext/v1'
const CONFIG_FILE = 'hguard.json'
const ACTIONS = ['pass', 'deny', 'ask', 'warn']
const DEFAULT_TIMEOUT_MS = 20000
const FAILED = 'h-guard could not finish its check'
const NO_REASON = 'h-guard stopped this without giving a reason'

export function register(on) {
  // 工具调用的权限决定：在 Claude Code 的规则与 settings hook 决定之后再收紧，从不放宽
  on('tool.check', async ($, e, next) => {
    const decided = await next(e)
    const reply = await callGuard($, 'tool.check', { data: e, decided: decisionOf(decided) })
    return applyCheck($, decided, reply)
  }).catch(async ($, e, next) => {
    // 接入层自身出错：已有 deny 保持，其余请求确认（spec §10.1：action 内部异常请求确认）
    return applyCheck($, await next(e), { action: 'error', message: FAILED })
  })

  // 工具结果：工具执行完、结果交给 Claude 之前检查；deny 扣下结果
  on('tool.call', async ($, e, next) => {
    const result = await next(e)
    if (result === undefined || result === null || result.deny !== undefined) return result
    const reply = await callGuard($, 'tool.result', { data: e, result })
    return applyResult($, result, reply)
  }).catch(async ($, e, next) => {
    // 接入层自身出错：放行结果，但告诉用户这次没有检查（spec §7.7）
    notify($, FAILED)
    return next(e)
  })

  // 提示词：deny 时不发送，原文退回输入框
  on('prompt.submit', async ($, e, next) => {
    const reply = await callGuard($, 'prompt.submit', { data: e })
    if (reply.action === 'deny' || reply.action === 'ask') return { drop: messageOf(reply) }
    if (reply.action === 'warn') return next({ ...e, context: [...(e.context ?? []), messageOf(reply)] })
    if (reply.action === 'error') $.ui.log(reply.message)
    return next(e)
  }).catch(async ($, e, next) => {
    notify($, FAILED)
    return next(e)
  })
}

// callGuard 按协议组装请求、运行 h-guard、校验回复。任何失败都返回 { action: 'error' }，
// 由各 hook 按 spec §10.1 处理：tool.check 请求确认，tool.result 与 prompt.submit 放行。
async function callGuard($, hook, extra) {
  try {
    const config = JSON.parse(await $.fs.read($.plugin.root + '/' + CONFIG_FILE))
    const argv = config.commands && config.commands[hook]
    if (!Array.isArray(argv) || argv.length === 0) return failure('no command configured for ' + hook)
    const request = {
      protocol: PROTOCOL,
      harness: 'claudecode',
      harness_version: versionOf(await $.session.version()),
      hook,
      session: { id: await $.session.id(), cwd: await $.session.cwd() },
      ...extra,
    }
    const out = await $.process.run([...argv, '--event', hook], {
      stdin: JSON.stringify(request),
      timeoutMs: config.timeout_ms || DEFAULT_TIMEOUT_MS,
    })
    if (out.exitCode !== 0) return failure('exit code ' + out.exitCode)
    const reply = JSON.parse(out.stdout)
    if (!reply || reply.protocol !== PROTOCOL || !ACTIONS.includes(reply.action)) return failure('unrecognized reply')
    return reply
  } catch (err) {
    return failure(err && err.message ? err.message : String(err))
  }
}

function failure(detail) {
  return { action: 'error', message: FAILED + ': ' + detail }
}

// messageOf 返回回复的说明；说明缺失时用固定文本，不能因为缺说明而让 deny 失效（spec §7.6）
function messageOf(reply) {
  return typeof reply.message === 'string' && reply.message.trim() !== '' ? reply.message : NO_REASON
}

// versionOf 把 $.session.version() 的结果（{ version, base?, builtAt? }）转成版本字符串
function versionOf(v) {
  return typeof v === 'string' ? v : v && typeof v.version === 'string' ? v.version : ''
}

// notify 尽力向用户显示一行提示；提示本身失败不影响放行
function notify($, text) {
  try {
    $.ui.log(text)
  } catch (err) {
    // 无法提示时只能放弃
  }
}

function decisionOf(decided) {
  return typeof decided === 'string' ? decided : decided && decided.decision
}

// applyCheck 只收紧：pass、warn 保留 Claude Code 的决定；deny 拒绝；ask 与接入层故障在已有决定
// 不是 deny 时请求确认。
function applyCheck($, decided, reply) {
  if (reply.action === 'deny') return { decision: 'deny', reason: messageOf(reply) }
  if (reply.action === 'ask' || reply.action === 'error') {
    if (decisionOf(decided) === 'deny') return decided
    return { decision: 'ask', reason: messageOf(reply) }
  }
  if (reply.action === 'warn') $.ui.log(messageOf(reply))
  return decided
}

// applyResult：deny（及不该出现在结果上的 ask）扣下结果，Claude 读到说明而不是原输出；
// warn 只提示用户；接入层故障放行并记一行日志。
function applyResult($, result, reply) {
  if (reply.action === 'deny' || reply.action === 'ask') return { deny: messageOf(reply) }
  if (reply.action === 'warn' || reply.action === 'error') $.ui.log(messageOf(reply))
  return result
}
