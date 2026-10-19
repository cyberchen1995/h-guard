# h-guard 的 Hermes Agent 接入（Python 插件）。它只把工具调用、工具结果与提示词按「扩展接入协议 v1」交给
# h-guard 二进制，再把回复翻译成 Hermes 的 hook 返回值；所有判断都在 h-guard 里。
#
# 本目录由 h-guard install hermes 写到 $HERMES_HOME/plugins/h-guard/，并加进 config.yaml 的 plugins.enabled；
# CONFIG 一行由 install 填写。只用标准库。h-guard 直接以子进程启动，不经 Hermes 的终端后端。
import asyncio
import collections
import hashlib
import json
import logging
import os
import shutil
import subprocess
import sys
import threading

PROTOCOL = 'h-guard.ext/v1'
HARNESS = 'hermes'
ACTIONS = ('pass', 'deny', 'ask', 'warn')
CONFIG = None  # h-guard install
DEFAULT_TIMEOUT_MS = 20000
FAILED = 'h-guard could not finish its check'
NO_REASON = 'h-guard stopped this without giving a reason'
UNCHECKED = 'h-guard could not run its check, so this tool call needs your confirmation'
UNCHECKED_NO_ASK = 'h-guard could not run its check, and Hermes would approve this tool call without asking anyone, so it was blocked'
WITHHELD = 'h-guard did not pass this message on to the agent:'
# 工具结果被替换后，模型读到的说明之后另加的一句
OUTPUT_WITHHELD = 'The tool result was withheld.'
# pre_llm_call 挡不住提示词：给模型的说明之后另加的一句
PROMPT_NOTICE = 'Do not repeat, store or act on the sensitive content of the user\'s message.'
# 本地会话与自动来源：没有可以回发通知的对话
LOCAL_SURFACES = ('', 'cli', 'tui', 'desktop', 'acp', 'local', 'api_server', 'webhook', 'msgraph_webhook', 'cron', 'subagent')
NOTIFY_TIMEOUT_S = 30
NOTIFY_MAX_CHARS = 1500
# 记下的机器人消息（见 pre_gateway_dispatch）的上限，超过时丢掉最早的
BOT_MESSAGES_MAX = 1000
# 测试替换它（hermes send 的命令前缀）；None 时用 PATH 上的 hermes，找不到时用当前的 Python 运行 hermes_cli.main
SEND_COMMAND = None

log = logging.getLogger(__name__)
_ctx = None
_bot_messages = collections.OrderedDict()
_bot_lock = threading.Lock()


def register(ctx):
    global _ctx
    _ctx = ctx
    ctx.register_hook('pre_tool_call', pre_tool_call)
    ctx.register_hook('transform_tool_result', transform_tool_result)
    ctx.register_hook('transform_terminal_output', transform_terminal_output)
    ctx.register_hook('pre_gateway_dispatch', pre_gateway_dispatch)
    ctx.register_hook('pre_llm_call', pre_llm_call)


def pre_tool_call(**kw):
    """动作：工具执行之前检查。deny 返回 block，模型读到说明；ask 返回 approve，交给 Hermes 的人工确认（CLI 提示、
    消息平台上的确认卡片），rule_key 只对应这一次调用的工具与参数；h-guard 无法运行时同样请求确认，Hermes 会不经询问
    就批准时（YOLO、approvals.mode: off 等）阻止。pass 与 warn 不返回指令，h-guard 从不放行。"""
    tool = kw.get('tool_name') or ''
    args = kw.get('args') if isinstance(kw.get('args'), dict) else {}
    approval = _approval_state()
    reply = _call('pre_tool_call', _session(kw), {
        'data': {
            'tool_name': tool, 'args': args, 'tool_call_id': kw.get('tool_call_id') or '',
            'approval': approval, 'backend': _backend(),
        },
    }, _cwd(kw))
    if reply['action'] == 'error':
        if approval in ('prompt', 'blocked'):
            text = UNCHECKED + ' (' + reply['message'] + ')'
            return {'action': 'approve', 'message': _approval_message(text, tool, args), 'rule_key': _rule_key(tool, args, text)}
        return {'action': 'block', 'message': UNCHECKED_NO_ASK + ' (' + reply['message'] + ')'}
    if reply['action'] == 'deny':
        _notify(reply, 'blocked', tool, approval)
        return {'action': 'block', 'message': _text_of(reply)}
    if reply['action'] == 'ask':
        _notify(reply, 'asks to confirm', tool, approval)
        text = _text_of(reply)
        return {'action': 'approve', 'message': _approval_message(text, tool, args), 'rule_key': _rule_key(tool, args, text)}
    if reply['action'] == 'warn':
        log.warning('h-guard: %s', _message_of(reply))
        _notify(reply, 'warns about', tool, approval)
    return None


def transform_tool_result(**kw):
    """工具结果：交给模型之前检查；deny 用说明代替结果。process_manage 的输出由 transform_terminal_output 检查。
    接入层故障放行结果并记一行日志。"""
    tool = kw.get('tool_name') or ''
    result = kw.get('result')
    if tool in ('process_manage', 'process') or not isinstance(result, str) or result == '':
        return None
    args = kw.get('args') if isinstance(kw.get('args'), dict) else {}
    try:
        reply = _call('transform_tool_result', _session(kw), {
            'data': {'tool_name': tool, 'args': args, 'tool_call_id': kw.get('tool_call_id') or '', 'status': kw.get('status') or ''},
            'result': {'content': result},
        }, _cwd(kw))
        return _output_reply(reply, tool, lambda text: json.dumps({'error': text}, ensure_ascii=False))
    except Exception:
        log.warning('h-guard: %s', FAILED)
    return None


def transform_terminal_output(**kw):
    """后台进程的输出（process_manage 的 poll、wait、log 与完成、心跳通知）：交给模型或对话之前检查；deny 用说明
    代替输出。前台命令的输出（env_type 不为空）由 transform_tool_result 检查，这里不重复。"""
    output = kw.get('output')
    if kw.get('env_type') or not isinstance(output, str) or output == '':
        return None
    try:
        reply = _call('transform_terminal_output', _session(kw), {
            'data': {'command': kw.get('command') or '', 'returncode': kw.get('returncode'), 'env_type': kw.get('env_type') or ''},
            'result': {'content': output},
        }, _cwd(kw))
        return _output_reply(reply, 'process_manage', lambda text: text)
    except Exception:
        log.warning('h-guard: %s', FAILED)
    return None


def _output_reply(reply, tool, wrap):
    if reply['action'] in ('deny', 'ask'):
        _notify(reply, 'withheld the output of', tool, '')
        return wrap(_text_of(reply) + ' ' + OUTPUT_WITHHELD)
    if reply['action'] == 'warn':
        log.warning('h-guard: %s', _message_of(reply))
        _notify(reply, 'warns about the output of', tool, '')
    if reply['action'] == 'error':
        log.warning('h-guard: %s', reply['message'])
    return None


async def pre_gateway_dispatch(**kw):
    """消息平台上的提示词：网关收到消息之后、授权与交给 agent 之前检查（Hermes 在事件循环上 await 这个回调，h-guard
    在另一个线程里运行，不卡住网关）。只检查已授权的发送者的消息：其余的 Hermes 自己丢弃或回复配对码。deny 时返回
    skip 丢弃这条消息，并把原因作为回复发回这个对话（机器人发的消息不回复）。warn 由这一轮的 pre_llm_call 交给模型。
    接入层故障放行并记一行日志，pre_llm_call 照常检查。另外记下机器人或 webhook 发的消息（event.source.is_bot）：
    pre_llm_call 的参数里没有这一项。"""
    event = kw.get('event')
    gateway = kw.get('gateway')
    src = getattr(event, 'source', None)
    _record_bot(event, src)
    text = getattr(event, 'text', None)
    if src is None or not isinstance(text, str) or text.strip() == '' or not _authorized(gateway, src):
        return None
    try:
        is_bot = bool(getattr(src, 'is_bot', False))
        reply = await asyncio.to_thread(_call, 'pre_gateway_dispatch', _gateway_session(gateway, src), {
            'data': {'text': text, 'platform': _platform_name(getattr(src, 'platform', '')), 'is_bot': is_bot},
        }, '')
        if reply['action'] in ('deny', 'ask'):
            msg = _message_of(reply)
            log.warning('h-guard: %s', msg)
            if not is_bot:
                await _reply(gateway, src, WITHHELD + ' ' + msg)
            return {'action': 'skip', 'reason': 'h-guard: ' + msg}
        if reply['action'] == 'error':
            log.warning('h-guard: %s', reply['message'])
    except Exception:
        log.warning('h-guard: %s', FAILED)
    return None


def _authorized(gateway, src):
    """网关会不会接受这个发送者（与 Hermes 随后做的检查相同）；问不了时按已授权处理，照常检查。"""
    try:
        return bool(gateway._is_user_authorized_for_source(src))
    except Exception:
        return True


def _gateway_session(gateway, src):
    try:
        key = gateway._session_key_for_source(src)
        if isinstance(key, str) and key != '':
            return key
    except Exception:
        pass
    return HARNESS + '-' + str(os.getpid())


async def _reply(gateway, src, text):
    """经收到这条消息的机器人把说明发回这个对话（同一话题里）；尽力而为。"""
    try:
        adapter = gateway._delivery_adapter_for(src)
        if adapter is None:
            return
        thread = getattr(src, 'thread_id', None)
        await adapter.send(src.chat_id, _sanitize(text), metadata={'thread_id': thread} if thread else None)
    except Exception:
        log.warning('h-guard: could not reply to the chat')


def _record_bot(event, src):
    """记下机器人发的消息，pre_llm_call 按它判断消息来源；不记下的话，机器人的「push main」会被当作用户本人的指令。"""
    try:
        if src is None or not getattr(src, 'is_bot', False):
            return
        platform = _platform_name(getattr(src, 'platform', ''))
        keys = [_bot_key(platform, 'text', getattr(event, 'text', '') or '')]
        mid = getattr(event, 'message_id', None) or getattr(src, 'message_id', None)
        if mid:
            keys.append(_bot_key(platform, 'message', str(getattr(src, 'chat_id', '') or '') + '\n' + str(mid)))
        with _bot_lock:
            for k in keys:
                _bot_messages.pop(k, None)
                _bot_messages[k] = True
            while len(_bot_messages) > BOT_MESSAGES_MAX:
                _bot_messages.popitem(last=False)
    except Exception:
        log.debug('h-guard: could not read the message source')


def _platform_name(p):
    return str(getattr(p, 'value', p) or '').lower()


def _bot_key(platform, kind, value):
    return hashlib.sha256((platform + '\n' + kind + '\n' + value).encode('utf-8')).hexdigest()


def _from_bot(platform, text, chat_id, message_id):
    """这条消息是不是 pre_gateway_dispatch 记下的机器人消息：按平台与文本，或平台、对话与消息 id。同样文本的用户消息
    也会按自动消息处理，属于安全方向。"""
    platform = _platform_name(platform)
    keys = [_bot_key(platform, 'text', text)]
    if message_id:
        keys.append(_bot_key(platform, 'message', str(chat_id or '') + '\n' + str(message_id)))
    with _bot_lock:
        return any(k in _bot_messages for k in keys)


def _session_env(name):
    try:
        from gateway.session_context import get_session_env
        return get_session_env(name, '') or ''
    except Exception:
        return ''


def pre_llm_call(**kw):
    """每一轮交给模型之前的用户消息（CLI、TUI、Desktop、消息平台、定时任务与子 agent 都经过这里）。这一步挡不住提示词：
    h-guard 把 deny 降级为 warn（prompt_not_blocked），插件把说明作为这一轮的上下文交给模型。接入层故障放行并记一行日志。"""
    text = _message_text(kw.get('user_message'))
    if text.strip() == '':
        return None
    try:
        platform = kw.get('platform') or ''
        is_bot = _from_bot(platform, text, _session_env('HERMES_SESSION_CHAT_ID'), _session_env('HERMES_SESSION_MESSAGE_ID'))
        reply = _call('pre_llm_call', _session(kw), {
            'data': {'text': text, 'platform': platform, 'parent_session_id': kw.get('parent_session_id') or '', 'is_bot': is_bot},
        }, _cwd(kw))
        if reply['action'] in ('deny', 'ask', 'warn'):
            log.warning('h-guard: %s', _message_of(reply))
            _notify(reply, 'warns about a prompt in', 'the session', '')
            return {'context': _text_of(reply) + ' ' + PROMPT_NOTICE}
        if reply['action'] == 'error':
            log.warning('h-guard: %s', reply['message'])
    except Exception:
        log.warning('h-guard: %s', FAILED)
    return None


def _message_text(msg):
    """用户消息的文本：字符串原样；多模态的消息（内容块列表）取各文本块，以换行连接。"""
    if isinstance(msg, str):
        return msg
    if not isinstance(msg, list):
        return ''
    parts = []
    for p in msg:
        if isinstance(p, dict) and p.get('type') in ('text', 'input_text') and isinstance(p.get('text'), str):
            parts.append(p['text'])
        elif isinstance(p, str):
            parts.append(p)
    return '\n'.join(parts)


def _approval_state():
    """approve 指令交给 Hermes 之后会怎样：prompt（有人回答）、blocked（没有人能回答，Hermes 拒绝）、auto（Hermes
    不经询问就批准：YOLO、approvals.mode: off、按 approvals.*_mode: approve 自动批准）；读不出时为空，h-guard 按不能
    请求确认处理。与 tools/approval.py 的 _run_approval_gate 同样的顺序。plugins.isolation: host 时插件在另一个进程里，
    读不到会话的状态。"""
    if os.environ.get('HERMES_PLUGIN_HOST_PROCESS') == '1':
        return ''
    try:
        from tools import approval as ap
        from tools import approval_context as ac
        if ap._yolo_active() or ac._get_approval_mode() == 'off':
            return 'auto'
        _cb, is_cli, is_gateway, is_ask = ap._presence()
        if is_cli or is_gateway or is_ask:
            return 'prompt'
        for c in ap._unattended_contexts():
            return 'blocked' if c.mode() == 'deny' else 'auto'
        return 'blocked'  # 插件的 approve 在没有人时 fail-closed
    except Exception:
        return ''


def _backend():
    try:
        from tools.terminal_tool import _get_env_config
        return str(_get_env_config().get('env_type') or '')
    except Exception:
        return os.environ.get('TERMINAL_ENV', '')


def _session(kw):
    sid = kw.get('session_id') or kw.get('task_id')
    return sid if isinstance(sid, str) and sid != '' else HARNESS + '-' + str(os.getpid())


def _cwd(kw):
    """会话的工作目录：终端记下的目录（跟着 cd 走）、Hermes 记下的会话目录，最后是 Hermes 进程的目录。"""
    try:
        from tools.terminal_tool import get_session_cwd
        d = get_session_cwd(kw.get('task_id') or None)
        if isinstance(d, str) and d != '':
            return d
    except Exception:
        pass
    try:
        d = _ctx.session_cwd() if _ctx is not None else ''
        if isinstance(d, str) and d != '':
            return d
    except Exception:
        pass
    return os.getcwd()


def _rule_key(tool, args, text):
    """approve 指令的 rule_key：Hermes 把用户的「本会话」「总是」选择记在 plugin_rule:<rule_key> 下。它由工具、参数与
    h-guard 的说明算出，只对应同一次调用；没有它时 Hermes 按工具名记，一次「总是」会放过之后这个工具的所有确认。"""
    body = json.dumps([tool, args, text], sort_keys=True, ensure_ascii=False, default=str)
    return 'h-guard:' + tool + ':' + hashlib.sha256(body.encode('utf-8')).hexdigest()[:16]


def _approval_message(text, tool, args):
    """确认卡片与 CLI 提示里显示的只有 message：带上命令或路径，用户才知道要确认的是什么。"""
    lines = [text]
    for key in ('command', 'path', 'data', 'patch', 'code', 'output_path', 'expression'):
        v = args.get(key)
        if isinstance(v, str) and v.strip() != '':
            if len(v) > 600:
                v = v[:600] + '…'
            lines.append(key + ': ' + v)
    if len(lines) == 1:
        lines.append('tool: ' + tool)
    return '\n'.join(lines)


def _notify(reply, verb, tool, approval):
    """按 h-guard 的配置（harnesses.hermes.notify，回复里带 notify 时）把说明发到消息渠道：来源会话所在的对话，没有时是
    配置的目标。说明已经在这个对话里显示过（消息平台上的确认卡片）时不再发。另起线程，不等待，不影响结论。"""
    n = reply.get('notify')
    if not isinstance(n, dict):
        return
    try:
        origin = _origin()
        if origin and approval == 'prompt' and reply['action'] == 'ask':
            return  # 确认卡片已经发到了这个对话
        target = origin or (n.get('to') if isinstance(n.get('to'), str) else '')
        if not target:
            log.info('h-guard: no channel to notify')
            return
        where = _surface() or 'cli'
        text = 'h-guard ' + verb + ' ' + tool + ' (Hermes, ' + where + '): ' + _message_of(reply)
        # 在 hook 的线程里读出这次会话的主目录：多配置档的网关按会话切换配置档（ContextVar），新线程看不到它，
        # hermes send 会用错配置档的凭据
        threading.Thread(target=_send, args=(target, _sanitize(text), _hermes_home()), daemon=True).start()
    except Exception:
        log.warning('h-guard: could not send a notification')


def _origin():
    """来源会话所在的对话（hermes send --to 的写法）：消息平台的会话，或定时任务的投递目标；本地会话为空。"""
    try:
        from gateway.session_context import get_session_env
    except Exception:
        return ''
    for prefix in ('HERMES_SESSION_', 'HERMES_CRON_AUTO_DELIVER_'):
        try:
            platform = get_session_env(prefix + 'PLATFORM', '') or ''
            chat = get_session_env(prefix + 'CHAT_ID', '') or ''
            thread = get_session_env(prefix + 'THREAD_ID', '') or ''
        except Exception:
            continue
        platform = str(platform).lower()
        if platform in LOCAL_SURFACES or not chat or ':' in str(chat) or ':' in str(thread):
            continue
        return platform + ':' + str(chat) + (':' + str(thread) if thread else '')
    return ''


def _surface():
    try:
        return _ctx.session_surface() if _ctx is not None else ''
    except Exception:
        return ''


def _sanitize(text):
    """通知只是一行说明：去掉控制字符；MEDIA: 会让 hermes send 把路径当附件发出，拆开。"""
    text = ''.join(c if c >= ' ' or c == '\n' else ' ' for c in text).replace('MEDIA:', 'MEDIA :')
    return text[:NOTIFY_MAX_CHARS]


def _hermes_home():
    """这次会话的 Hermes 主目录（含配置档的切换）；读不到时为空，hermes send 沿用进程的 HERMES_HOME。"""
    try:
        from hermes_constants import get_hermes_home
        return str(get_hermes_home())
    except Exception:
        return ''


def _send(target, text, home=''):
    try:
        cmd = list(SEND_COMMAND) if SEND_COMMAND else ([shutil.which('hermes')] if shutil.which('hermes') else [sys.executable, '-m', 'hermes_cli.main'])
        env = dict(os.environ)
        if home:
            env['HERMES_HOME'] = home
        # 正文从 stdin 传入（-f -），不经 argv，也就不会被当作选项
        p = subprocess.Popen(cmd + ['send', '--to', target, '--quiet', '-f', '-'], stdin=subprocess.PIPE,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env, **_hidden())
        try:
            p.communicate(text.encode('utf-8'), timeout=NOTIFY_TIMEOUT_S)
        except subprocess.TimeoutExpired:
            p.kill()
            p.communicate()
        if p.returncode != 0:
            log.warning('h-guard: hermes send to %s failed (exit code %s)', target.split(':', 1)[0], p.returncode)
    except Exception:
        log.warning('h-guard: could not run hermes send')


def _hidden():
    if sys.platform == 'win32':
        return {'creationflags': getattr(subprocess, 'CREATE_NO_WINDOW', 0)}
    return {}


def _call(hook, session, extra, cwd):
    """按协议组装请求、运行 h-guard、校验回复。任何失败都返回 {'action': 'error'}，由各 hook 按固定规则处理。"""
    try:
        config = CONFIG or {'command': ['h-guard', 'hook', HARNESS], 'timeout_ms': DEFAULT_TIMEOUT_MS}
        request = {'protocol': PROTOCOL, 'harness': HARNESS, 'hook': hook, 'session': {'id': session, 'cwd': cwd or os.getcwd()}}
        request.update(extra)
        body = json.dumps(request, ensure_ascii=False, default=str).encode('utf-8')
        timeout = (config.get('timeout_ms') or DEFAULT_TIMEOUT_MS) / 1000
        try:
            out = subprocess.run(list(config['command']) + ['--event', hook], input=body, stdout=subprocess.PIPE,
                                 stderr=subprocess.DEVNULL, timeout=timeout, **_hidden())
        except subprocess.TimeoutExpired:
            return _failure('timed out')
        if out.returncode != 0:
            return _failure('exit code ' + str(out.returncode))
        reply = json.loads(out.stdout.decode('utf-8'))
        if not isinstance(reply, dict) or reply.get('protocol') != PROTOCOL or reply.get('action') not in ACTIONS:
            return _failure('unrecognized reply')
        return reply
    except Exception as err:
        return _failure(err)


def _failure(detail):
    return {'action': 'error', 'message': FAILED + ': ' + str(detail)}


def _message_of(reply):
    """回复的说明；说明缺失时用固定文本，不能因为缺说明而让 deny 失效。"""
    msg = reply.get('message')
    return msg if isinstance(msg, str) and msg.strip() != '' else NO_REASON


def _text_of(reply):
    """写给模型的说明：前缀表明来源，后接原因与前进路径。"""
    msg = _message_of(reply)
    s = msg if msg.startswith('h-guard') else 'h-guard: ' + msg
    hint = reply.get('hint')
    if isinstance(hint, str) and hint != '':
        s += ' ' + hint
    return s
