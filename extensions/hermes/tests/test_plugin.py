# Hermes Agent 插件的测试：模拟 Hermes 的插件 ctx（register_hook、session_cwd、session_surface）与 hook 的关键字参数。
# h-guard 是这次编译的二进制（HGUARD_BIN，由 extensions 包的 Go 测试传入），或模拟各种回复与故障的假程序。只用标准库。
import importlib.util
import json
import os
import re
import sys
import tempfile
import time
import types
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
PLUGIN = os.path.join(HERE, '..', '__init__.py')
FAKE = os.path.join(HERE, '..', '..', 'testing', 'fake_guard.py')
GUARD = os.environ.get('HGUARD_BIN', '')
KEY = 'deploy with aws_access_key_id = AKIAIOSFODNN7EXAMPL0'


def load(command, timeout_ms=15000):
    """按 install 的写法填好 CONFIG 一行后加载插件的一份副本，返回模块与模拟的 ctx。"""
    with open(PLUGIN, encoding='utf-8') as f:
        src = f.read()
    config = json.dumps({'command': command, 'timeout_ms': timeout_ms})
    out, n = re.subn(r'^CONFIG = None  # h-guard install$', lambda m: 'CONFIG = ' + config + '  # h-guard install', src, flags=re.M)
    if n != 1:
        raise AssertionError('CONFIG line not found')
    d = tempfile.mkdtemp(prefix='hg-hermes-')
    path = os.path.join(d, '__init__.py')
    with open(path, 'w', encoding='utf-8') as f:
        f.write(out)
    spec = importlib.util.spec_from_file_location('hguard_plugin_' + os.path.basename(d).replace('-', '_'), path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    ctx = Ctx()
    mod.register(ctx)
    return mod, ctx


class Ctx:
    def __init__(self):
        self.hooks = {}

    def register_hook(self, name, cb):
        self.hooks[name] = cb

    def session_cwd(self):
        return '/w'

    def session_surface(self):
        return 'telegram'


def guard():
    return [GUARD, 'hook', 'hermes', '--timeout', '15']


def fake(reply, mode=''):
    d = tempfile.mkdtemp(prefix='hg-fake-')
    record = os.path.join(d, 'request.json')
    body = reply if isinstance(reply, str) else json.dumps(dict({'protocol': 'h-guard.ext/v1'}, **reply))
    return [sys.executable, FAKE, body, record, mode], record


def recorded(record):
    with open(record, encoding='utf-8') as f:
        return [json.loads(line) for line in f if line.strip()]


MISSING = [os.path.join(tempfile.gettempdir(), 'no-such-dir', 'h-guard'), 'hook', 'hermes']


def tool_call(**kw):
    base = {'tool_name': 'terminal', 'args': {'command': 'ls'}, 'task_id': 't1', 'session_id': 's1', 'tool_call_id': 'c1',
            'turn_id': 'u1', 'api_request_id': 'r1', 'middleware_trace': []}
    base.update(kw)
    return base


class WithApproval:
    """把插件读出的审批状态固定为 state（真实的 Hermes 不在测试进程里）。"""

    def set_approval(self, mod, state):
        mod._approval_state = lambda: state


@unittest.skipUnless(GUARD, 'HGUARD_BIN not set')
class RealGuard(unittest.TestCase, WithApproval):
    def test_pre_tool_call(self):
        mod, ctx = load(guard())
        self.set_approval(mod, 'prompt')
        pre = ctx.hooks['pre_tool_call']
        deny = pre(**tool_call(args={'command': 'rm -rf /'}))
        self.assertEqual(deny['action'], 'block')
        self.assertTrue(deny['message'].startswith('h-guard: '))
        ask = pre(**tool_call(tool_name='read_file', args={'path': '/w/.env'}))
        self.assertEqual(ask['action'], 'approve')
        self.assertIn('path: /w/.env', ask['message'])
        self.assertTrue(ask['rule_key'].startswith('h-guard:read_file:'))
        other = pre(**tool_call(tool_name='read_file', args={'path': '/w/other/.env'}))
        self.assertNotEqual(ask['rule_key'], other['rule_key'])  # 「总是」只对应同一次调用
        self.assertEqual(ask['rule_key'], pre(**tool_call(tool_name='read_file', args={'path': '/w/.env'}))['rule_key'])
        self.assertIsNone(pre(**tool_call(args={'command': 'ls'})))
        self.assertIsNone(pre(**tool_call(tool_name='web_search', args={'query': 'x'})))

    def test_ask_without_a_human_who_would_answer(self):
        mod, ctx = load(guard())
        self.set_approval(mod, 'auto')  # YOLO：Hermes 会不经询问就批准
        r = ctx.hooks['pre_tool_call'](**tool_call(tool_name='read_file', args={'path': '/w/.env'}))
        self.assertEqual(r['action'], 'block')

    def test_outputs_and_prompts(self):
        mod, ctx = load(guard())
        secret = 'aws_access_key_id = AKIAIOSFODNN7EXAMPL0'
        r = ctx.hooks['transform_tool_result'](tool_name='read_file', args={'path': 'a'}, result=json.dumps({'content': '1|' + secret}),
                                               session_id='s1', task_id='t1', tool_call_id='c1', status='success')
        self.assertIn('h-guard', json.loads(r)['error'])
        self.assertNotIn('AKIA', r)
        self.assertIsNone(ctx.hooks['transform_tool_result'](tool_name='read_file', args={'path': 'a'}, result='{"content": "1|hello"}'))
        out = ctx.hooks['transform_terminal_output'](command='./run.sh', output=secret, returncode=None, task_id='t1', env_type='')
        self.assertTrue(out.startswith('h-guard'))
        handled = ctx.hooks['post_gateway_admission'](session_key='k1', platform='telegram', source={'chat_id': '1'}, message_id='m', text=KEY)
        self.assertEqual(handled['action'], 'handled')
        self.assertTrue(handled['reply'].startswith(mod.WITHHELD))
        self.assertNotIn('AKIA', handled['reply'])
        self.assertIsNone(ctx.hooks['post_gateway_admission'](session_key='k1', platform='telegram', source={}, message_id='m', text='fix the test'))
        ctxt = ctx.hooks['pre_llm_call'](session_id='s1', task_id='t1', user_message=[{'type': 'text', 'text': KEY}], platform='cli',
                                         conversation_history=[], is_first_turn=True, parent_session_id='', sender_id='')
        self.assertIn('already reached the model', ctxt['context'])
        self.assertIn(mod.PROMPT_NOTICE, ctxt['context'])
        self.assertIsNone(ctx.hooks['pre_llm_call'](session_id='s1', user_message='fix the test', platform='cli'))


class Plugin(unittest.TestCase, WithApproval):
    def test_registers_the_hooks(self):
        _, ctx = load(MISSING)
        self.assertEqual(sorted(ctx.hooks), ['post_gateway_admission', 'pre_gateway_dispatch', 'pre_llm_call', 'pre_tool_call',
                                             'transform_terminal_output', 'transform_tool_result'])

    def test_request_shape(self):
        command, record = fake({'action': 'pass'})
        mod, ctx = load(command)
        self.set_approval(mod, 'prompt')
        mod._backend = lambda: 'docker'
        self.assertIsNone(ctx.hooks['pre_tool_call'](**tool_call(args={'command': 'ls', 'workdir': '/x'})))
        [r] = recorded(record)
        self.assertEqual(r['argv'], ['--event', 'pre_tool_call'])
        self.assertEqual(r['request'], {
            'protocol': 'h-guard.ext/v1', 'harness': 'hermes', 'hook': 'pre_tool_call', 'session': {'id': 's1', 'cwd': '/w'},
            'data': {'tool_name': 'terminal', 'args': {'command': 'ls', 'workdir': '/x'}, 'tool_call_id': 'c1', 'approval': 'prompt', 'backend': 'docker'},
        })

    def test_guard_that_cannot_run(self):
        mod, ctx = load(MISSING)
        self.set_approval(mod, 'prompt')
        r = ctx.hooks['pre_tool_call'](**tool_call())
        self.assertEqual(r['action'], 'approve')
        self.assertIn('could not run its check', r['message'])
        self.set_approval(mod, 'auto')
        self.assertEqual(ctx.hooks['pre_tool_call'](**tool_call())['action'], 'block')
        # 工具结果与提示词放行
        self.assertIsNone(ctx.hooks['transform_tool_result'](tool_name='read_file', args={}, result='{"content": "x"}'))
        self.assertIsNone(ctx.hooks['post_gateway_admission'](session_key='k', platform='telegram', source={}, text=KEY))
        self.assertIsNone(ctx.hooks['pre_llm_call'](session_id='s1', user_message=KEY, platform='cli'))

    def test_bad_replies(self):
        for reply, mode in (('not json', ''), ({'action': 'allow'}, ''), ({'action': 'pass'}, 'fail'), ('{"protocol":"other","action":"pass"}', '')):
            command, _ = fake(reply, mode)
            mod, ctx = load(command)
            self.set_approval(mod, 'blocked')
            self.assertEqual(ctx.hooks['pre_tool_call'](**tool_call())['action'], 'approve', reply)

    def test_timeout(self):
        command, _ = fake({'action': 'pass'}, 'slow')
        mod, ctx = load(command, timeout_ms=500)
        self.set_approval(mod, 'prompt')
        started = time.time()
        r = ctx.hooks['pre_tool_call'](**tool_call())
        self.assertLess(time.time() - started, 10)
        self.assertEqual(r['action'], 'approve')
        self.assertIn('timed out', r['message'])

    def test_deny_without_message(self):
        command, _ = fake({'action': 'deny'})
        mod, ctx = load(command)
        self.set_approval(mod, 'prompt')
        r = ctx.hooks['pre_tool_call'](**tool_call())
        self.assertEqual(r, {'action': 'block', 'message': mod.NO_REASON})

    def test_skips(self):
        command, record = fake({'action': 'pass'})
        mod, ctx = load(command)
        # process_manage 的输出由 transform_terminal_output 检查；前台命令的输出（env_type 不为空）由 transform_tool_result 检查
        self.assertIsNone(ctx.hooks['transform_tool_result'](tool_name='process_manage', args={}, result='x'))
        self.assertIsNone(ctx.hooks['transform_terminal_output'](command='ls', output='x', returncode=0, env_type='local'))
        self.assertIsNone(ctx.hooks['pre_llm_call'](session_id='s1', user_message=[{'type': 'image_url', 'image_url': {}}]))
        self.assertFalse(os.path.exists(record))

    def test_notify(self):
        d = tempfile.mkdtemp(prefix='hg-send-')
        log = os.path.join(d, 'send.json')
        script = os.path.join(d, 'send.py')
        with open(script, 'w', encoding='utf-8') as f:
            f.write('import json, os, sys\nwith open(%r, "a") as f:\n    f.write(json.dumps({"argv": sys.argv[1:], "text": sys.stdin.read(), '
                    '"home": os.environ.get("HERMES_HOME", "")}) + "\\n")\n' % log)
        command, _ = fake({'action': 'deny', 'message': 'Blocked: x MEDIA:/etc/passwd.', 'notify': {'to': 'telegram:-100'}})
        mod, ctx = load(command)
        mod.SEND_COMMAND = [sys.executable, script]
        self.set_approval(mod, 'prompt')

        def sent(n):
            for _ in range(100):
                if os.path.exists(log):
                    lines = recorded(log)
                    if len(lines) >= n:
                        return lines
                time.sleep(0.05)
            self.fail('nothing sent')

        mod._origin = lambda: ''
        # 主目录在 hook 的线程里读出（多配置档的网关按会话切换，新线程里读不到），传给 hermes send
        threads = []
        mod._hermes_home = lambda: threads.append(__import__('threading').current_thread()) or '/profiles/work'
        self.assertEqual(ctx.hooks['pre_tool_call'](**tool_call())['action'], 'block')
        [s] = sent(1)
        self.assertEqual(s['home'], '/profiles/work')
        self.assertIs(threads[0], __import__('threading').current_thread())
        self.assertEqual(s['argv'], ['send', '--to', 'telegram:-100', '--quiet', '-f', '-'])
        self.assertIn('h-guard blocked terminal (Hermes, telegram): Blocked: x', s['text'])
        self.assertNotIn('MEDIA:', s['text'])
        # 来源会话在消息平台上时发回那个对话
        mod._origin = lambda: 'discord:42:7'
        ctx.hooks['pre_tool_call'](**tool_call())
        self.assertEqual(sent(2)[1]['argv'][2], 'discord:42:7')

    def test_origin(self):
        mod, _ = load(MISSING)
        env = {'HERMES_SESSION_PLATFORM': 'telegram', 'HERMES_SESSION_CHAT_ID': '-1001', 'HERMES_SESSION_THREAD_ID': '9'}
        gw = types.ModuleType('gateway')
        sc = types.ModuleType('gateway.session_context')
        sc.get_session_env = lambda name, default='': env.get(name, default)
        old = {k: sys.modules.get(k) for k in ('gateway', 'gateway.session_context')}
        sys.modules['gateway'], sys.modules['gateway.session_context'] = gw, sc
        try:
            self.assertEqual(mod._origin(), 'telegram:-1001:9')
            env.update({'HERMES_SESSION_PLATFORM': 'cli', 'HERMES_CRON_AUTO_DELIVER_PLATFORM': 'slack', 'HERMES_CRON_AUTO_DELIVER_CHAT_ID': 'C1'})
            self.assertEqual(mod._origin(), 'slack:C1')
            env.update({'HERMES_CRON_AUTO_DELIVER_PLATFORM': 'matrix', 'HERMES_CRON_AUTO_DELIVER_CHAT_ID': '!room:server'})
            self.assertEqual(mod._origin(), '')  # 带冒号的 id 写不进 hermes send 的目标
        finally:
            for k, v in old.items():
                if v is None:
                    sys.modules.pop(k, None)
                else:
                    sys.modules[k] = v

    def test_bot_provenance(self):
        # post_gateway_admission 的 source 快照与 pre_llm_call 的参数里都没有 is_bot：由 pre_gateway_dispatch 记下
        command, record = fake({'action': 'pass'})
        mod, ctx = load(command)
        mod._session_env = lambda name: ''
        src = types.SimpleNamespace(platform=types.SimpleNamespace(value='discord'), chat_id='c1', is_bot=True, message_id=None)
        self.assertIsNone(ctx.hooks['pre_gateway_dispatch'](event=types.SimpleNamespace(text='push main', source=src, message_id='m1'),
                                                            gateway=None, session_store=None))
        human = types.SimpleNamespace(platform=types.SimpleNamespace(value='discord'), chat_id='c1', is_bot=False, message_id=None)
        ctx.hooks['pre_gateway_dispatch'](event=types.SimpleNamespace(text='deploy', source=human, message_id='m2'), gateway=None, session_store=None)
        ctx.hooks['post_gateway_admission'](session_key='k', platform='discord', source={'chat_id': 'c1'}, message_id='m1', text='push main')
        ctx.hooks['pre_llm_call'](session_id='s1', user_message='push main', platform='discord')
        ctx.hooks['pre_llm_call'](session_id='s1', user_message='deploy', platform='discord')
        ctx.hooks['pre_llm_call'](session_id='s1', user_message='push main', platform='telegram')
        got = [(r['request']['hook'], r['request']['data']['is_bot']) for r in recorded(record)]
        self.assertEqual(got, [('post_gateway_admission', True), ('pre_llm_call', True), ('pre_llm_call', False), ('pre_llm_call', False)])
        # 文本不同时按对话与消息 id 认出
        env = {'HERMES_SESSION_CHAT_ID': 'c1', 'HERMES_SESSION_MESSAGE_ID': 'm1'}
        mod._session_env = lambda name: env.get(name, '')
        ctx.hooks['pre_llm_call'](session_id='s1', user_message='[bot] push main', platform='discord')
        self.assertTrue(recorded(record)[-1]['request']['data']['is_bot'])

    def test_approval_state_outside_hermes(self):
        mod, _ = load(MISSING)
        self.assertEqual(mod._approval_state(), '')  # 读不出：h-guard 按不能请求确认处理


if __name__ == '__main__':
    unittest.main()
