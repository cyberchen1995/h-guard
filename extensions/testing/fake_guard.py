# 假 h-guard（Python 插件的测试用）：argv 是 回复、记录文件、模式，之后是插件追加的 --event <hook>。
import json
import sys
import time

reply, record, mode = sys.argv[1], sys.argv[2], sys.argv[3]
data = sys.stdin.buffer.read().decode('utf-8')
if record:
    with open(record, 'a', encoding='utf-8') as f:
        f.write(json.dumps({'argv': sys.argv[4:], 'request': json.loads(data)}) + '\n')
if mode == 'slow':
    time.sleep(60)
sys.stdout.write(reply)
sys.exit(3 if mode == 'fail' else 0)
