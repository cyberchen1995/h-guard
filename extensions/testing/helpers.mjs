// 扩展测试共用的工具：按 install 的写法填好 CONFIG 一行后加载扩展；h-guard 的命令是真实的二进制（HGUARD_BIN，
// 由 extensions 包的 Go 测试编译并传入），或模拟各种回复与故障的假程序。
import { mkdtemp, readFile, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { basename, dirname, join } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))

// load 加载 file 的一份副本：CONFIG 是 command 与 timeoutMs，HARNESS 是 harness（只有 pi 的模板有这一行）
export async function load(file, harness, command, timeoutMs = 15000) {
  const src = await readFile(file, 'utf8')
  const config = JSON.stringify({ command, timeout_ms: timeoutMs })
  const out = src
    .replace(/^const CONFIG = null \/\/ h-guard install$/m, () => 'const CONFIG = ' + config + ' // h-guard install')
    .replace(/^const HARNESS = '[a-z]+' \/\/ h-guard install$/m, () => "const HARNESS = '" + harness + "' // h-guard install")
  if (!out.includes('const CONFIG = ' + config)) throw new Error('CONFIG line not found in ' + file)
  const dir = await mkdtemp(join(tmpdir(), 'hg-ext-'))
  const path = join(dir, basename(file).replace(/\.js$/, '.mjs'))
  await writeFile(path, out)
  return import(pathToFileURL(path).href)
}

// guard 是真实 h-guard 的命令；没有 HGUARD_BIN 时测试应跳过
export function guard(harness) {
  return [process.env.HGUARD_BIN, 'hook', harness, '--timeout', '15']
}

export const haveGuard = !!process.env.HGUARD_BIN

// fake 是假 h-guard 的命令：把请求记到 record 文件（给了时），回复 reply（对象原样 JSON；字符串原样输出）；
// mode 为 'fail' 时以 3 退出，'slow' 时不回复
export async function fake(reply, mode = '') {
  const dir = await mkdtemp(join(tmpdir(), 'hg-fake-'))
  const record = join(dir, 'request.json')
  const body = typeof reply === 'string' ? reply : JSON.stringify({ protocol: 'h-guard.ext/v1', ...reply })
  return { command: [process.execPath, join(here, 'fake-guard.mjs'), body, record, mode], record }
}

export async function recorded(record) {
  const lines = (await readFile(record, 'utf8')).trim().split('\n')
  return lines.map((l) => JSON.parse(l))
}

// missing 是不存在的 h-guard
export const missing = [join(tmpdir(), 'no-such-dir', 'h-guard'), 'hook', 'x']
