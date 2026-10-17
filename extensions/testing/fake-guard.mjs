// 假 h-guard：argv 是 回复、记录文件、模式，之后是扩展追加的 --event <hook>。
import { appendFileSync } from 'node:fs'

const [reply, record, mode] = process.argv.slice(2, 5)
let input = ''
process.stdin.setEncoding('utf8')
process.stdin.on('data', (d) => {
  input += d
})
process.stdin.on('end', () => {
  if (record) appendFileSync(record, JSON.stringify({ argv: process.argv.slice(5), request: JSON.parse(input) }) + '\n')
  if (mode === 'slow') {
    setTimeout(() => {}, 60000)
    return
  }
  process.stdout.write(reply)
  process.exitCode = mode === 'fail' ? 3 : 0
})
