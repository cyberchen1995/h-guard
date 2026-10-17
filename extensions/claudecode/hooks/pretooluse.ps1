# h-guard 的经典 PreToolUse hook，Windows 原生环境用；与 pretooluse.sh 相同：把 Claude Code 的
# hook 输入交给 h-guard，h-guard 无法运行（找不到、启动失败、非零退出）时输出 ask，让这次工具调用请求确认。
# 插件根目录的 hguard-bin（h-guard 的路径）与 hguard-timeout（传给 h-guard 的 --timeout 秒数）由 install 写入，
# 第一行有效；没有时分别用 PATH 中的 h-guard 与 20。兼容 Windows PowerShell 5.1。
$ErrorActionPreference = 'Stop'
$utf8 = New-Object System.Text.UTF8Encoding $false
$OutputEncoding = $utf8
[Console]::InputEncoding = $utf8
[Console]::OutputEncoding = $utf8
$ask = '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"ask","permissionDecisionReason":"h-guard could not run its check, so this tool call needs your confirmation."}}'
$root = $env:CLAUDE_PLUGIN_ROOT
if (-not $root) { $root = Split-Path -Parent $PSScriptRoot }
$bin = 'h-guard'
try {
  $line = Get-Content -LiteralPath (Join-Path $root 'hguard-bin') -TotalCount 1 -Encoding UTF8
  if ($line -and $line.Trim()) { $bin = $line.Trim() }
} catch {}
$timeout = 20
try {
  $line = Get-Content -LiteralPath (Join-Path $root 'hguard-timeout') -TotalCount 1 -Encoding UTF8
  if ($line -and $line.Trim() -match '^[0-9]+$') { $timeout = [int]$line.Trim() }
} catch {}
try {
  $in = [Console]::In.ReadToEnd()
  # Windows PowerShell 5.1 把原生程序重定向的 stderr 也当作错误记录，Stop 下第一条就终止、有效的回答被换成 ask；
  # 调用时用 Continue。找不到 h-guard 时 $LASTEXITCODE 不是 0，照样输出 ask
  $ErrorActionPreference = 'Continue'
  $out = $in | & $bin hook claudecode --event PreToolUse --timeout $timeout 2>$null
  if ($LASTEXITCODE -eq 0) {
    [Console]::Out.Write(($out -join "`n"))
    exit 0
  }
} catch {}
[Console]::Out.WriteLine($ask)
exit 0
