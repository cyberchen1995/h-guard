// Package corpus 内嵌 h-guard eval 的标注语料（spec §3.1、§8.3）。commands.jsonl 每行一条：
// command、user_requests（按时间先后，旧的在前）、expect（pass / ask / deny）、rules（应识别出的规则）、note、
// 可选的 shell（默认 posix）。前 102 条取自 Python 版的语料，其后是「先要求、后撤回」用例（spec §5.4）。
package corpus

import "embed"

// FS 是内嵌的语料文件。
//
//go:embed *.jsonl
var FS embed.FS
