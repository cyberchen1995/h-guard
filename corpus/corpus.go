// Package corpus 内嵌 h-guard eval 的标注语料（spec §3.1、§8.3）。commands.jsonl 每行一条：
// command、user_requests（按时间先后，旧的在前）、expect（pass / ask / deny）、rules（应识别出的规则）、note、
// 可选的 shell（默认 posix）。前 102 条取自 Python 版的语料，其后是「先要求、后撤回」用例（spec §5.4）。
// powershell.jsonl 是同样格式的 PowerShell 语料（M3b，spec §5.3），每条的 shell 都是 powershell。
// outbound.jsonl 是 outbound 判断层的标注语料（M4b，h-guard eval --outbound）：每行有 text、source（prompt、tool_output）、
// 可选的 tool、expect（应识别出的类别，空表示可以发出去）、split（tune 用来定门槛，holdout 与 fresh 只报告）与 note。
// 全部自建、虚构，标签由维护者裁定；fresh 是题目措辞冻结之后追加的留出集。
package corpus

import "embed"

// FS 是内嵌的语料文件。
//
//go:embed *.jsonl
var FS embed.FS
