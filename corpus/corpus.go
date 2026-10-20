// Package corpus 内嵌 h-guard eval 的标注语料。commands.jsonl 每行一条：
// command、user_requests（按时间先后，旧的在前）、expect（pass / ask / deny）、rules（应识别出的规则）、note、
// 可选的 shell（默认 posix）。前 102 条取自 Python 版的语料，其后是「先要求、后撤回」用例。
// powershell.jsonl 是同样格式的 PowerShell 语料，每条的 shell 都是 powershell。
// outbound.jsonl 是 outbound 判断层的标注语料（h-guard eval --outbound）：每行有 text、source（prompt、tool_output）、
// 可选的 tool、expect（应识别出的类别，空表示可以发出去）、split（tune 用来定门槛，holdout 与 fresh 只报告）与 note。
// 全部自建、虚构，标签由维护者裁定；fresh 是题目措辞冻结之后追加的留出集。
// holdout.jsonl 是三种配置对比（h-guard eval --compare）用的留出步骤：每行一步，有 id、scenario、tool、
// command 或 path、可选的 user_requests 与 requested、expect、harm（危害类别）、basis（标注依据）与 note；
// 阈值扫描不读它。tasks/*.yaml 一个文件一条多步会话任务，同样由 --compare 重放：步骤字段与 holdout.jsonl 相同，
// 只是 id 与 scenario 可省（取自任务）；project.files 列出沙箱工程要预置的文件。
package corpus

import "embed"

// FS 是内嵌的语料文件。
//
//go:embed *.jsonl tasks/*.yaml
var FS embed.FS
