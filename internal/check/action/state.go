package action

import (
	"strconv"
	"unicode/utf8"

	"github.com/cyberchen1995/h-guard/pkg/detect/secrets"
)

// StateInput 是发给模型的 state 的原料。字段名对应问题里引用的 `call.command`、`call.cwd`、`user_requests`，
// 改名要连问题一起改。不放工具调用的 description：那是 agent 对命令的自述，不能当证据。
type StateInput struct {
	Harness         string
	Tool            string
	Command         string
	Cwd             string
	Requests        []string // 用户本人的指令，最新的在前，已按窗口截取
	MaxCommandChars int
	MaxRequestChars int
}

// BuildState 组装 state（Python 版 build_state）：先遮蔽凭据，再对超长文本做中间截断。
// truncated 为真表示命令或任一条指令被截断（spec §5.1 证据完整性）。
func BuildState(in StateInput) (state map[string]any, truncated bool) {
	cmd, cut := truncateMiddle(secrets.Redact(in.Command), in.MaxCommandChars)
	requests := make([]any, 0, len(in.Requests))
	for _, r := range in.Requests {
		t, c := truncateMiddle(secrets.Redact(r), in.MaxRequestChars)
		cut = cut || c
		requests = append(requests, t)
	}
	return map[string]any{
		"call": map[string]any{
			"harness": in.Harness,
			"tool":    in.Tool,
			"command": cmd,
			"cwd":     in.Cwd,
		},
		"user_requests": requests,
	}, cut
}

// truncateMiddle 超长时掐掉中间、保留首 2/3 与尾 1/3（按字符计，与 Python 版一致）：
// 命令的危险部分常在末尾（`&& rm -rf /`），只留开头会看漏。
func truncateMiddle(text string, limit int) (string, bool) {
	n := utf8.RuneCountInString(text)
	if n <= limit {
		return text, false
	}
	runes := []rune(text)
	head := limit * 2 / 3
	tail := limit - head
	dropped := n - head - tail
	return string(runes[:head]) + "…（中间省略 " + strconv.Itoa(dropped) + " 字）…" + string(runes[n-tail:]), true
}
