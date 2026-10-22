package action_test

import (
	"os"
	"testing"

	"github.com/cyberchen1995/h-guard/internal/rules"
)

// TestMain：测试回放规则不受延迟约束，正则匹配用宽松的超时。hook 里的 100 毫秒在 -race 与高负载下会偶尔超时
// （超时按命中处理），同一条命令的结论随负载变化。要验证超时行为的测试用 productionMatchTimeout 换回 hook 的值。
func TestMain(m *testing.M) {
	rules.SetMatchTimeout(rules.ReplayMatchTimeout)
	os.Exit(m.Run())
}

// productionMatchTimeout 让本测试之后加载的规则用 hook 的正则超时，测试结束时恢复。须在加载规则（newCheck）之前调用。
func productionMatchTimeout(t *testing.T) {
	t.Cleanup(rules.SetMatchTimeout(rules.MatchTimeout))
}
