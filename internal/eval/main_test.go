package eval_test

import (
	"os"
	"testing"

	"github.com/cyberchen1995/h-guard/internal/rules"
)

// TestMain：评估回放规则不受延迟约束，正则匹配用宽松的超时。hook 里的 100 毫秒在 -race 与高负载下会偶尔超时
// （超时按命中处理），两次相同的回放结论不同，自助抽样、阈值扫描与边际的结论随之变化。
func TestMain(m *testing.M) {
	rules.SetMatchTimeout(rules.ReplayMatchTimeout)
	os.Exit(m.Run())
}
