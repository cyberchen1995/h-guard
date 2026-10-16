package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestEvalOutboundThresholdAndSettings：--threshold 只按给定门槛报告（采纳的门槛不一定是扫描的建议，M4b 终审 M-6）；
// 报告写明评估的设置与默认配置的差别（M4b 终审 I-2）；不在 0..1 时是用法错误。
func TestEvalOutboundThresholdAndSettings(t *testing.T) {
	srv := newOutboundServer(t, 0.9)
	e := newEnv(t)
	e.outboundJudgeConfig(srv, "")
	cases := filepath.Join(t.TempDir(), "cases.jsonl")
	os.WriteFile(cases, []byte(`{"text":"`+strings.Repeat("weekly planning notes ", 20)+`","source":"prompt","expect":[],"split":"tune"}`+"\n"), 0o600)
	out, errs, code := e.run(nil, "eval", "--outbound", "--yes", "--threshold", "0.2", "--cases", cases)
	if code != 0 || !strings.Contains(out, "(threshold 0.2)") || !strings.Contains(out, "evaluation settings: tier 3") || !strings.Contains(out, "PII on") {
		t.Errorf("exit %d\n%s\n%s", code, out, errs)
	}
	if _, _, code := e.run(nil, "eval", "--outbound", "--yes", "--threshold", "1.5", "--cases", cases); code != 2 {
		t.Errorf("threshold 1.5: exit %d", code)
	}
}

// TestStatusOwnCategoryQuestions：配置改写了类别题时 status 写明这些题不在校准指纹里（与 action 的「your rules … ask
// their own questions」相同，M4b 终审 M-5）。
func TestStatusOwnCategoryQuestions(t *testing.T) {
	srv := newOutboundServer(t, 0.9)
	e := newEnv(t)
	e.outboundJudgeConfig(srv, "outbound: {categories: {credentials: {question: {question: 'Secrets?'}}}}\n")
	if out, _, _ := e.run(nil, "status"); !strings.Contains(out, "your categories credentials ask their own questions") {
		t.Errorf("status = %s", out)
	}
}
