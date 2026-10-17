package eval_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/cyberchen1995/h-guard/internal/eval"
)

// TestOutboundReportBlockedAndExtra：报告分开「整条已被本地拦下」与「漏过去」：本地按别的类别 deny 了整条时，没认出的
// 类别标明「text blocked by local rules」，不算漏过去；另数应识别出的文本上多标的类别（M4b 终审 I-2）。
func TestOutboundReportBlockedAndExtra(t *testing.T) {
	outs := []eval.OutboundOutcome{
		{Case: eval.OutboundCase{Text: "a", Source: "prompt", Expect: []string{"credentials"}, Split: eval.SplitTune, Note: "blocked"}, Local: []string{"pii"}, Blocked: true},
		{Case: eval.OutboundCase{Text: "b", Source: "prompt", Expect: []string{"credentials"}, Split: eval.SplitTune, Note: "slipped"}, Sent: true, P: map[string]float64{"credentials": 0.1}},
		{Case: eval.OutboundCase{Text: "c", Source: "prompt", Expect: []string{"pii"}, Split: eval.SplitTune, Note: "caught"}, Sent: true, P: map[string]float64{"pii": 0.9, "credentials": 0.7}},
	}
	s := eval.ScoreOutbound(outs, 0.5, "")
	if s.Slipped != 1 || s.LeakCases != 3 || s.LocalSlipped != 2 || s.Extra != 2 || s.LocalExtra != 1 {
		t.Errorf("score %+v", s)
	}
	var buf bytes.Buffer
	eval.WriteOutboundReport(&buf, outs, 0.5)
	for _, want := range []string{"missed credentials (text blocked by local rules)", "slipped through, local only", "slipped through, local + judge", "extra categories flagged"} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("report lacks %q:\n%s", want, buf.String())
		}
	}
}
