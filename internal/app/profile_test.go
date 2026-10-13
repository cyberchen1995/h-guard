package app

import (
	"testing"

	"github.com/cyberchen1995/h-guard/internal/config"
)

// TestBuiltinProfileMatchesTheQuestions：内置 jev 档案的指纹与当前内置题集一致。改了题目措辞（或信号题）却没有
// 重新校准时失败：先用 h-guard eval --backend jev --sweep 重新校准，再更新 default.yaml（spec §8.3）。
func TestBuiltinProfileMatchesTheQuestions(t *testing.T) {
	cfg := config.Defaults()
	b, err := cfg.NewBackend("jev")
	if err != nil {
		t.Fatal(err)
	}
	th, cal := cfg.ThresholdsFor("jev", b, builtinDigest())
	if !cal.Calibrated() {
		t.Fatalf("the built-in jev profile is uncalibrated (%s); recalibrate with h-guard eval --backend jev --sweep", cal.Reason)
	}
	p := cfg.Profiles["jev"].Thresholds
	if th.Hit != *p.Hit || th.Veto != *p.Veto || th.Requested != *p.Requested {
		t.Errorf("thresholds %+v do not come from the profile %+v", th, p)
	}
}
