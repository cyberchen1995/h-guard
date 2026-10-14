package app

import (
	"maps"
	"slices"
	"testing"

	"github.com/cyberchen1995/h-guard/internal/config"
)

// builtinProfiles 是内置后端引用的档案；builtinUncalibrated 是故意还没有档案的内置后端。
// 两个表合起来必须覆盖 default.yaml 的全部后端：新增内置后端时要在这里明确归类。
var (
	builtinProfiles = map[string]string{"jev": "jev", "gemma4-local": "gemma4-local",
		"claude-haiku": "claude-haiku", "claude-sonnet": "claude-sonnet"}
	builtinUncalibrated = []string{}
)

// TestBuiltinProfileMatchesTheQuestions：每个引用了档案的内置后端，其档案的指纹都与当前内置题集及该后端的
// Describe 一致，阈值来自档案。改了题目措辞（或信号题）、后端的取答方式或内置模型却没有重新校准时失败：
// 先用 h-guard eval --backend <名字> --sweep 重新校准，再更新 default.yaml（spec §8.3）。
//
// 没有档案的内置后端（claude-haiku、claude-sonnet 在验收任务里用真实调用校准之前）当前必须是未校准的
// no_profile；为它们写入档案时，这个测试需要有意识地更新。
func TestBuiltinProfileMatchesTheQuestions(t *testing.T) {
	cfg := config.Defaults()
	digest := builtinDigest()
	if digest == "" {
		t.Fatal("the built-in question set could not be loaded")
	}
	names := slices.Sorted(maps.Keys(cfg.Backends))
	for _, name := range names {
		bc := cfg.Backends[name]
		b, err := cfg.NewBackend(name)
		if err != nil {
			t.Fatalf("built-in backend %s: %v", name, err)
		}
		th, cal := cfg.ThresholdsFor(name, b, digest)
		if bc.Profile == "" {
			if !slices.Contains(builtinUncalibrated, name) {
				t.Errorf("built-in backend %s has no profile; calibrate it (h-guard eval --backend %s --sweep) and add the profile, "+
					"or list it in builtinUncalibrated on purpose", name, name)
			}
			if cal.Reason != config.UncalibratedNoProfile {
				t.Errorf("%s has no profile and should resolve to %s, got %q; a profile was added: move %s from builtinUncalibrated to builtinProfiles",
					name, config.UncalibratedNoProfile, cal.Reason, name)
			}
			continue
		}
		if want, ok := builtinProfiles[name]; !ok || want != bc.Profile {
			t.Errorf("built-in backend %s refers to profile %q, which builtinProfiles does not expect (%q)", name, bc.Profile, want)
		}
		if !cal.Calibrated() {
			t.Errorf("the built-in profile %s of backend %s is uncalibrated (%s); recalibrate with h-guard eval --backend %s --sweep",
				bc.Profile, name, cal.Reason, name)
			continue
		}
		p := cfg.Profiles[bc.Profile].Thresholds
		if th.Hit != *p.Hit || th.Veto != *p.Veto || th.Requested != *p.Requested || !maps.Equal(th.RadiusFloor, p.RadiusFloor) {
			t.Errorf("%s: thresholds %+v do not come from the profile %+v", name, th, p)
		}
	}
	// 两个表里列出的后端都必须真的存在，改名或删除时不能悄悄跳过检查
	for name := range builtinProfiles {
		if _, ok := cfg.Backends[name]; !ok {
			t.Errorf("builtinProfiles lists %s, which is not a built-in backend", name)
		}
	}
	for _, name := range builtinUncalibrated {
		if _, ok := cfg.Backends[name]; !ok {
			t.Errorf("builtinUncalibrated lists %s, which is not a built-in backend", name)
		}
	}
}
