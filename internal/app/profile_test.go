package app

import (
	"maps"
	"slices"
	"testing"

	"github.com/cyberchen1995/h-guard/internal/check/outbound"
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
// 先用 h-guard eval --backend <名字> --sweep 重新校准，再更新 default.yaml。
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

// TestBuiltinOutboundProfiles：写了 outbound 门槛的内置档案必须按当前的 outbound 题集校准（fingerprint.outbound_questions
// 等于 outbound.BuiltinQuestionsDigest，模型与概率获取方式与后端一致）。改了 outbound 题目的措辞而不重新校准，这里会失败
// （与 TestBuiltinProfileMatchesTheQuestions 对 action 题集的要求相同）。
//
// builtinOutbound 列出带 outbound 门槛的内置后端与门槛：claude-haiku 在 153 条 outbound 语料上真实调用，
// 维护者采用 0.2（扫描的平台 0.15–0.25 的中间，2026-10-16）。
var builtinOutbound = map[string]float64{"claude-haiku": 0.2}

func TestBuiltinOutboundProfiles(t *testing.T) {
	cfg := config.Defaults()
	for _, name := range slices.Sorted(maps.Keys(cfg.Backends)) {
		p, ok := cfg.Profiles[cfg.Backends[name].Profile]
		if want, listed := builtinOutbound[name]; listed && (!ok || p.Thresholds.Outbound == nil || *p.Thresholds.Outbound != want) {
			t.Errorf("built-in backend %s should have outbound threshold %g", name, want)
		}
		if !ok || p.Thresholds.Outbound == nil {
			continue
		}
		if _, listed := builtinOutbound[name]; !listed {
			t.Errorf("built-in backend %s has an outbound threshold that builtinOutbound does not list", name)
		}
		b, err := cfg.NewBackend(name)
		if err != nil {
			t.Fatalf("built-in backend %s: %v", name, err)
		}
		if th, cal := cfg.OutboundThresholdFor(name, b, outbound.BuiltinQuestionsDigest); !cal.Calibrated() || th != *p.Thresholds.Outbound {
			t.Errorf("the outbound threshold of built-in profile %s is uncalibrated (%s); recalibrate with h-guard eval --outbound --backend %s --sweep",
				cfg.Backends[name].Profile, cal.Reason, name)
		}
	}
}
