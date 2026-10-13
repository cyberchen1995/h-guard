package app

import (
	"errors"
	"io"

	"github.com/cyberchen1995/h-guard/internal/check/action"
	"github.com/cyberchen1995/h-guard/internal/config"
	"github.com/cyberchen1995/h-guard/internal/consent"
	"github.com/cyberchen1995/h-guard/internal/rules"
	"github.com/cyberchen1995/h-guard/pkg/detect/secrets"
	"github.com/cyberchen1995/h-guard/pkg/judge"
)

// judgeState 是配置的判断后端在这次运行中的状态：能否调用、同意与校准情况。hook、check 与 status 共用。
type judgeState struct {
	name     string
	typ      string
	backend  judge.Backend // 构造失败时为 nil
	identity consent.Identity
	// consent 是同意状态：granted、missing、changed（同名后端的同意绑定的是另一个身份或不含 action 范围）、
	// unavailable（后端说不出自己的目标，或配置目录取不到）
	consent    string
	record     *consent.Record // 同名后端的同意记录
	thresholds config.Thresholds
	cal        config.Calibration
	err        error // 后端构造失败的原因
}

// 同意状态。
const (
	consentGranted     = "granted"
	consentMissing     = "missing"
	consentChanged     = "changed"
	consentUnavailable = "unavailable"
)

// inspectJudge 构造配置的后端 name，核对同意（范围 action）并按档案与指纹选出阈值。只构造对象，不发请求。
func (s setup) inspectJudge(o Options, name string) judgeState {
	st := judgeState{name: name, typ: s.cfg.Backends[name].Type, consent: consentUnavailable}
	b, err := s.cfg.NewBackend(name)
	if err != nil {
		st.err = err
		return st
	}
	if d, ok := b.(interface{ SetDir(string) }); ok && o.ConfigDir != "" {
		d.SetDir(o.ConfigDir) // exec 程序的工作目录是 h-guard 配置目录（spec §8.4）
	}
	st.backend = b
	st.thresholds, st.cal = s.cfg.ThresholdsFor(name, b, builtinDigest())
	id, ok := consent.IdentityOf(name, st.typ, b)
	if !ok || o.ConfigDir == "" {
		return st
	}
	st.identity = id
	store := consent.Store{Dir: o.ConfigDir}
	records, err := store.Load()
	if err != nil {
		st.consent = consentMissing // 损坏或版本不认识的记录视为没有同意
		return st
	}
	st.consent = consentMissing
	for i, r := range records {
		if r.Backend == name {
			st.record = &records[i]
			st.consent = consentChanged
		}
	}
	if store.Covers(id, consent.ScopeAction) {
		st.consent = consentGranted
	}
	return st
}

// actionJudge 是 hook 与 check 的判断层（spec §8.5）：模型开启、后端可建、同意有效时才调用后端，
// 否则按同意缺失处理（judge_consent_missing，正则命中即请求确认）。
func (s setup) actionJudge(o Options) (action.Judge, judgeState) {
	if !s.cfg.Judge.Enabled {
		return action.Judge{}, judgeState{}
	}
	st := s.inspectJudge(o, s.cfg.Judge.Backend)
	if st.backend == nil || st.consent != consentGranted {
		return action.Judge{Unavailable: action.FallbackConsentMissing}, st
	}
	th := st.thresholds
	return action.Judge{Backend: st.backend, Thresholds: &th}, st
}

// builtinDigest 返回内置题集的指纹（spec §8.3：档案指纹只覆盖内置规则与信号题）。内置规则包编进二进制，
// 加载失败只能是构建错误，此时返回空串，任何档案都不匹配（按未校准处理）。
func builtinDigest() string {
	set, err := rules.Builtin()
	if err != nil {
		return ""
	}
	return config.QuestionsDigest(action.QuestionSet(set))
}

// ownQuestions 返回启用的、带自己题目的用户规则（含覆盖内置规则的）：它们的题目不在校准指纹内（spec §8.3）。
func (s setup) ownQuestions() []string {
	var ids []string
	for _, r := range s.rules.All() {
		if _, ok := r.JudgeQuestion(); ok && !r.Builtin && r.Enabled() {
			ids = append(ids, r.ID)
		}
	}
	return ids
}

// shown 遮蔽显示用的文本中本地能识别的凭据形状（评审 M2-07、R2-03）。只用于显示，打开文件等实际操作用原值。
// CLI 命令的输出另外整体经过 maskingWriter，所以这里只是让单个值在拼接前就已遮蔽。
func shown(s string) string { return secrets.MaskForLog(s) }

// maskingWriter 是 CLI 输出的最终边界：每次写入的文本先经 secrets.MaskForLog（评审 R3-02）。
// fmt 的每次调用写入一次，一个值不会被拆到两次写入里；MaskForLog 可重复调用，已遮蔽的内容不变。
type maskingWriter struct{ w io.Writer }

func (m maskingWriter) Write(p []byte) (int, error) {
	if _, err := io.WriteString(m.w, secrets.MaskForLog(string(p))); err != nil {
		return 0, err
	}
	return len(p), nil
}

// errNoTerminal 表示需要交互确认的命令不在终端里运行（spec §8.5：非交互终端拒绝）。
var errNoTerminal = errors.New("this command asks for confirmation and must run in an interactive terminal")
