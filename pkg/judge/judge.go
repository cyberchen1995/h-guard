// Package judge 定义判断后端接口、问题与答案类型。
//
// 后端只负责「问」：把问题交给模型并取回概率。答案校验、阈值与策略由 h-guard 框架处理。
package judge

import (
	"context"
	"slices"
)

// Kind 是题型。
type Kind string

const (
	KindProbability Kind = "probability" // 回答一个 [0, 1] 概率
	KindScale       Kind = "scale"       // 回答各级别上的分布
)

// Instructions 是发给模型的问题措辞，固定为英文（阈值依赖措辞）。
type Instructions struct {
	Question    string            `json:"question"`
	CountsAsYes string            `json:"counts_as_yes,omitempty"`
	CountsAsNo  string            `json:"counts_as_no,omitempty"`
	Criteria    map[string]string `json:"criteria,omitempty"`
}

// Question 是一道判断题。
type Question struct {
	ID           string       `json:"id"`
	Kind         Kind         `json:"kind"`
	Instructions Instructions `json:"instructions"`
	Levels       []string     `json:"levels,omitempty"` // 仅 KindScale
}

// Answer 是一道题的答案：KindProbability 用 P，KindScale 用 Dist。
// nil 表示没有给出，与明确的 0 区分：JSON 中 {} 与 {"p": null} 都解码为 P == nil。
type Answer struct {
	P    *float64  `json:"p,omitempty"`
	Dist []float64 `json:"dist,omitempty"`
}

// Prob 返回指向 v 的指针，便于构造 Answer{P: Prob(0.3)}。
func Prob(v float64) *float64 { return &v }

// Usage 是一次请求的用量。
type Usage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}

// Response 是一次请求的结果。缺题只当该题未答。
type Response struct {
	Answers map[string]Answer `json:"answers"`
	Model   string            `json:"model,omitempty"`
	Usage   Usage             `json:"usage"`
}

// Mechanism 是后端取得答案的方式，只供显示与诊断（status、backend list）。能力校验只看
// BackendCaps.Kinds，不看 Mechanism。不同方式给出的概率分布不同，阈值要分别校准；
// 校准指纹以 Info.Probability 区分方式，Mechanism 不进入指纹。
type Mechanism string

const (
	MechanismNative     Mechanism = "native"      // 服务端原生给出概率（typesafe）
	MechanismLogprobs   Mechanism = "logprobs"    // 读模型作答位置候选字符的 logprob
	MechanismJSONSchema Mechanism = "json_schema" // 结构化输出：OpenAI response_format、Anthropic output_config.format
	MechanismForcedTool Mechanism = "forced_tool" // 强制模型调用参数为答案的工具
	MechanismAutoTool   Mechanism = "auto_tool"   // 提供答案工具但不强制调用：模型没有调用即没有答案
	MechanismProgram    Mechanism = "program"     // 外部程序（exec），取答方式由程序决定
)

// BackendCaps 声明后端能力。
type BackendCaps struct {
	Calibrated bool `json:"calibrated"` // 概率经过校准（如原生概率模型）
	Batch      bool `json:"batch"`      // 一次请求能回答多道题
	// Mechanism 是取答方式。内置后端都声明它，judgetest 要求非空。
	Mechanism Mechanism `json:"mechanism,omitempty"`
	// Kinds 是能回答的题型。nil 表示全部（兼容没有声明它的后端）；空切片（非 nil）表示一种都不支持。
	// AskAll 不把不支持的题型发给后端，这些题保持未答，不能产生放行。JSON 不省略空切片：
	// 省略后解码为 nil，「一种都不支持」就成了「全部支持」。
	Kinds []Kind `json:"kinds"`
}

// Supports 报告后端能否回答 k 型的题；Kinds 为 nil 时总为真。
func (c BackendCaps) Supports(k Kind) bool { return c.Kinds == nil || slices.Contains(c.Kinds, k) }

// Backend 是判断后端。
type Backend interface {
	Name() string
	Caps() BackendCaps
	// Ask 必须遵守 ctx 的截止时间：ctx 结束后尽快返回错误。
	// 返回的答案只能以 qs 中的题目 ID 为键。
	Ask(ctx context.Context, state map[string]any, qs []Question) (Response, error)
}

// Info 描述后端：数据发往哪里，用什么模型与概率获取方式。都不含凭据。
type Info struct {
	// Target 是数据的去向：HTTP 后端为 scheme://host:port，exec 后端为程序的绝对路径与参数。同意记录绑定它。
	Target string
	// Model 是配置里的模型标识；Probability 是概率获取方式（native、logprobs、verbalized）。校准指纹绑定这两项。
	Model, Probability string
}

// Describer 是后端的可选接口。只有实现了它的后端才能记录同意与校准：不知道数据发往哪里就无法征得同意。
type Describer interface {
	Describe() Info
}
