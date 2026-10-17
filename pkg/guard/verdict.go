package guard

// FindingSource 是命中的来源。
type FindingSource string

const (
	FindingLocal FindingSource = "local" // 本地规则
	FindingJudge FindingSource = "judge" // 判断层
	FindingBoth  FindingSource = "both"  // 两层都命中
)

// Location 是命中在文本或命令中的位置。
type Location struct {
	Line  int `json:"line"`  // 从 1 开始；0 表示未知
	Start int `json:"start"` // 字节偏移，含
	End   int `json:"end"`   // 字节偏移，不含
}

// Finding 是一条命中。
type Finding struct {
	Rule        string        `json:"rule"`               // 规则 id，如 publish、pii.email
	Category    string        `json:"category,omitempty"` // outbound 类别；action 规则为空
	Source      FindingSource `json:"source"`
	Probability *float64      `json:"probability,omitempty"` // 判断层给出的概率；纯本地命中为 nil
	Locations   []Location    `json:"locations,omitempty"`
}

// Reason 是结构化原因：消息键 + 参数，不含文本。
type Reason struct {
	Code   string            `json:"code"`
	Params map[string]string `json:"params,omitempty"`
}

// Verdict 是一个 Check 的结论。
type Verdict struct {
	Decision  Decision       `json:"decision"`
	Findings  []Finding      `json:"findings,omitempty"`
	Reasons   []Reason       `json:"reasons,omitempty"`
	Signals   map[string]any `json:"signals,omitempty"`
	Fallbacks []string       `json:"fallbacks,omitempty"` // 降级原因码，可有多个
}

// Outcome 是交给 adapter 渲染的最终结果。
type Outcome struct {
	Verdict Verdict  `json:"verdict"`           // 能力降级后的结论
	Raw     Decision `json:"raw"`               // 能力降级前的结论
	Message string   `json:"message,omitempty"` // 已本地化的原因
	Hint    string   `json:"hint,omitempty"`    // 已本地化的前进路径
}
