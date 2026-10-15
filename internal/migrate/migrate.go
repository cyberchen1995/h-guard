// Package migrate 把 Python 版的 questions.json 转成 Go 版的配置与规则包（spec §9、§12 migrate）。
//
// 旧版的配置文件是整份替换的（h-guard config --init 复制出厂文件再改），所以只迁移相对出厂文件（内嵌的
// python_questions.json）的改动：没改的部分由 Go 版的内置规则与默认值覆盖（它们更严）。没有对应的设置不迁移，
// 逐条说明。
package migrate

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/cyberchen1995/h-guard/internal/install"
	"github.com/cyberchen1995/h-guard/internal/rules"
)

// pythonDefault 是 Python 版最后的出厂 questions.json（h-guard.old a9a258f，2026-09-21）。
//
//go:embed python_questions.json
var pythonDefault []byte

// 更早发布的出厂版本（h-guard.old e81f231、473786b，同一天）。用户的文件是从某个版本复制来的：与任一版本相同的
// 部分都算没改，否则没改过的旧写法会被当成用户的改动迁移成规则（终审 I-1）。
var (
	//go:embed python_questions_473786b.json
	python473786b []byte
	//go:embed python_questions_e81f231.json
	pythonE81f231 []byte
)

// Result 是迁移的结果：Config 写进 config.yaml，Rules 是规则包（文件名 → 内容，写进规则目录），Notes 是没有迁移
// 或需要用户留意的地方，Skipped 是迁移不了的规则（可能是用户自己的 deny 规则：调用方据此拒绝写入）。
type Result struct {
	Config  []install.Value
	Rules   map[string][]byte
	Notes   []string
	Skipped []string
}

// lockedIDs 是 Go 版的硬规则：内容不能被同 id 的用户规则覆盖。
var lockedIDs = []string{"catastrophic", "fork_bomb", "guard_tampering"}

type questions struct {
	Version       json.Number                `json:"version"`
	Model         string                     `json:"model"`
	Policy        map[string]json.RawMessage `json:"policy"`
	Rules         map[string]json.RawMessage `json:"rules"`
	PatternsExtra map[string]json.RawMessage `json:"patterns_extra"`
	Signals       map[string]json.RawMessage `json:"signals"`
}

func parse(b []byte) (questions, error) {
	var q questions
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	if err := dec.Decode(&q); err != nil {
		return q, fmt.Errorf("not a questions.json: %w", err)
	}
	if q.Version != "" && q.Version != "1" {
		return q, fmt.Errorf("questions.json version %s is not supported", q.Version)
	}
	return q, nil
}

// Convert 迁移 questions.json 的内容。
func Convert(data []byte) (Result, error) {
	user, err := parse(data)
	if err != nil {
		return Result{}, err
	}
	var bases []questions // 新的在前；bases[0] 是最后的出厂版本
	for _, b := range [][]byte{pythonDefault, python473786b, pythonE81f231} {
		q, err := parse(b)
		if err != nil {
			return Result{}, err
		}
		bases = append(bases, q)
	}
	base := bases[0]
	factory := func(pick func(questions) (json.RawMessage, bool)) []json.RawMessage {
		var out []json.RawMessage
		for _, b := range bases {
			if v, ok := pick(b); ok {
				out = append(out, v)
			}
		}
		return out
	}
	unchanged := func(v json.RawMessage, olds []json.RawMessage) bool {
		return slices.ContainsFunc(olds, func(o json.RawMessage) bool { return sameJSON(o, v) })
	}
	r := Result{Rules: map[string][]byte{}}
	note := func(format string, args ...any) { r.Notes = append(r.Notes, fmt.Sprintf(format, args...)) }
	set := func(path, value, tag string) {
		r.Config = append(r.Config, install.Value{Path: strings.Split(path, "."), Value: value, Tag: tag})
	}

	// 规则：rules 与 patterns_extra（没有题的纯正则规则）
	baseRules, userRules := merged(base), merged(user)
	// 生成的 id 不能与用户自己的规则相撞（计划评审 M3D-06）
	used := map[string]bool{}
	for id := range userRules {
		used[id] = true
	}
	unique := func(base string) string {
		id := base
		for n := 2; used[id]; n++ {
			id = fmt.Sprintf("%s_%d", base, n)
		}
		used[id] = true
		return id
	}
	for _, id := range slices.Sorted(maps.Keys(userRules)) {
		raw := userRules[id]
		olds := factory(func(q questions) (json.RawMessage, bool) { v, ok := merged(q)[id]; return v, ok })
		builtin := len(olds) > 0
		if unchanged(raw, olds) {
			continue
		}
		if old, ok := closestDetection(id, olds, raw); ok {
			// 只改了不影响本地检测的字段：整条覆盖会丢掉 PowerShell 写法与 Go 版的修正，所以逐项说明
			noteFieldChanges(id, old, raw, note)
			continue
		}
		outID := id
		switch {
		case slices.Contains(lockedIDs, id):
			outID = unique(id + "_migrated")
			note("%s is a locked built-in rule and cannot be overridden; your version is written as %s and the built-in rule stays", id, outID)
		case builtin:
			note("%s: overrides the built-in rule with your version; the built-in PowerShell patterns and later fixes no longer apply to it", id)
		}
		b, err := rulePack(outID, raw, note)
		if err != nil {
			note("%s: skipped (%v)", id, err)
			r.Skipped = append(r.Skipped, id)
			continue
		}
		r.Rules[outID+".yaml"] = b
	}
	// 文件里没有的规则不停用：旧版 config --init 复制的是当时的出厂文件，早期版本本来就没有后来加的规则（如
	// guard_tampering），据此停用会关掉保护（审查 C1）。只说明，要停用由用户自己写进配置。
	for _, id := range slices.Sorted(maps.Keys(baseRules)) {
		if _, ok := userRules[id]; !ok {
			note("%s is not in your questions.json (it was copied from an older version, or you removed it); h-guard keeps it on. To turn it off, add rules: {%s: {enabled: false}} to the config", id, id)
		}
	}

	// policy
	for _, k := range slices.Sorted(maps.Keys(user.Policy)) {
		if strings.HasPrefix(k, "_") {
			continue
		}
		v, old := user.Policy[k], base.Policy[k]
		if unchanged(v, factory(func(q questions) (json.RawMessage, bool) { v, ok := q.Policy[k]; return v, ok })) {
			continue
		}
		switch k {
		case "when_ask_unsupported", "on_unavailable":
			var s string
			if json.Unmarshal(v, &s) != nil {
				note("policy.%s is not a string; not migrated", k)
				continue
			}
			set("policy."+k, s, "!!str")
			if k == "when_ask_unsupported" && s == "pass" {
				note("policy.when_ask_unsupported: pass lets the action through on harnesses that cannot ask (Codex); the default is deny")
			}
		case "request_window", "max_command_chars", "max_request_chars":
			var n json.Number
			if json.Unmarshal(v, &n) != nil {
				note("policy.%s is not a number; not migrated", k)
				continue
			}
			set("policy."+k, n.String(), "!!int")
		case "hit_threshold", "regex_veto_threshold", "requested_threshold":
			note("policy.%s: thresholds now belong to a calibrated profile per backend and are not migrated; calibrate with h-guard eval --backend <name> --sweep if the built-in profile does not suit you", k)
		case "guarded_tools", "path_guarded_tools":
			note("policy.%s has no counterpart: h-guard now checks every tool the harness reports; not migrated", k)
		case "protected_paths":
			if err := protectedPaths(&r, v, old, unique("migrated_protected_paths"), note); err != nil {
				note("policy.protected_paths: skipped (%v)", err)
			}
		default:
			note("policy.%s is unknown; not migrated", k)
		}
	}
	if user.Model != "" && !slices.ContainsFunc(bases, func(q questions) bool { return q.Model == user.Model }) {
		// 只有 model 来自旧配置；其余字段让 jev 后端完整（配置按后端名整条合并），用户已经写下的保留（M3d 终审 M-3）
		set("backends.jev.model", user.Model, "!!str")
		for _, kv := range [][2]string{{"type", "typesafe"}, {"profile", "jev"}, {"api_key_env", "TYPESAFE_API_KEY"}} {
			r.Config = append(r.Config, install.Value{Path: []string{"backends", "jev", kv[0]}, Value: kv[1], Tag: "!!str", KeepExisting: true})
		}
		note("model %s: the built-in jev profile is calibrated for %s, so conservative thresholds are used until you calibrate", user.Model, base.Model)
	}
	for _, id := range slices.Sorted(maps.Keys(user.Signals)) {
		if !unchanged(user.Signals[id], factory(func(q questions) (json.RawMessage, bool) { v, ok := q.Signals[id]; return v, ok })) {
			note("signals.%s: the signal questions are built in and fixed (the calibration depends on their wording); not migrated", id)
		}
	}
	return r, nil
}

// sameDetection 报告两条规则的本地检测是否相同：动作、正则、命令位置、去引号。
// closestDetection 在出厂版本里找检测写法与 raw 相同的那一版；有几版都相同时取需要说明的字段最少的，说明只针对
// 用户真正改过的地方（终审 I-1）。
func closestDetection(id string, olds []json.RawMessage, raw json.RawMessage) (json.RawMessage, bool) {
	var best json.RawMessage
	fewest := -1
	for _, o := range olds {
		if !sameDetection(o, raw) {
			continue
		}
		n := 0
		noteFieldChanges(id, o, raw, func(string, ...any) { n++ })
		if fewest < 0 || n < fewest {
			best, fewest = o, n
		}
	}
	return best, fewest >= 0
}

func sameDetection(a, b json.RawMessage) bool {
	var x, y oldRule
	if json.Unmarshal(a, &x) != nil || json.Unmarshal(b, &y) != nil {
		return false
	}
	action := func(s string) string {
		if s == "" {
			return "ask"
		}
		return s
	}
	return action(x.Action) == action(y.Action) && slices.Equal(x.Regex, y.Regex) && x.CommandPosition == y.CommandPosition && x.StripQuotes == y.StripQuotes
}

// noteFieldChanges 说明内置规则里没有迁移的改动。
func noteFieldChanges(id string, a, b json.RawMessage, note func(string, ...any)) {
	var x, y oldRule
	_ = json.Unmarshal(a, &x)
	_ = json.Unmarshal(b, &y)
	if x.Reason != y.Reason {
		note("%s: reason: the built-in reason text is used; yours is not migrated", id)
	}
	if !reflect.DeepEqual(x.Threshold, y.Threshold) && y.Threshold != nil {
		note("%s: threshold %s has no counterpart (thresholds belong to the backend's profile); not migrated", id, strconv.FormatFloat(*y.Threshold, 'g', -1, 64))
	}
	if x.RadiusFloor != y.RadiusFloor {
		note("%s: radius_floor %s is not migrated; set it in the backend's profile (profiles.<name>.thresholds.radius_floor)", id, strconv.FormatFloat(y.RadiusFloor, 'g', -1, 64))
	}
	if !reflect.DeepEqual(x.BypassableByRequest, y.BypassableByRequest) {
		note("%s: bypassable_by_request is not migrated; to keep your setting, copy the built-in rule into your rules directory and change it there", id)
	}
	if !sameJSON(x.Question, y.Question) {
		note("%s: question: the built-in question wording is fixed (the calibration depends on it); yours is not migrated", id)
	}
}

func merged(q questions) map[string]json.RawMessage {
	m := maps.Clone(q.Rules)
	if m == nil {
		m = map[string]json.RawMessage{}
	}
	maps.Copy(m, q.PatternsExtra)
	return m
}

// sameJSON 按取值比较两段 JSON（键的顺序与空白不算）。
func sameJSON(a, b json.RawMessage) bool {
	var x, y any
	if json.Unmarshal(a, &x) != nil || json.Unmarshal(b, &y) != nil {
		return bytes.Equal(a, b)
	}
	p, _ := json.Marshal(x)
	q, _ := json.Marshal(y)
	return bytes.Equal(p, q)
}

type oldRule struct {
	Action              string          `json:"action"`
	Reason              string          `json:"reason"`
	Regex               []string        `json:"regex"`
	Question            json.RawMessage `json:"question"`
	Threshold           *float64        `json:"threshold"`
	RadiusFloor         float64         `json:"radius_floor"`
	BypassableByRequest *bool           `json:"bypassable_by_request"`
	CommandPosition     bool            `json:"command_position"`
	StripQuotes         bool            `json:"strip_quotes"`
}

type oldQuestion struct {
	Type         string `json:"type"`
	Instructions struct {
		Question    string `json:"question"`
		CountsAsYes string `json:"counts_as_yes"`
		CountsAsNo  string `json:"counts_as_no"`
	} `json:"instructions"`
	Criteria map[string]string `json:"criteria"`
}

type pack struct {
	Schema        int               `yaml:"schema"`
	ID            string            `yaml:"id"`
	Action        string            `yaml:"action"`
	On            []string          `yaml:"on,flow"`
	RequiresJudge bool              `yaml:"requires_judge,omitempty"`
	Reason        map[string]string `yaml:"reason"`
	Match         packMatch         `yaml:"match"`
	RadiusFloor   float64           `yaml:"radius_floor,omitempty"`
	Bypassable    *bool             `yaml:"bypassable_by_request,omitempty"`
	Vetoable      *bool             `yaml:"vetoable_by_judge,omitempty"`
	Question      *packQuestion     `yaml:"question,omitempty"`
}

type packMatch struct {
	Exec *packExec `yaml:"exec,omitempty"`
	File *packFile `yaml:"file,omitempty"`
}

type packExec struct {
	Any             []string `yaml:"any"`
	CommandPosition bool     `yaml:"command_position,omitempty"`
	StripQuotes     bool     `yaml:"strip_quotes,omitempty"`
}

type packFile struct {
	Paths []string `yaml:"paths"`
}

type packQuestion struct {
	Kind         string `yaml:"kind"`
	Instructions struct {
		Question    string `yaml:"question"`
		CountsAsYes string `yaml:"counts_as_yes"`
		CountsAsNo  string `yaml:"counts_as_no"`
	} `yaml:"instructions"`
	Criteria map[string]string `yaml:"criteria"`
}

// rulePack 把一条旧规则写成规则包，并按用户规则的要求校验（正则编译、字段约束）。
func rulePack(id string, raw json.RawMessage, note func(string, ...any)) ([]byte, error) {
	var o oldRule
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&o); err != nil {
		return nil, err
	}
	p := pack{Schema: rules.SchemaVersion, ID: id, Action: o.Action, On: []string{"exec"},
		Reason: map[string]string{"en": o.Reason, "zh-CN": o.Reason}, RadiusFloor: o.RadiusFloor, Bypassable: o.BypassableByRequest,
		Match: packMatch{Exec: &packExec{CommandPosition: o.CommandPosition, StripQuotes: o.StripQuotes}}}
	if p.Action == "" {
		p.Action = "ask"
	}
	for _, re := range o.Regex {
		p.Match.Exec.Any = append(p.Match.Exec.Any, goRegex(re))
	}
	if len(o.Question) > 0 && string(o.Question) != "null" {
		var q oldQuestion
		if err := json.Unmarshal(o.Question, &q); err != nil {
			return nil, err
		}
		if q.Type != "noul" {
			return nil, fmt.Errorf("question type %q is not supported; only yes/no (noul) questions carry over", q.Type)
		}
		pq := &packQuestion{Kind: "probability", Criteria: q.Criteria}
		pq.Instructions.Question, pq.Instructions.CountsAsYes, pq.Instructions.CountsAsNo = q.Instructions.Question, q.Instructions.CountsAsYes, q.Instructions.CountsAsNo
		p.Question, p.RequiresJudge = pq, true
	}
	if o.Threshold != nil {
		note("%s: threshold %s has no counterpart (thresholds belong to the backend's profile); not migrated", id, strconv.FormatFloat(*o.Threshold, 'g', -1, 64))
	}
	b, err := marshalPack(p)
	if err != nil {
		return nil, err
	}
	if _, err := rules.ParseUser(b, id+".yaml"); err != nil {
		var re *rules.Error
		if errors.As(err, &re) {
			return nil, errors.New(re.Brief())
		}
		return nil, err
	}
	note("%s: the English reason is a copy of the Chinese one; edit reason.en in %s.yaml", id, id)
	return b, nil
}

func marshalPack(p pack) ([]byte, error) {
	var b bytes.Buffer
	b.WriteString("# Migrated from questions.json by h-guard migrate.\n")
	enc := yaml.NewEncoder(&b)
	enc.SetIndent(2)
	if err := enc.Encode(p); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

var (
	pyNamedGroup = regexp.MustCompile(`\(\?P<`)
	pyBackref    = regexp.MustCompile(`\(\?P=(\w+)\)`)
	pyEnd        = regexp.MustCompile(`(^|[^\\])((?:\\\\)*)\\Z`)
)

// goRegex 把 Python re 的写法换成 regexp2 的：(?P<n>…) → (?<n>…)，(?P=n) → \k<n>，\Z（绝对末尾）→ \z。
// 其余写法两者一致（大小写不敏感、负向前瞻、(?-i:…)）；仍然编译不了的规则由校验报出、跳过。
func goRegex(re string) string {
	re = pyNamedGroup.ReplaceAllString(re, "(?<")
	re = pyBackref.ReplaceAllString(re, `\k<$1>`)
	return pyEnd.ReplaceAllString(re, `$1$2\z`)
}

// protectedPaths 把新增的保护路径写成一条文件规则（与护栏自我保护相同：不能凭授权放行，模型不能否决）；
// 去掉的出厂路径仍由内置的护栏自我保护覆盖，说明。
func protectedPaths(r *Result, raw, old json.RawMessage, id string, note func(string, ...any)) error {
	var cur, base []string
	if err := json.Unmarshal(raw, &cur); err != nil {
		return err
	}
	_ = json.Unmarshal(old, &base)
	var extra []string
	for _, p := range cur {
		if !slices.Contains(base, p) {
			extra = append(extra, p)
		}
	}
	for _, p := range base {
		if !slices.Contains(cur, p) {
			note("policy.protected_paths: %s was removed, but the built-in guard_tampering rule still protects it", p)
		}
	}
	if len(extra) == 0 {
		return nil
	}
	no := false
	p := pack{Schema: rules.SchemaVersion, ID: id, Action: "ask", On: []string{"file_write", "file_delete", "file_rename"},
		Reason:     map[string]string{"en": "Changes a path you protected in h-guard's Python version", "zh-CN": "改动在 Python 版中保护的路径"},
		Match:      packMatch{File: &packFile{Paths: extra}},
		Bypassable: &no, Vetoable: &no}
	b, err := marshalPack(p)
	if err != nil {
		return err
	}
	if _, err := rules.ParseUser(b, p.ID+".yaml"); err != nil {
		return err
	}
	r.Rules[p.ID+".yaml"] = b
	note("policy.protected_paths: %s written as the file rule %s (commands that touch them are not covered)", strings.Join(extra, ", "), p.ID)
	return nil
}
