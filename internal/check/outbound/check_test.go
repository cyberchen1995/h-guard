package outbound_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cyberchen1995/h-guard/internal/check/outbound"
	"github.com/cyberchen1995/h-guard/internal/config"
	"github.com/cyberchen1995/h-guard/internal/i18n"
	"github.com/cyberchen1995/h-guard/internal/rules"
	"github.com/cyberchen1995/h-guard/pkg/guard"

	// 内置后端的类型要注册，内置默认配置才能通过校验
	_ "github.com/cyberchen1995/h-guard/pkg/judge/anthropic"
	_ "github.com/cyberchen1995/h-guard/pkg/judge/exec"
	_ "github.com/cyberchen1995/h-guard/pkg/judge/openai"
	_ "github.com/cyberchen1995/h-guard/pkg/judge/typesafe"
)

// newCheck 用一份配置（version: 1 之后的内容）与用户规则包（文件名 → 内容）构造 Check，与 hook 一样按配置覆盖开关。
func newCheck(t testing.TB, cfgYAML string, userRules map[string]string) *outbound.Check {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "config.yaml")
	os.WriteFile(p, []byte("version: 1\n"+cfgYAML), 0o600)
	cfg, err := config.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	rulesDir := filepath.Join(dir, "rules")
	os.MkdirAll(rulesDir, 0o700)
	for name, body := range userRules {
		os.WriteFile(filepath.Join(rulesDir, name), []byte(body), 0o600)
	}
	set, err := rules.Load(rulesDir)
	if err != nil {
		t.Fatal(err)
	}
	ov := rules.Overrides{}
	for id := range cfg.Rules {
		if on, ok := cfg.RuleEnabled(id); ok {
			ov[id] = on
		}
	}
	if _, err := set.Apply(ov); err != nil {
		t.Fatal(err)
	}
	return &outbound.Check{Rules: set, Config: cfg}
}

func prompt(text string) guard.Event {
	return guard.Event{Kind: guard.EventPrompt, Harness: "h", Text: text}
}

func evaluate(t *testing.T, c *outbound.Check, ev guard.Event) (guard.Verdict, []guard.Verdict) {
	t.Helper()
	var commits []guard.Verdict
	v, err := c.Evaluate(context.Background(), ev, func(v guard.Verdict) { commits = append(commits, v) })
	if err != nil {
		t.Fatal(err)
	}
	return v, commits
}

// TestApplies：档位决定扫描范围（spec §4）：第 1 档只扫提示词，第 2 档加上文件内容的工具输出，第 3 档全部工具输出；
// 动作事件不归 outbound。
func TestApplies(t *testing.T) {
	file := guard.Event{Kind: guard.EventToolOutput, Harness: "h", FileContent: true}
	other := guard.Event{Kind: guard.EventToolOutput, Harness: "h"}
	action := guard.Event{Kind: guard.EventAction, Harness: "h", Actions: []guard.Action{{Kind: guard.ActionExec, Exec: &guard.ExecAction{Command: "ls", Shell: guard.ShellPOSIX}}}}
	for tier, want := range map[int][3]bool{1: {true, false, false}, 2: {true, true, false}, 3: {true, true, true}} {
		c := newCheck(t, "outbound: {tier: "+string(rune('0'+tier))+"}\n", nil)
		if got := [3]bool{c.Applies(prompt("x")), c.Applies(file), c.Applies(other)}; got != want {
			t.Errorf("tier %d: %v", tier, got)
		}
		if c.Applies(action) {
			t.Errorf("tier %d: applies to actions", tier)
		}
	}
}

// TestCredentialInPrompt：提示词里的凭据默认 deny：命中写明规则、类别与行号；原因只有类别、命中数与行号，不含原文
// （spec §6.3）；本地 deny 立即提交（spec §3.3）。
func TestCredentialInPrompt(t *testing.T) {
	c := newCheck(t, "", nil)
	text := "please deploy\nexport OPENAI_API_KEY=sk-abcdefghijklmnop1234\nand Bearer Ab3dEf6hIj9kLm2nOp5q too"
	v, commits := evaluate(t, c, prompt(text))
	if v.Decision != guard.DecisionDeny || len(commits) != 1 || commits[0].Decision != guard.DecisionDeny {
		t.Fatalf("verdict %+v, commits %+v", v, commits)
	}
	want := []guard.Finding{
		{Rule: "credentials.bearer", Category: "credentials", Source: guard.FindingLocal, Locations: []guard.Location{{Line: 3, Start: 71, End: 91}}},
		{Rule: "credentials.prefixed_token", Category: "credentials", Source: guard.FindingLocal, Locations: []guard.Location{{Line: 2, Start: 36, End: 59}}},
	}
	if !reflect.DeepEqual(v.Findings, want) {
		t.Errorf("findings = %+v", v.Findings)
	}
	if !reflect.DeepEqual(v.Reasons, []guard.Reason{{Code: i18n.KeyOutboundCredentials, Params: map[string]string{"count": "2", "lines": "2, 3"}},
		{Code: i18n.KeyHintOutbound}}) {
		t.Errorf("reasons = %+v", v.Reasons)
	}
	b, _ := json.Marshal(v)
	if strings.Contains(string(b), "sk-abcdefghijklmnop1234") || strings.Contains(string(b), "Ab3dEf6hIj9kLm2nOp5q") {
		t.Errorf("verdict leaks the value: %s", b)
	}
}

// TestPIICategory：PII 类别默认关闭；开启后命中即 deny；ignore 里的值不算（去掉首尾空白，邮箱不区分大小写）。
func TestPIICategory(t *testing.T) {
	text := "mail me at Alice.Wang@Acme-Corp.cn or call 13800138000"
	if v, _ := evaluate(t, newCheck(t, "", nil), prompt(text)); v.Decision != guard.DecisionPass {
		t.Errorf("pii off: %+v", v)
	}
	v, _ := evaluate(t, newCheck(t, "outbound: {categories: {pii: {enabled: true}}}\n", nil), prompt(text))
	if v.Decision != guard.DecisionDeny || len(v.Findings) != 2 || v.Reasons[0].Code != i18n.KeyOutboundPII || v.Reasons[0].Params["count"] != "2" {
		t.Errorf("pii on: %+v", v)
	}
	v, _ = evaluate(t, newCheck(t, "outbound: {categories: {pii: {enabled: true, ignore: [' alice.wang@acme-corp.cn ', '13800138000']}}}\n", nil), prompt(text))
	if v.Decision != guard.DecisionPass || len(v.Findings) != 0 {
		t.Errorf("ignored: %+v", v)
	}
	// 按 id 停用一条规则：只剩另一条
	v, _ = evaluate(t, newCheck(t, "outbound: {categories: {pii: {enabled: true}}}\nrules: {pii.email: {enabled: false}}\n", nil), prompt(text))
	if v.Decision != guard.DecisionDeny || len(v.Findings) != 1 || v.Findings[0].Rule != "pii.phone_cn" {
		t.Errorf("email disabled: %+v", v)
	}
}

// TestCategoryActions：类别的动作是 warn 时只提示；同时有 deny 与 warn 的类别时取 deny（spec §6.2）。自定义类别用用户
// 规则包的正则，原因写出类别名。
func TestCategoryActions(t *testing.T) {
	falcon := map[string]string{"falcon.yaml": "schema: 1\nid: acme.codename\ncategory: acme-codename\non: [prompt, tool_output]\n" +
		"match: {regex: ['\\bProject Falcon\\b']}\n"}
	c := newCheck(t, "outbound: {categories: {acme-codename: {action: warn}}}\n", falcon)
	v, commits := evaluate(t, c, prompt("status of project falcon?"))
	if v.Decision != guard.DecisionWarn || len(commits) != 0 ||
		!reflect.DeepEqual(v.Reasons[0], guard.Reason{Code: i18n.KeyOutboundCustom, Params: map[string]string{"category": "acme-codename", "count": "1", "lines": "1"}}) {
		t.Errorf("warn: %+v, commits %+v", v, commits)
	}
	if v, _ := evaluate(t, c, prompt("Project Falcon key: api_key=s3cr3tValue42")); v.Decision != guard.DecisionDeny || len(v.Reasons) != 3 {
		t.Errorf("deny and warn: %+v", v)
	}
	// 类别停用：规则不算
	c = newCheck(t, "outbound: {categories: {acme-codename: {enabled: false}}}\n", falcon)
	if v, _ := evaluate(t, c, prompt("project falcon")); v.Decision != guard.DecisionPass {
		t.Errorf("category disabled: %+v", v)
	}
}

// TestToolOutput：工具输出同样扫描（规则的 on 决定），只作用于提示词的规则不扫工具输出。
func TestToolOutput(t *testing.T) {
	onlyPrompt := map[string]string{"p.yaml": "schema: 1\nid: acme.prompt\ncategory: acme\non: [prompt]\nmatch: {regex: [falcon]}\n"}
	c := newCheck(t, "outbound: {tier: 3}\n", onlyPrompt)
	out := guard.Event{Kind: guard.EventToolOutput, Harness: "h", Tool: "Bash", Text: "DB=postgres://admin:s3cr3tP4ss@db:5432/app\nfalcon"}
	v, _ := evaluate(t, c, out)
	if v.Decision != guard.DecisionDeny || len(v.Findings) != 1 || v.Findings[0].Rule != "credentials.url_password" {
		t.Errorf("tool output: %+v", v)
	}
}

// TestRegexTimeout：用户正则超时按未命中处理（outbound 没有请求确认），带 regex_timeout（spec §3.4）。
func TestRegexTimeout(t *testing.T) {
	slow := map[string]string{"slow.yaml": "schema: 1\nid: acme.slow\ncategory: acme\non: [prompt]\nmatch: {regex: ['(a+)+$']}\n"}
	v, _ := evaluate(t, newCheck(t, "", slow), prompt(strings.Repeat("a", 40)+"!"))
	if v.Decision != guard.DecisionPass || !reflect.DeepEqual(v.Fallbacks, []string{outbound.FallbackRegexTimeout}) {
		t.Errorf("verdict = %+v", v)
	}
}

// TestBudget：截止时间到了还没扫完时放行，带 local_budget_exceeded；检测器已经得出的 deny 在用户正则之前提交，
// 之后正则阶段超时也保持（spec §3.4、§10.1）。
func TestBudget(t *testing.T) {
	slow := map[string]string{"slow.yaml": "schema: 1\nid: acme.slow\ncategory: acme\non: [prompt]\nmatch: {regex: [x]}\n"}
	c := newCheck(t, "", slow)
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	var commits []guard.Verdict
	v, err := c.Evaluate(ctx, prompt("sk-abcdefghijklmnop1234 x"), func(v guard.Verdict) { commits = append(commits, v) })
	if err != nil || v.Decision != guard.DecisionDeny || !reflect.DeepEqual(v.Fallbacks, []string{outbound.FallbackBudget}) ||
		len(commits) != 1 || commits[0].Decision != guard.DecisionDeny {
		t.Errorf("deny kept: %+v %v, commits %+v", v, err, commits)
	}
	v, err = c.Evaluate(ctx, prompt("x"), func(guard.Verdict) {})
	if err != nil || v.Decision != guard.DecisionPass || !reflect.DeepEqual(v.Fallbacks, []string{outbound.FallbackBudget}) {
		t.Errorf("pass: %+v %v", v, err)
	}
}

// TestTruncatedPrivateKeyDenied：被截断的私钥（只有 BEGIN 行）同样 deny（M4a 终审 I-1）。
func TestTruncatedPrivateKeyDenied(t *testing.T) {
	v, _ := evaluate(t, newCheck(t, "", nil), prompt("here:\n-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ\nAAAAMwAAAAtzc2gtZWQyNTUxOQAAACDm9zLbW1h"))
	if v.Decision != guard.DecisionDeny || len(v.Findings) != 1 || v.Findings[0].Rule != "private_key.pem" {
		t.Errorf("verdict = %+v", v)
	}
}

// TestNothingFound：没有命中时放行，不带原因。误报样本：UUID、git 哈希、示例 key、占位符、变量引用、代码与文档里
// 常见的写法都不算凭据（M4a 计划评审：遮蔽照宽，拦截再校验）。
func TestNothingFound(t *testing.T) {
	c := newCheck(t, "", nil)
	for _, text := range []string{
		"id 123e4567-e89b-12d3-a456-426614174000, commit a94a8fe5ccb19ba61c4c0873d391e987982fbbd3",
		"set OPENAI_API_KEY=your-api-key-here before running",
		"password: changeme",
		"api_key = os.environ['OPENAI_API_KEY']",
		"token = $GITHUB_TOKEN",
		"secret=${SECRET_VALUE}",
		"password = getPassword(user)",
		"Authorization: Bearer <token>",
		"the access token was refreshed at startup",
		"API_KEY=REPLACE_WITH_YOUR_KEY",
		"sha256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		"postgres://user:password@localhost:5432/app",
		// 带数字的路径与标识符（M4a 计划评审 C2）
		"Fix the token refresh bug in src/main/java/com/acme/OAuth2TokenService",
		"the token is generated by generateHmacSha256TokenForUser",
		"see auth flow in docs/OAuth2/PKCEFlowDiagram3",
		"api key rotation for projects/acme/secrets/StripeKey2024",
		"the access key policy is AWSLambdaBasicExecutionRole2",
		"session token TTL: 3600, refresh at RefreshTokenHandlerV2",
		"Use the credentials from vault path secret/data/Prod2DbCreds",
		"the secret sauce is kubernetesDeploymentV2Controller",
		// 普通单词、分支名、代码与占位值（M4a 计划评审 I1）
		"Bearer authentication uses the AuthorizationHeaderProvider",
		"git checkout pk_feature_branch_for_payments",
		"import sk-learn-preprocessing-module",
		"why does token = jwt.encode(payload, key) fail?",
		`token = request.headers.get("X-Token")`,
		`password = os.environ["DB_PASSWORD"]`,
		"API_KEY=your-api-key-here",
		"const apiKey = process.env.API_KEY",
		"PASSWORD=<your password>",
		"secret: xxxxxxxx",
		// 版本号、内网地址、只提到这些词的句子
		"bump version to 1.2.3.4 and node 20.11.1",
		"the service listens on 10.0.0.12:8080",
		"rotate the token bucket every 30s",
		"the password policy requires 12 characters",
		// 代码、类型标注、粘贴的环境变量与报错、配置项、默认连接串（M4a 终审 C-1）
		"interface Props { token: string; password: string }",
		"type Config = { apiKey: string }",
		"accessToken: string;\nreadonly token: string;\npassword: string | undefined",
		"struct User { password: String, }",
		"token: Option<String>",
		"const user = { password: hashedPassword, token: accessToken, apiKey: apiKey, };",
		"login({ password=user.password, })",
		"PWD=/Users/cc/project\nOLDPWD=/home/alice/src",
		"pwd: /Users/cc/MyCode/h-guard",
		"zsh: pwd: command not found",
		"Error: invalid token: expired_signature",
		"error TS2322: Type 'number' is not assignable to type 'string'. token: string",
		"csrf_token=enabled\npassword: required\nsecret: optional",
		"use the --password=prompt flag",
		"secret: &secret\npassword: !vault |",
		"token=${TOKEN:-default123}",
		"rename token:refresh to token:rotate",
		"DATABASE_URL=postgres://postgres:postgres@localhost:5432/db",
		"amqp://guest:guest@localhost:5672/ and mysql://root:root@127.0.0.1:3306/app",
		"aws_access_key_id = AKIAIOSFODNN7EXAMPLE",
		"src/auth/token.ts:12: export const token: string = ''",
		"/etc/passwd:root:x:0:0:root:/root:/bin/bash",
	} {
		v, commits := evaluate(t, c, prompt(text))
		if v.Decision != guard.DecisionPass || len(v.Findings) != 0 || len(v.Reasons) != 0 || len(commits) != 0 {
			t.Errorf("%q: %+v", text, v)
		}
	}
}

// TestEarlyCommit：检测器得出的 deny 在用户正则之前提交，提交的结论只含检测器的命中；用户正则另有命中时最终结论
// 再提交一次，包含全部命中（spec §3.3）。
func TestEarlyCommit(t *testing.T) {
	falcon := map[string]string{"falcon.yaml": "schema: 1\nid: acme.codename\ncategory: acme\non: [prompt]\nmatch: {regex: [falcon]}\n"}
	v, commits := evaluate(t, newCheck(t, "", falcon), prompt("falcon uses sk-abcdefghijklmnop1234"))
	if len(commits) != 2 || len(commits[0].Findings) != 1 || commits[0].Findings[0].Rule != "credentials.prefixed_token" ||
		len(commits[1].Findings) != 2 || v.Decision != guard.DecisionDeny {
		t.Errorf("verdict %+v, commits %+v", v, commits)
	}
	// 用户正则没有新命中：只提交一次
	if _, commits = evaluate(t, newCheck(t, "", falcon), prompt("sk-abcdefghijklmnop1234")); len(commits) != 1 {
		t.Errorf("commits %+v", commits)
	}
}

// faultCtx 在第 n 次 Err 调用时执行 at，用来在用户正则之间注入后续阶段的故障。
type faultCtx struct {
	context.Context
	n, calls int
	at       func()
}

func (c *faultCtx) Err() error {
	if c.calls++; c.calls == c.n {
		c.at()
	}
	return nil
}

// TestRegexDenyCommittedBeforeNextRule：检测器没有命中、第一条用户规则命中 deny 类别时，在开始下一条规则之前就提交；
// 之后的规则出故障（panic）也不会丢掉这个 deny（spec §3.3、§10.1，M4a Codex 评审 M4A-03）。
func TestRegexDenyCommittedBeforeNextRule(t *testing.T) {
	two := map[string]string{
		"a.yaml": "schema: 1\nid: acme.a\ncategory: acme\non: [prompt]\nmatch: {regex: [MARKER]}\n",
		"b.yaml": "schema: 1\nid: acme.b\ncategory: acme\non: [prompt]\nmatch: {regex: [OTHER]}\n",
	}
	// 只有第一条规则时 Err 被调用的次数；两条规则时下一次调用就在开始第二条规则之前
	count := &faultCtx{Context: context.Background(), at: func() {}}
	if _, err := newCheck(t, "", map[string]string{"a.yaml": two["a.yaml"]}).Evaluate(count, prompt("MARKER"), func(guard.Verdict) {}); err != nil {
		t.Fatal(err)
	}
	n := count.calls + 1
	c := newCheck(t, "", two)
	commits := 0
	ctx := &faultCtx{Context: context.Background(), n: n, at: func() {
		if commits == 0 {
			t.Error("second rule started before the first rule's deny was committed")
		}
	}}
	v, err := c.Evaluate(ctx, prompt("MARKER"), func(v guard.Verdict) {
		if v.Decision == guard.DecisionDeny {
			commits++
		}
	})
	if err != nil || v.Decision != guard.DecisionDeny || commits != 1 || ctx.calls < n {
		t.Errorf("verdict %+v, commits %d, calls %d", v, commits, ctx.calls)
	}
	ctx = &faultCtx{Context: context.Background(), n: n, at: func() { panic("injected later-stage failure") }}
	if v, err := guard.Run(ctx, c, prompt("MARKER")); v.Decision != guard.DecisionDeny || err == nil {
		t.Errorf("after fault: %+v %v", v, err)
	}
	// warn 类别的命中不提交
	c = newCheck(t, "outbound: {categories: {acme: {action: warn}}}\n", two)
	commits = 0
	if v, _ := c.Evaluate(context.Background(), prompt("MARKER OTHER"), func(guard.Verdict) { commits++ }); v.Decision != guard.DecisionWarn || commits != 0 {
		t.Errorf("warn: %+v, commits %d", v, commits)
	}
}

// TestSensitiveSpansIncomplete：敏感区间的扫描被取消（哪怕已经找到一部分）时 ok 为假，调用方不记正文；扫完时
// TestScan：Evaluate 交出这一次用户正则认出的全部区间：credentials、private_key 类别（含类别停用的、值在 ignore 里
// 的）记为 Secret，其余记为 Other；扫描途中取消或截止时间已过时 Complete 为假（M4a Codex 第二轮 R2-01，M4b 复用扫描
// 结果）。
func TestScan(t *testing.T) {
	userRules := map[string]string{
		"k.yaml": "schema: 1\nid: acme.key\ncategory: credentials\non: [prompt]\nmatch: {regex: ['ACME-[0-9]{12}']}\n",
		"f.yaml": "schema: 1\nid: acme.falcon\ncategory: acme\non: [prompt]\nmatch: {regex: [falcon]}\n",
		"p.yaml": "schema: 1\nid: acme.blob\ncategory: private_key\non: [prompt]\nmatch: {regex: ['BLOB<[^>]*>']}\n",
	}
	text := "ACME-111111111111 ACME-222222222222 falcon BLOB<x>"
	scanOf := func(c *outbound.Check, ctx context.Context) (sc outbound.Scan, called bool) {
		c.Scanned = func(s outbound.Scan) { sc, called = s, true }
		if _, err := c.Evaluate(ctx, prompt(text), func(guard.Verdict) {}); err != nil {
			t.Fatal(err)
		}
		return sc, called
	}
	// 私钥类别停用、ACME 的值在 ignore 里：不算命中，照样遮蔽
	c := newCheck(t, "outbound: {categories: {private_key: {enabled: false}, credentials: {ignore: ['ACME-111111111111']}}}\n", userRules)
	sc, called := scanOf(c, context.Background())
	if !called || !sc.Complete || !reflect.DeepEqual(sc.Secret, [][2]int{{0, 17}, {18, 35}, {43, 50}}) || !reflect.DeepEqual(sc.Other, [][2]int{{36, 42}}) {
		t.Errorf("complete: %+v", sc)
	}
	// 第一处匹配之后取消
	if sc, _ := scanOf(c, &cancelCtx{faultCtx: &faultCtx{Context: context.Background(), n: -1, at: func() {}}, from: 2}); sc.Complete {
		t.Errorf("partial scan reported complete: %+v", sc)
	}
	// 扫描之前截止时间已过
	expired, cancel := context.WithCancel(context.Background())
	cancel()
	if sc, _ := scanOf(c, expired); sc.Complete {
		t.Error("expired context reported complete")
	}
}

// cancelCtx 从第 from 次 Err 调用起返回 context.Canceled。
type cancelCtx struct {
	*faultCtx
	from int
}

func (c *cancelCtx) Err() error {
	c.faultCtx.Err()
	if c.calls >= c.from {
		return context.Canceled
	}
	return nil
}

// TestManyHits：大段文本里有大量命中时，命中数与行号照常计入，每条命中记下的位置有上限（M4a 计划评审 I3）。
func TestManyHits(t *testing.T) {
	var b strings.Builder
	for i := range 5000 {
		b.WriteString("8.8." + strconv.Itoa(i%250+1) + "." + strconv.Itoa(i%200+1) + " GET /\n")
	}
	v, _ := evaluate(t, newCheck(t, "outbound: {categories: {pii: {enabled: true}}}\n", nil), prompt(b.String()))
	if v.Decision != guard.DecisionDeny || len(v.Findings) != 1 || len(v.Reasons) != 2 {
		t.Fatalf("verdict %+v", v.Reasons)
	}
	if len(v.Findings[0].Locations) != 100 || v.Reasons[0].Params["count"] != "5000" ||
		!strings.HasPrefix(v.Reasons[0].Params["lines"], "1, 2, 3") || !strings.HasSuffix(v.Reasons[0].Params["lines"], "…") {
		t.Errorf("locations %d, reasons %+v", len(v.Findings[0].Locations), v.Reasons)
	}
}

// FuzzVerdictNeverLeaks：任意文本的结论（原因与命中）都不含命中的原文（spec §6.3）。
func FuzzVerdictNeverLeaks(f *testing.F) {
	for _, s := range []string{"export OPENAI_API_KEY=sk-abcdefghijklmnop1234", "Bearer Ab3dEf6hIj9kLm2nOp5q",
		"-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk\n-----END OPENSSH PRIVATE KEY-----", "mail alice@example.org 13800138000",
		"DB=postgres://admin:s3cr3tP4ss@db:5432/app"} {
		f.Add(s)
	}
	c := newCheck(f, "outbound: {tier: 3, categories: {pii: {enabled: true}}}\n", nil)
	f.Fuzz(func(t *testing.T, text string) {
		v, err := c.Evaluate(context.Background(), prompt(text), func(guard.Verdict) {})
		if err != nil {
			t.Fatal(err)
		}
		b, _ := json.Marshal(v)
		for _, fd := range v.Findings {
			for _, l := range fd.Locations {
				if value := text[l.Start:l.End]; len(value) >= 8 && strings.Contains(string(b), value) {
					t.Fatalf("verdict leaks %q: %s", value, b)
				}
			}
		}
	})
}
