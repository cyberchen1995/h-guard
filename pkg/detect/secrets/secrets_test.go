package secrets_test

import (
	"regexp"
	"strings"
	"testing"

	"github.com/cyberchen1995/h-guard/pkg/detect/secrets"
)

func rules(hits []secrets.Hit) []string {
	var out []string
	for _, h := range hits {
		out = append(out, h.Rule)
	}
	return out
}

func TestFindPositives(t *testing.T) {
	tests := []struct {
		text, rule, value string
	}{
		{"export OPENAI=sk-abcdefghijklmnop1234", secrets.RulePrefixedToken, "sk-abcdefghijklmnop1234"},
		{"gh auth login --with-token ghp_ABCDEFGHIJKLMNOPQRST", secrets.RulePrefixedToken, "ghp_ABCDEFGHIJKLMNOPQRST"},
		{`curl -H "Authorization: Bearer abcdefghijklmnopqrstuv" x`, secrets.RuleBearer, "abcdefghijklmnopqrstuv"},
		{"api_key=supersecretvalue", secrets.RuleAssignment, "supersecretvalue"},
		{"PASSWORD: hunter2hunter2", secrets.RuleAssignment, "hunter2hunter2"},
		{"aws configure set aws_access_key_id AKIAIOSFODNN7EXAMPL0", secrets.RuleAWSAccessKey, "AKIAIOSFODNN7EXAMPL0"},
		{"psql postgres://admin:s3cr3tP4ss@db.internal:5432/app", secrets.RuleURLPassword, "s3cr3tP4ss"},
		{"-----BEGIN RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----", secrets.RulePrivateKey,
			"-----BEGIN RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----"},
	}
	for _, tt := range tests {
		hits := secrets.Find(tt.text)
		if len(hits) != 1 || hits[0].Rule != tt.rule || tt.text[hits[0].Start:hits[0].End] != tt.value {
			t.Errorf("Find(%q) = %+v, want one %s hit on %q", tt.text, hits, tt.rule, tt.value)
		}
	}
}

func TestFindNegatives(t *testing.T) {
	for _, text := range []string{
		"id 123e4567-e89b-12d3-a456-426614174000",           // UUID
		"git show a94a8fe5ccb19ba61c4c0873d391e987982fbbd3", // git 哈希
		"token=abc",                     // 太短
		"git push origin main",          // 普通命令
		"https://example.com/path@v1.2", // URL 里没有用户名密码
		"echo skill-issue",              // 不是 sk- 前缀 token
	} {
		if hits := secrets.Find(text); len(hits) != 0 {
			t.Errorf("Find(%q) = %v, want none", text, rules(hits))
		}
	}
}

func TestQuotedAssignments(t *testing.T) {
	tests := []struct{ text, want string }{
		{`export PASSWORD="syntheticPassword123"`, `export PASSWORD="[redacted]"`},
		{`password='syntheticPassword123'`, `password='[redacted]'`},
		{`{"api_key":"syntheticPassword123"}`, `{"api_key":"[redacted]"}`},
		{`{"api_key": "two words here"}`, `{"api_key": "[redacted]"}`},
		{`token="escaped \" quote inside"`, `token="[redacted]"`},
		{`secret="unterminatedValue`, `secret="[redacted]`},
	}
	for _, tt := range tests {
		if got := secrets.Redact(tt.text); got != tt.want {
			t.Errorf("Redact(%s) = %s, want %s", tt.text, got, tt.want)
		}
	}
}

func TestOverlappingHitsAreMergedIntoTheirUnion(t *testing.T) {
	for _, text := range []string{
		`password=prefix:sk-abcdefghijklmnop:syntheticSuffix123`,
		`postgres://u:prefix:sk-abcdefghijklmnop:syntheticSuffix123@host/db`,
	} {
		got := secrets.Redact(text)
		if strings.Contains(got, "prefix") || strings.Contains(got, "syntheticSuffix123") || strings.Count(got, "[redacted]") != 1 {
			t.Errorf("Redact(%s) = %s", text, got)
		}
	}
}

func TestOverlappingRulesReportedOnce(t *testing.T) {
	// 赋值里的值本身是带前缀的 token：只报一次，取更具体的规则
	hits := secrets.Find("token=ghp_ABCDEFGHIJKLMNOPQRST")
	if len(hits) != 1 || hits[0].Rule != secrets.RulePrefixedToken {
		t.Errorf("hits = %+v", hits)
	}
}

func TestRedactKeepsContext(t *testing.T) {
	got := secrets.Redact(`curl -H "Authorization: Bearer abcdefghijklmnopqrstuv" -d api_key=supersecretvalue`)
	want := `curl -H "Authorization: Bearer [redacted]" -d api_key=[redacted]`
	if got != want {
		t.Errorf("Redact =\n%s\nwant\n%s", got, want)
	}
	if secrets.Redact("ls -la") != "ls -la" {
		t.Error("Redact changed text without secrets")
	}
}

func TestMaskForLog(t *testing.T) {
	got := secrets.MaskForLog("token: 123e4567-e89b-12d3-a456-426614174000")
	want := "token: [secret:credentials.assignment len=36 charset=hex shape=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx]"
	if got != want {
		t.Errorf("MaskForLog =\n%s\nwant\n%s", got, want)
	}
	long := "password=" + strings.Repeat("Gz9", 30)
	if got := secrets.MaskForLog(long); strings.Contains(got, "shape=") || !strings.Contains(got, "len=90 charset=alnum") {
		t.Errorf("long value mask = %s", got)
	}
	if strings.Contains(secrets.MaskForLog("api_key=supersecretvalue"), "supersecretvalue") {
		t.Error("MaskForLog leaked the value")
	}
	// 非 ASCII 的值：shape 不能把字符原样留下
	if got := secrets.MaskForLog("password=中文口令测试值"); strings.Contains(got, "中文") || !strings.Contains(got, "len=7 charset=mixed shape=xxxxxxx]") {
		t.Errorf("unicode mask = %s", got)
	}
	if got := secrets.MaskForLog("pwd=ab!#$%cd"); !strings.Contains(got, "shape=xxxxxxxx]") {
		t.Errorf("symbols must not survive in shape: %s", got)
	}
}

// TestMaskShapeNeverReplaysTheValue：shape 只在实际替换了至少一半字符时输出，且绝不等于原值（评审 N05）。
func TestMaskShapeNeverReplaysTheValue(t *testing.T) {
	tests := []struct {
		value     string
		wantShape string // 空表示不输出 shape
	}{
		{"~@+=/-_.:~@+=", ""},    // 全是分隔符
		{"a~@+=/-_.:", ""},       // 1/10 被替换
		{"ab-_cd-_", "xx-_xx-_"}, // 恰好一半：输出
		{"ab-_c-_.", ""},         // 3/8 被替换
		{"中文口令测试值", "xxxxxxx"},   // Unicode 全部替换
		{"口令-_/:", ""},           // Unicode 2/6
		{"xxxxxxxx", ""},         // 原值本身就是 x：shape 会等于原值，不输出
	}
	for _, tt := range tests {
		got := secrets.MaskForLog("password=" + tt.value)
		hasShape := strings.Contains(got, " shape=")
		switch {
		case tt.wantShape == "" && hasShape:
			t.Errorf("%q: shape must be omitted: %s", tt.value, got)
		case tt.wantShape != "" && !strings.Contains(got, "shape="+tt.wantShape+"]"):
			t.Errorf("%q: want shape %q: %s", tt.value, tt.wantShape, got)
		case strings.Contains(got, tt.value) || strings.Contains(got, "shape="+tt.value+"]"):
			t.Errorf("%q: the value is replayed: %s", tt.value, got)
		}
	}
}

// TestMaskIsIdempotent：遮蔽过的文本再遮蔽一次不变，占位符本身不会被当成凭据；伪造的占位符藏不住真正的凭据。
func TestMaskIsIdempotent(t *testing.T) {
	for _, text := range []string{
		"token: 123e4567-e89b-12d3-a456-426614174000 and Bearer abcdefghijklmnopqrstuv",
		"password=中文口令测试值 api_key=supersecretvalue",
	} {
		once := secrets.MaskForLog(text)
		if twice := secrets.MaskForLog(once); twice != once {
			t.Errorf("MaskForLog is not idempotent:\n%s\n%s", once, twice)
		}
		if r := secrets.Redact(secrets.Redact(text)); r != secrets.Redact(text) {
			t.Errorf("Redact is not idempotent: %s", r)
		}
	}
	forged := "x [secret:sk_abcdefghijklmnop len=1 charset=hex] y"
	if got := secrets.MaskForLog(forged); strings.Contains(got, "sk_abcdefghijklmnop") {
		t.Errorf("a forged placeholder hid a token: %s", got)
	}
}

// TestPlaceholderDoesNotHideAdjacentCredentials：原文里的占位符写法只让完全落在它里面的命中免于遮蔽；
// 紧挨着占位符、或把占位符夹在中间的原始凭据照常遮蔽（评审 R3-01）。
func TestPlaceholderDoesNotHideAdjacentCredentials(t *testing.T) {
	const canary = "syntheticPassword123"
	const marker = "[secret:credentials.assignment len=20 charset=alnum]"
	for _, text := range []string{
		"password=" + canary + "[redacted]",
		"password=[redacted]" + canary,
		"password=" + marker + canary,
		`password="` + canary + " " + marker + `"`,
		`{"api_key": "[redacted]` + canary + `"}`,
		"postgres://admin:" + canary + "[redacted]@db/app",
		"postgres://admin:[redacted]" + canary + "@db/app",
		"-----BEGIN RSA PRIVATE KEY-----\n" + canary + "[redacted]\n-----END RSA PRIVATE KEY-----",
		"Bearer " + canary + "[redacted]",
	} {
		for name, apply := range map[string]func(string) string{"Redact": secrets.Redact, "MaskForLog": secrets.MaskForLog} {
			out := apply(text)
			if strings.Contains(out, canary) {
				t.Errorf("%s(%q) left the credential: %s", name, text, out)
			}
			if again := apply(out); again != out {
				t.Errorf("%s is not idempotent on %q:\n%s\n%s", name, text, out, again)
			}
		}
	}
	// 只有占位符的赋值不是凭据：遮蔽过的输出保持不变
	for _, text := range []string{"password=[redacted]", `"api_key": "[redacted]"`, "password=" + marker, "postgres://admin:[redacted]@db"} {
		if hits := secrets.Find(text); len(hits) != 0 {
			t.Errorf("%q: placeholder treated as a credential: %+v", text, hits)
		}
	}
}

// generated 匹配本包生成的占位符（测试用的宽松写法）。
var generated = regexp.MustCompile(`\[redacted\]|\[secret:[a-z_.]+ len=\d+ charset=[a-z0-9]+(?: shape=[^\]]*)?\]`)

// FuzzMaskNeverLeaksFoundValues：找到的值不会原样留在输出里（生成的占位符之外），shape 不重放值；再遮蔽一次时，
// 生成的占位符不会单独被当作凭据。任意拼接的输入再遮蔽一次可能多遮住与占位符相邻的原文（替换改变了相邻匹配的上下文），
// 所以这里不要求逐字节不变；正常输出的不变性由 TestMaskIsIdempotent 等用例覆盖。
func FuzzMaskNeverLeaksFoundValues(f *testing.F) {
	for _, seed := range []string{"api_key=supersecretvalue", "Bearer abcdefghijklmnopqrstuv", "x sk-abcdefghijklmnop y",
		`export PASSWORD="syntheticPassword123"`, `password=prefix:sk-abcdefghijklmnop:syntheticSuffix123`, "password=中文口令测试值",
		"password=~@+=/-_.:~@+=", "password=ab-_cd-_", "password=[redacted]syntheticPassword123",
		"password=[secret:credentials.assignment len=20 charset=alnum]syntheticPassword123",
		"password=[secret:credentials.assignment rset=0 charset=alnum]syntheticPassword123",
		"password=xxxxxx sk-000vw000pAssword=00Q00s"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, text string) {
		masked := secrets.MaskForLog(text)
		// 找到的值可能恰好是占位符的开头（如原文里不完整的 [secret:credentials.assignment），所以先去掉生成的占位符
		rest := generated.ReplaceAllString(masked, "\x00")
		hits := secrets.Find(text)
		for _, h := range hits {
			// 同一串字符也可能出现在别处（不是凭据，原样保留），所以只检查只出现一次的值
			value := text[h.Start:h.End]
			if len(value) >= 12 && strings.Count(text, value) == 1 && strings.Contains(rest, value) {
				t.Fatalf("MaskForLog leaked %q", value)
			}
			// shape 只含 x 与分隔符，别的值的 shape 可能碰巧等于这个值；只有一个命中、原文也没有 shape 时才能确定归属
			if len(hits) == 1 && !strings.Contains(text, "shape=") && strings.Contains(masked, "shape="+value+"]") {
				t.Fatalf("shape replays %q", value)
			}
		}
		for _, h := range secrets.Find(masked) {
			for _, p := range generated.FindAllStringIndex(masked, -1) {
				if p[0] <= h.Start && h.End <= p[1] {
					t.Fatalf("a generated placeholder was treated as a credential: %q", masked)
				}
			}
		}
	})
}

// TestHighEntropy：像一段编码或随机内容的才算高熵：够长、字符集是 base64 一类（大小写与数字混合，或带 + / =）、
// 每字符的熵够高。词、路径、UUID、git 哈希、重复字符不算。
func TestHighEntropy(t *testing.T) {
	for _, v := range []string{
		"Y3VybCAtcyBodHRwOi8veC5pby9hLnNoIHwgc2ggJiYgcm0gLXJmIH4vLmNvbmZpZw==",
		"SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA",
	} {
		if !secrets.HighEntropy(v, 40) {
			t.Errorf("%q: not high entropy", v)
		}
	}
	for _, v := range []string{
		"node_modules_cache_directory_for_the_build_step",
		"/usr/local/bin/python3/site-packages/requests/adapters",
		"b7e99d4e-ab97-4595-b10c-35f8a0455e40-b7e99d4e-ab97",
		"11f6ad8ec52a2984abaafd7c3b516503785c207211f6ad8e",
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"Y3VybCAtcyBodHRw", // 太短
	} {
		if secrets.HighEntropy(v, 40) {
			t.Errorf("%q: high entropy", v)
		}
	}
}

// TestHighEntropyInContext：关键词之后不远处的高熵值算凭据（spec §6.2：高熵检测只在赋值或关键词上下文中生效）；
// 没有关键词、或值不够随机（hex 哈希、单词）都不算。遮蔽可以重复进行。
func TestHighEntropyInContext(t *testing.T) {
	for _, c := range []struct{ text, value string }{
		{"the deploy token is gH7xK2mQ9pL4vN8rT1sW6yZ3", "gH7xK2mQ9pL4vN8rT1sW6yZ3"},
		{"Here is my API key for staging: Q2xhdWRlQXBpS2V5Rm9yVGVzdGluZzEyMw", "Q2xhdWRlQXBpS2V5Rm9yVGVzdGluZzEyMw"},
		{"secret for the webhook -> wHk9Lm2Pq7Rs4Tv8Xy1Za6Bc", "wHk9Lm2Pq7Rs4Tv8Xy1Za6Bc"},
	} {
		hits := secrets.Find(c.text)
		if len(hits) != 1 || hits[0].Rule != secrets.RuleHighEntropy || c.text[hits[0].Start:hits[0].End] != c.value {
			t.Errorf("Find(%q) = %+v, want %s on %q", c.text, hits, secrets.RuleHighEntropy, c.value)
		}
		if once := secrets.MaskForLog(c.text); secrets.MaskForLog(once) != once || strings.Contains(once, c.value) {
			t.Errorf("MaskForLog(%q) = %q", c.text, once)
		}
	}
	for _, text := range []string{
		"commit gH7xK2mQ9pL4vN8rT1sW6yZ3 fixed the build",             // 没有关键词
		"the token is a94a8fe5ccb19ba61c4c0873d391e987982fbbd3",       // hex 哈希不够随机
		"password policy requires AtLeastTwelveCharacters long",       // 单词，没有数字
		"token bucket refill rate and the auth middleware ordering",   // 只是提到这些词
		"the secret ingredient: 123e4567-e89b-12d3-a456-426614174000", // UUID
		// 路径与驼峰标识符（带数字也不算），关键词与值之间没有 is、:、= 这类连接（M4a 计划评审 C2）
		"Fix the token refresh bug in src/main/java/com/acme/OAuth2TokenService",
		"the token is generated by generateHmacSha256TokenForUser",
		"see auth flow in docs/OAuth2/PKCEFlowDiagram3",
		"the access key policy is AWSLambdaBasicExecutionRole2",
		"session token TTL: 3600, refresh at RefreshTokenHandlerV2",
		"the secret is kubernetesDeploymentV2Controller",
		"api key rotation for projects/acme/secrets/StripeKey2024",
		"Use the credentials from vault path secret/data/Prod2DbCreds",
		"token gH7xK2mQ9pL4vN8rT1sW6yZ3Ab and more", // 没有连接
	} {
		if hits := secrets.Find(text); len(hits) != 0 {
			t.Errorf("Find(%q) = %v, want none", text, rules(hits))
		}
	}
}

// TestFindRules：只用指定的规则查，合并与标签只在这些规则之间进行：停用一条规则不会连带吞掉其他规则的命中
// （M4a 计划评审 I2）。
func TestFindRules(t *testing.T) {
	text := "OPENAI_API_KEY=sk-proj-Ab3dEf6hIj9kLm2nOp5q"
	if hits := secrets.FindRules(text, secrets.RuleAssignment); len(hits) != 1 || hits[0].Rule != secrets.RuleAssignment {
		t.Errorf("assignment only: %+v", hits)
	}
	if hits := secrets.FindRules(text); len(hits) != 1 || hits[0].Rule != secrets.RulePrefixedToken {
		t.Errorf("all rules: %+v", hits)
	}
	// 停用 assignment：同一个值仍由 high_entropy 认出
	text = `password = "gH7xK2mQ9pL4vN8rT1sW6yZ3Ab5cD"`
	if hits := secrets.FindRules(text, secrets.RuleHighEntropy); len(hits) != 1 || hits[0].Rule != secrets.RuleHighEntropy {
		t.Errorf("high_entropy only: %+v", hits)
	}
	if hits := secrets.FindRules(text); len(hits) != 1 || hits[0].Rule != secrets.RuleAssignment {
		t.Errorf("all rules: %+v", hits)
	}
}

// TestConfirmed：拦截前对命中值再校验（遮蔽仍用宽的形状，维护者决定 2026-10-16）：占位符、代码表达式、英文单词串、
// 环境变量引用都不算；像真的凭据的值算。
func TestConfirmed(t *testing.T) {
	for _, c := range []struct {
		rule, value string
		want        bool
	}{
		{secrets.RulePrefixedToken, "sk-abcdefghijklmnop1234", true},
		{secrets.RulePrefixedToken, "ghp_8fK2LmQ9xT4vB7nR1sW3yZ6pA0cD5eH", true},
		{secrets.RulePrefixedToken, "sk-learn-preprocessing-module", false},
		{secrets.RulePrefixedToken, "pk_feature_branch_for_payments", false},
		{secrets.RuleBearer, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", true},
		{secrets.RuleBearer, "Ab3dEf6hIj9kLm2nOp5q", true},
		{secrets.RuleBearer, "authentication", false},
		{secrets.RuleBearer, "AuthorizationHeaderProvider", false},
		{secrets.RuleAssignment, "hunter2hunter2", true},
		{secrets.RuleAssignment, "sk-proj-Ab3dEf6hIj9kLm2nOp5q", true},
		{secrets.RuleAssignment, "your-api-key-here", false},
		{secrets.RuleAssignment, "<your token>", false},
		{secrets.RuleAssignment, "<generate", false},
		{secrets.RuleAssignment, "changeme", false},
		{secrets.RuleAssignment, "xxxxxxxxxx", false},
		{secrets.RuleAssignment, "${DB_PASSWORD}", false},
		{secrets.RuleAssignment, "$OPENAI_API_KEY", false},
		{secrets.RuleAssignment, "process.env.API_KEY", false},
		{secrets.RuleAssignment, "request.headers.get(\"X-Token\")", false},
		{secrets.RuleAssignment, "os.environ[\"DB_PASSWORD\"]", false},
		{secrets.RuleAssignment, "jwt.encode(payload,", false},
		{secrets.RuleAssignment, "DB_PASSWORD", false},
		{secrets.RuleURLPassword, "s3cr3tP4ss", true},
		{secrets.RuleURLPassword, "password", false},
		{secrets.RuleURLPassword, "${PGPASSWORD}", false},
		{secrets.RuleAWSAccessKey, "AKIAIOSFODNN7EXAMPL0", true},
		// 类型名、标识符、YAML 锚点与标签、带默认值的变量、passwd 文件行、默认口令、AWS 文档的示例 key（M4a 终审 C-1）
		{secrets.RuleAssignment, "string;", false},
		{secrets.RuleAssignment, "String,", false},
		{secrets.RuleAssignment, "Option<String>", false},
		{secrets.RuleAssignment, "string|undefined", false},
		{secrets.RuleAssignment, "hashedPassword,", false},
		{secrets.RuleAssignment, "accessToken", false},
		{secrets.RuleAssignment, "expired_signature", false},
		{secrets.RuleAssignment, "required", false},
		{secrets.RuleAssignment, "&secret", false},
		{secrets.RuleAssignment, "!vault", false},
		{secrets.RuleAssignment, "${TOKEN:-default123}", false},
		{secrets.RuleAssignment, "root:x:0:0:root:/root:/bin/bash", false},
		{secrets.RuleAssignment, "Tr0ub4dor&3", true},
		{secrets.RuleAssignment, "correct-horse-battery-staple-42", true},
		{secrets.RuleURLPassword, "postgres", false},
		{secrets.RuleURLPassword, "guest", false},
		{secrets.RuleAWSAccessKey, "AKIAIOSFODNN7EXAMPLE", false},
		{secrets.RulePrivateKey, "-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----", true},
	} {
		if got := secrets.Confirmed(c.rule, c.value); got != c.want {
			t.Errorf("Confirmed(%s, %q) = %v", c.rule, c.value, got)
		}
	}
}

// TestMaskKeepLines：遮蔽之后行数不变（跨行的私钥换成占位符加同样多的换行），按行截取的摘录不会露出私钥正文
// （M4a 计划评审 C1）。
func TestMaskKeepLines(t *testing.T) {
	text := "line one\n-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\nQyNTUxOQAAACD\n-----END OPENSSH PRIVATE KEY-----\nlast"
	got := secrets.MaskKeepLines(text)
	if strings.Count(got, "\n") != strings.Count(text, "\n") || strings.Contains(got, "b3BlbnNzaC1rZXk") || strings.Contains(got, "QyNTUxOQ") ||
		!strings.HasPrefix(got, "line one\n[secret:private_key.pem") || !strings.HasSuffix(got, "\nlast") {
		t.Errorf("MaskKeepLines = %q", got)
	}
	// 依赖上下文的形状：值与关键词隔着几行，单看值认不出来；占位符按已经找到的命中生成，不再重新识别裸值
	// （M4a Codex 评审 M4A-01）
	for _, text := range []string{"password:\n\n\n\nAb3dEf6hIj9kLm2nOp5q", "Bearer\n\n\n\nAb3dEf6hIj9kLm2nOp5q",
		"api_key =\n\n  gH7xK2mQ9pL4vN8rT1sW6yZ3Ab5cD"} {
		got := secrets.MaskKeepLines(text)
		if len(secrets.Find(text)) == 0 || strings.Count(got, "\n") != strings.Count(text, "\n") || strings.Contains(got, "Ab3dEf6hIj9kLm2nOp5q") ||
			strings.Contains(got, "gH7xK2mQ9pL4") || !strings.Contains(got, "[secret:") {
			t.Errorf("MaskKeepLines(%q) = %q, hits %v", text, got, secrets.Find(text))
		}
	}
	// 调用方另外给出的区间（用户正则认出的凭据）同样遮蔽，与内置命中重叠时合并
	text = "id ACME-123456789012 and key sk-abcdefghijklmnop1234"
	got = secrets.MaskKeepLines(text, [2]int{3, 20}, [2]int{27, 35}, [2]int{5, 900})
	if strings.Contains(got, "ACME-1234") || strings.Contains(got, "abcdefghijklmnop") || !strings.Contains(got, "[secret:custom len=17") ||
		strings.Count(got, "[secret:") != 2 || secrets.MaskForLog(got) != got {
		t.Errorf("MaskKeepLines with extra = %q", got)
	}
}

// TestTruncatedPrivateKey：只有 BEGIN 行（head、带 limit 的读取、粘贴了一部分）或只有 END 行的私钥同样认出，正文
// 遮蔽；只有 BEGIN 行、没有正文时不算（M4a 终审 I-1）。
func TestTruncatedPrivateKey(t *testing.T) {
	body := "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAAB\nAAAAMwAAAAtzc2gtZWQyNTUxOQAAACDm9zLbW1hc2tlZC1i"
	for name, text := range map[string]string{
		"head only": "deploy key:\n-----BEGIN OPENSSH PRIVATE KEY-----\n" + body + "\n",
		"tail only": body + "\n-----END OPENSSH PRIVATE KEY-----\nthanks",
		"indented":  "key: |\n  -----BEGIN RSA PRIVATE KEY-----\n  " + strings.ReplaceAll(body, "\n", "\n  "),
	} {
		hits := secrets.Find(text)
		masked := secrets.MaskKeepLines(text)
		if len(hits) != 1 || hits[0].Rule != secrets.RulePrivateKey || strings.Contains(masked, "b3BlbnNzaC1rZXkt") || strings.Contains(masked, "AAAAMwAAAAtzc2gt") ||
			strings.Count(masked, "\n") != strings.Count(text, "\n") {
			t.Errorf("%s: hits %v, masked %q", name, hits, masked)
		}
	}
	if hits := secrets.Find("see -----BEGIN RSA PRIVATE KEY----- in the docs"); len(hits) != 0 {
		t.Errorf("BEGIN line alone: %v", hits)
	}
}

// TestTruncatedKeyShortLastLine：只有正文与 END 行的私钥，END 前最后一行正文很短（PEM 的最后一行长度不定，常是
// AB3x== 这样几个字符）时同样认出（M4b 终审 M-2）；前面各行仍要求至少 16 个字符。
func TestTruncatedKeyShortLastLine(t *testing.T) {
	body := strings.Repeat("MIIEowIBAAKCAQEAuQ3zZ9kq2Lm8Np4Rs7Tv1Wy5Za3Bc6Df0GhJkLm\n", 20)
	for _, last := range []string{"AB3x==", "VQIDAQABo1MwUTAdBgNVHQ4EFgQU=="} {
		text := body + last + "\n-----END RSA PRIVATE KEY-----\n"
		if hits := secrets.Find(text); len(hits) != 1 || hits[0].Rule != secrets.RulePrivateKey || hits[0].Start != 0 {
			t.Errorf("last line %q: %v", last, hits)
		}
	}
	if hits := secrets.Find("ok\n-----END RSA PRIVATE KEY-----\n"); len(hits) != 0 {
		t.Errorf("END after a short word: %v", hits)
	}
}
