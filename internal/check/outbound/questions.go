package outbound

import (
	"github.com/cyberchen1995/h-guard/pkg/judge"
)

// QuestionPrefix 是类别题的 ID 前缀：类别 name 的题 ID 是 QuestionPrefix + name。
const QuestionPrefix = "outbound."

// BuiltinQuestionsDigest 是 outbound 内置题集（三个内置类别题）的指纹，即 config.QuestionsDigest(BuiltinQuestions())。
// 带 outbound 阈值的内置档案（internal/config/default.yaml）的 fingerprint.outbound_questions 都是它，
// TestOutboundQuestionsDigestIsPinned 把它固定下来。
//
// 门槛是在这一套措辞上校准的：改措辞是破坏性变更，只在大版本做——同时重新校准全部带 outbound 阈值的内置档案、
// 更新本常量，并在发布说明里写明。用户在配置里写的类别题不在其中。
const BuiltinQuestionsDigest = "sha256:e7ee52fe169a18ddc19689ea73e9bbdec3073f34c5c25f5558cba8db7cdfa91a"

// 发给模型的 state（BuildState）：text 是遮蔽了本地命中之后的一块文本，source 是 prompt 或 tool_output，
// tool 是产生工具输出的工具名（提示词没有），chunk 写明这是第几块、共几块。题目引用 `text`，改名要连题目一起改。
//
// 措辞固定为英文、不做本地化（阈值依赖措辞，spec §8.3）。
var builtinQuestions = []judge.Question{
	{
		ID:   QuestionPrefix + "credentials",
		Kind: judge.KindProbability,
		Instructions: judge.Instructions{
			Question:    "Does `text` contain a secret credential written out in full, one that would let whoever reads it access an account, service or system: a password, API key, access token, session cookie, client secret, signing secret or similar?",
			CountsAsYes: "A real-looking secret value in any format, including ones without a familiar prefix: 'the admin password is Tr0ub4dor&3', 'use token 7f3a9c1e…', a webhook or signed URL whose path or query carries the secret, an auth line from .npmrc or .pypirc, a value under a Kubernetes Secret's data, a database password in a connection string.",
			CountsAsNo:  "Placeholders and examples ('your-api-key', '<token>', 'changeme', 'xxxx', 'sk-...'), variable references ($TOKEN, ${{ secrets.X }}, process.env.KEY), hashes (password hashes included), commit ids and UUIDs used as ordinary identifiers (a UUID-shaped value that is itself a password or token still counts), public keys and certificates, the words password or token without a value, and anything already replaced by an h-guard placeholder ([secret:…], [pii:…] or [masked]).",
		},
	},
	{
		ID:   QuestionPrefix + "private_key",
		Kind: judge.KindProbability,
		Instructions: judge.Instructions{
			Question:    "Does `text` contain private key material: the secret half of a key pair or a secret that derives keys?",
			CountsAsYes: "PEM or OpenSSH private key bodies, including truncated ones or ones missing their BEGIN/END lines; PGP private key blocks; a JWK with a private 'd' parameter; a PuTTY .ppk private section; a wallet seed phrase or mnemonic; base64 key material labelled as a private or signing key.",
			CountsAsNo:  "Public keys, certificates, certificate requests, key fingerprints, paths or names of key files, commands that generate keys without printing them, and anything already replaced by an h-guard placeholder ([secret:…], [pii:…] or [masked]).",
		},
	},
	{
		ID:   QuestionPrefix + "pii",
		Kind: judge.KindProbability,
		Instructions: judge.Instructions{
			Question:    "Does `text` contain personal information about a real, identifiable private person: a name together with contact, location or account details, a home or postal address, a personal phone number or email, a government ID, bank or card number, date of birth, or health or financial details?",
			CountsAsYes: "Customer or user records ('Zhang Wei, 138 0013 8000, 12 Xinhua Rd'), a CV or résumé, a support ticket quoting a person's address, rows exported from a users table, a scanned form's fields, a named patient's diagnosis.",
			CountsAsNo:  "Names alone (authors in commits, licences or code comments, public figures), obviously fake sample data (John Doe, 555-0100, example.com), company or service contact details, usernames or handles without other details, and anything already replaced by an h-guard placeholder ([secret:…], [pii:…] or [masked]).",
		},
	},
}

// BuiltinQuestions 返回内置类别题（副本）。
func BuiltinQuestions() []judge.Question {
	return append([]judge.Question(nil), builtinQuestions...)
}

// Question 返回类别 name 的题：配置里写了 question 时用配置的（不在校准指纹内），否则内置类别用内置题；自定义
// 类别没写 question 时没有题。只看配置，不看类别是否启用。
func (c *Check) Question(name string) (judge.Question, bool) {
	if q := c.Config.Category(name).Question; q != nil {
		return judge.Question{ID: QuestionPrefix + name, Kind: judge.KindProbability,
			Instructions: judge.Instructions{Question: q.Question, CountsAsYes: q.CountsAsYes, CountsAsNo: q.CountsAsNo}}, true
	}
	for _, q := range builtinQuestions {
		if q.ID == QuestionPrefix+name {
			return q, true
		}
	}
	return judge.Question{}, false
}
