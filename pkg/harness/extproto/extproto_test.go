package extproto_test

import (
	"encoding/json"
	"testing"

	"github.com/cyberchen1995/h-guard/pkg/harness/extproto"
)

const validRequest = `{"protocol":"h-guard.ext/v1","harness":"claudecode","harness_version":"2.1.296","hook":"tool.check",` +
	`"session":{"id":"s1","cwd":"/work"},"data":{"tool":"Bash","input":{"command":"ls"}},"decided":"allow"}`

func TestParseRequest(t *testing.T) {
	r, err := extproto.ParseRequest([]byte(validRequest))
	if err != nil {
		t.Fatal(err)
	}
	if r.Harness != "claudecode" || r.Hook != "tool.check" || r.Session.ID != "s1" || r.Decided != "allow" {
		t.Errorf("request = %+v", r)
	}
	var data struct{ Tool string }
	if err := json.Unmarshal(r.Data, &data); err != nil || data.Tool != "Bash" {
		t.Errorf("data = %s", r.Data)
	}
}

func TestParseRequestRejects(t *testing.T) {
	for name, in := range map[string]string{
		"not json":         `{`,
		"wrong protocol":   `{"protocol":"other","harness":"claudecode","hook":"x","session":{"id":"s"},"data":{}}`,
		"invalid harness":  `{"protocol":"h-guard.ext/v1","harness":"Claude Code","hook":"x","session":{"id":"s"},"data":{}}`,
		"empty hook":       `{"protocol":"h-guard.ext/v1","harness":"claudecode","hook":"","session":{"id":"s"},"data":{}}`,
		"empty session id": `{"protocol":"h-guard.ext/v1","harness":"claudecode","hook":"x","session":{},"data":{}}`,
		"missing data":     `{"protocol":"h-guard.ext/v1","harness":"claudecode","hook":"x","session":{"id":"s"}}`,
		"null data":        `{"protocol":"h-guard.ext/v1","harness":"claudecode","hook":"x","session":{"id":"s"},"data":null}`,
	} {
		if _, err := extproto.ParseRequest([]byte(in)); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}

func TestReplyRoundTrip(t *testing.T) {
	b, err := json.Marshal(extproto.NewReply(extproto.ActionDeny, "blocked", "do it by hand"))
	if err != nil {
		t.Fatal(err)
	}
	r, err := extproto.ParseReply(b)
	if err != nil || r.Action != extproto.ActionDeny || r.Message != "blocked" || r.Hint != "do it by hand" {
		t.Fatalf("ParseReply(%s) = %+v, %v", b, r, err)
	}
	if b, _ := json.Marshal(extproto.NewReply(extproto.ActionPass, "", "")); string(b) != `{"protocol":"h-guard.ext/v1","action":"pass"}` {
		t.Errorf("pass reply = %s", b)
	}
}

func TestParseReplyRejects(t *testing.T) {
	for _, in := range []string{
		`{"protocol":"h-guard.ext/v1","action":"allow"}`, `{"protocol":"other","action":"pass"}`, `[]`,
		// 非 pass 的回复必须带说明：扩展把它交给用户或模型，空说明会让扩展的返回值不合法
		`{"protocol":"h-guard.ext/v1","action":"deny"}`, `{"protocol":"h-guard.ext/v1","action":"ask","message":""}`,
		`{"protocol":"h-guard.ext/v1","action":"warn","message":"  "}`,
	} {
		if _, err := extproto.ParseReply([]byte(in)); err == nil {
			t.Errorf("ParseReply(%s): want an error", in)
		}
	}
}
