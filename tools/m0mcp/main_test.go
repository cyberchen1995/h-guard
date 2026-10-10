package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func secretFile(t *testing.T, secret string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(p, []byte(secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func call(t *testing.T, method, params, file string) *response {
	t.Helper()
	return handle(request{JSONRPC: "2.0", ID: json.RawMessage(`1`), Method: method, Params: json.RawMessage(params)}, file)
}

func TestInitializeEchoesProtocolVersion(t *testing.T) {
	resp := call(t, "initialize", `{"protocolVersion":"2025-03-26","capabilities":{}}`, "")
	b, _ := json.Marshal(resp.Result)
	if !strings.Contains(string(b), `"protocolVersion":"2025-03-26"`) || !strings.Contains(string(b), `"tools":{}`) {
		t.Errorf("initialize result = %s", b)
	}
}

func TestToolsList(t *testing.T) {
	b, _ := json.Marshal(call(t, "tools/list", `{}`, "").Result)
	for _, want := range []string{`"name":"hg_m0_report"`, `"inputSchema"`, `"outputSchema"`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("tools/list result lacks %s: %s", want, b)
		}
	}
}

func TestToolsCallReturnsStructuredAndTextContent(t *testing.T) {
	resp := call(t, "tools/call", `{"name":"hg_m0_report","arguments":{}}`, secretFile(t, "HGCANARY-MCP"))
	b, _ := json.Marshal(resp.Result)
	var result struct {
		Content []struct {
			Type, Text string
		}
		StructuredContent struct {
			Code  string
			Parts int
		}
		IsError bool
	}
	if err := json.Unmarshal(b, &result); err != nil {
		t.Fatal(err)
	}
	if result.IsError || len(result.Content) != 2 || !strings.Contains(result.Content[0].Text, "HGCANARY-MCP") {
		t.Errorf("content = %+v", result)
	}
	if result.StructuredContent.Code != "HGCANARY-MCP" || result.StructuredContent.Parts != 2 {
		t.Errorf("structured content = %+v", result.StructuredContent)
	}
}

func TestToolsCallMissingFileIsToolError(t *testing.T) {
	b, _ := json.Marshal(call(t, "tools/call", `{"name":"hg_m0_report"}`, filepath.Join(t.TempDir(), "missing")).Result)
	if !strings.Contains(string(b), `"isError":true`) {
		t.Errorf("result = %s", b)
	}
}

func TestErrorsAndNotifications(t *testing.T) {
	if resp := call(t, "nope", `{}`, ""); resp.Error == nil || resp.Error.Code != -32601 {
		t.Errorf("unknown method: %+v", resp)
	}
	if resp := call(t, "tools/call", `{"name":"other"}`, ""); resp.Error == nil || resp.Error.Code != -32602 {
		t.Errorf("unknown tool: %+v", resp)
	}
	if resp := handle(request{JSONRPC: "2.0", Method: "notifications/initialized"}, ""); resp != nil {
		t.Errorf("notification must not get a reply: %+v", resp)
	}
}

func TestServeRoundTrip(t *testing.T) {
	in := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"hg_m0_report"}}`,
		`{not json`,
	}, "\n") + "\n"
	var out bytes.Buffer
	if err := serve(strings.NewReader(in), &out, secretFile(t, "HGCANARY-SERVE")); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("got %d replies, want 3:\n%s", len(lines), out.String())
	}
	if !strings.Contains(lines[1], "HGCANARY-SERVE") || !strings.Contains(lines[2], `"code":-32700`) {
		t.Errorf("replies =\n%s", out.String())
	}
}
