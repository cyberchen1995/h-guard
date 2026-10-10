// Command m0mcp 是 M0 录制用的最小 MCP 服务：stdio 上换行分隔的 JSON-RPC 2.0（spec §7.5）。
// 它只提供一个工具 hg_m0_report：读取 -secret-file 中的人工秘密串，以结构化内容加两个文本块返回，
// 用来核实各 harness 对结构化 MCP 输出的拦截。它不读取其他文件，也不访问网络。
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
)

const (
	toolName        = "hg_m0_report"
	defaultProtocol = "2025-06-18"
)

type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

// handle 处理一条请求；通知（没有 id）不回复，返回 nil。
func handle(req request, secretFile string) *response {
	if len(req.ID) == 0 || string(req.ID) == "null" {
		return nil
	}
	resp := &response{JSONRPC: "2.0", ID: req.ID}
	switch req.Method {
	case "initialize":
		var p struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		_ = json.Unmarshal(req.Params, &p)
		if p.ProtocolVersion == "" {
			p.ProtocolVersion = defaultProtocol
		}
		resp.Result = map[string]any{
			"protocolVersion": p.ProtocolVersion,
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": "hg-m0", "version": "0.0.0"},
		}
	case "ping":
		resp.Result = map[string]any{}
	case "tools/list":
		resp.Result = map[string]any{"tools": []any{map[string]any{
			"name":        toolName,
			"description": "Return the M0 test report. Takes no arguments.",
			"inputSchema": map[string]any{"type": "object", "properties": map[string]any{}},
			"outputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"code":  map[string]any{"type": "string"},
					"parts": map[string]any{"type": "integer"},
				},
				"required": []string{"code", "parts"},
			},
		}}}
	case "tools/call":
		var p struct {
			Name string `json:"name"`
		}
		_ = json.Unmarshal(req.Params, &p)
		if p.Name != toolName {
			resp.Error = &rpcError{Code: -32602, Message: "unknown tool " + p.Name}
			break
		}
		resp.Result = report(secretFile)
	default:
		resp.Error = &rpcError{Code: -32601, Message: "method not found: " + req.Method}
	}
	return resp
}

// report 返回工具结果：结构化内容加两个文本块，秘密串同时出现在两处。
func report(secretFile string) map[string]any {
	b, err := os.ReadFile(secretFile)
	if err != nil {
		return map[string]any{"isError": true, "content": []any{text("cannot read the report: " + err.Error())}}
	}
	code := strings.TrimSpace(string(b))
	return map[string]any{
		"content":           []any{text("report code: " + code), text("report end")},
		"structuredContent": map[string]any{"code": code, "parts": 2},
		"isError":           false,
	}
}

func text(s string) map[string]any { return map[string]any{"type": "text", "text": s} }

// serve 逐行读取请求并写回响应，直到输入结束。无法解析的行回复 JSON-RPC 解析错误。
func serve(in io.Reader, out io.Writer, secretFile string) error {
	r := bufio.NewReader(in)
	enc := json.NewEncoder(out)
	for {
		line, err := r.ReadBytes('\n')
		if len(bytes.TrimSpace(line)) > 0 {
			var req request
			resp := &response{JSONRPC: "2.0", ID: json.RawMessage("null"), Error: &rpcError{Code: -32700, Message: "parse error"}}
			if json.Unmarshal(line, &req) == nil {
				resp = handle(req, secretFile)
			}
			if resp != nil {
				if werr := enc.Encode(resp); werr != nil {
					return werr
				}
			}
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

func main() {
	secretFile := flag.String("secret-file", "", "存放人工秘密串的文件（必填）")
	flag.Parse()
	if *secretFile == "" {
		fmt.Fprintln(os.Stderr, "m0mcp: -secret-file is required")
		os.Exit(1)
	}
	if err := serve(os.Stdin, os.Stdout, *secretFile); err != nil {
		fmt.Fprintln(os.Stderr, "m0mcp:", err)
		os.Exit(1)
	}
}
