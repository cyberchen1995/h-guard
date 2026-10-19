package openclaw

import (
	"encoding/json"
	"testing"

	"github.com/cyberchen1995/h-guard/pkg/guard"
)

// TestLocalRef：文件引用与 OpenClaw 一样判断：file: URL 按 safeFileURLToPath 解码（百分号编码、localhost、Windows
// 盘符），OpenClaw 拒绝的 URL（远端主机、编码的分隔符）与 http(s)、data:、media:// 不是本地文件；MEDIA: 前缀去掉。
func TestLocalRef(t *testing.T) {
	for _, tt := range []struct {
		ref, platform, want string
		ok                  bool
	}{
		{"file:///home/user/%2Eenv", "linux", "/home/user/.env", true},
		{"FILE://localhost/home/user/.ssh/id_rsa", "linux", "/home/user/.ssh/id_rsa", true},
		{"file:/etc/shadow", "linux", "/etc/shadow", true},
		{"file:///home/user/a%20b.txt", "darwin", "/home/user/a b.txt", true},
		{"file:///C:/Users/me/.aws/credentials", "win32", `C:\Users\me\.aws\credentials`, true},
		{"file:///C:/Users/me/.aws/credentials", "linux", "/C:/Users/me/.aws/credentials", true},
		{"file:///etc/passwd", "win32", "", false},
		{"file://evil.example/etc/passwd", "linux", "", false},
		{"file:///home/user%2F.env", "linux", "", false},
		{"file:///home/user/%5C.env", "linux", "", false},
		{"MEDIA:/home/user/.env", "linux", "/home/user/.env", true},
		{" media : ~/.ssh/id_rsa", "linux", "~/.ssh/id_rsa", true},
		{"MEDIA:file:///home/user/%2Eenv", "linux", "/home/user/.env", true},
		{"media://inbound/a.png", "linux", "", false},
		{"https://example.com/a.png", "linux", "", false},
		{"data:image/png;base64,eA==", "linux", "", false},
		{`C:\x\c.txt`, "linux", `C:\x\c.txt`, true},
		{"notes/a.pdf", "linux", "notes/a.pdf", true},
		{"~/report.pdf", "linux", "~/report.pdf", true},
		{"  ", "linux", "", false},
	} {
		got, ok := localRef(tt.ref, tt.platform)
		if got != tt.want || ok != tt.ok {
			t.Errorf("localRef(%q, %s) = %q, %v; want %q, %v", tt.ref, tt.platform, got, ok, tt.want, tt.ok)
		}
	}
}

// TestRefReads：各工具引用本地文件的参数（字符串与列表、嵌套的附件、snake_case 写法、MEDIA: 指令）都按读文件检查，
// 远端 URL 不算，重复的只算一次；类型不对的参数 OpenClaw 会拒绝，不取。
func TestRefReads(t *testing.T) {
	for _, tt := range []struct {
		tool   string
		params map[string]any
		want   []string
	}{
		{"pdf", map[string]any{"pdf": "file:///home/u/%2Eenv", "pdfs": []string{"a.pdf", "https://x/b.pdf", "a.pdf"}}, []string{"/home/u/.env", "a.pdf"}},
		{"image_generate", map[string]any{"image": "~/.ssh/id_rsa", "images": []any{"b.png", 3}}, []string{"~/.ssh/id_rsa", "b.png"}},
		{"music_generate", map[string]any{"images": []string{"c.png"}}, []string{"c.png"}},
		{"video_generate", map[string]any{"video": "v.mp4", "videos": []string{"w.mp4"}, "audioRef": "a.mp3", "audio_refs": []string{"b.mp3"}, "images": []string{"i.png"}}, []string{"i.png", "v.mp4", "w.mp4", "a.mp3", "b.mp3"}},
		{"message", map[string]any{"action": "send", "media_url": "file:///tmp/x", "attachments": []any{map[string]any{"file_path": "y"}, "z"}}, []string{"/tmp/x", "y"}},
		{"message", map[string]any{"action": "upload-file", "url": "file:///home/u/.ssh/id_rsa"}, []string{"/home/u/.ssh/id_rsa"}},
		{"message", map[string]any{"action": "upload-file", "url": "~/.aws/credentials"}, []string{"~/.aws/credentials"}},
		{"message", map[string]any{"action": "upload-file", "url": "https://example.com/a.pdf"}, nil},
		{"sessions_send", map[string]any{"message": "see\nMEDIA: /home/u/.env\nand MEDIA:`notes.md`"}, []string{"/home/u/.env", "notes.md"}},
		{"view_image", map[string]any{"path": "https://x/a.png", "paths": []string{"b.png"}}, []string{"b.png"}},
		{"pdf", map[string]any{"pdf": 7}, nil},
	} {
		raw, _ := json.Marshal(tt.params)
		var got []string
		for _, a := range refReads(tt.tool, raw, "linux") {
			if a.Kind != guard.ActionFileRead {
				t.Errorf("%s: %s, want file_read", tt.tool, a.Kind)
			}
			got = append(got, a.File.Path)
		}
		if g, w := jsonOf(got), jsonOf(tt.want); g != w {
			t.Errorf("%s %v: %s, want %s", tt.tool, tt.params, g, w)
		}
	}
}

func jsonOf(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
