package openclaw

import (
	"encoding/json"
	"net/url"
	"regexp"
	"strings"

	"github.com/cyberchen1995/h-guard/pkg/guard"
	"github.com/cyberchen1995/h-guard/pkg/harness/internal/extadapter"
)

// refSpec 是一个工具的参数里引用本地文件的位置：keys 是取值为字符串或字符串列表的参数，nested 是取值为对象列表的
// 参数及其中引用文件的键，mediaLines 是正文里可以写 MEDIA: 指令（一行一个附件）的参数。OpenClaw 也接受这些键的
// snake_case 写法（resolveSnakeCaseParamKey），一并取。
type refSpec struct {
	keys       []string
	nested     []nestedRefs
	mediaLines []string
}

// nestedRefs 是取值为对象列表的参数（list）及其中引用文件的键。按顺序列出，动作的顺序固定。
type nestedRefs struct {
	list string
	keys []string
}

// fileRefs 是会读取本地文件、却不是读文件工具的 OpenClaw 工具（2026.10.4）：这些文件的内容会离开本机（发到频道、
// 交给模型或媒体服务的提供方）或进入另一个会话，按读文件检查。
//   - view_image：path、paths（本地图片或允许的 URL）；
//   - message：附件 media、mediaUrl、path、filePath、fileUrl、image、mediaUrls 与 attachments[] 的 media、mediaUrl、
//     path、filePath、fileUrl、url（src/infra/outbound/message-action-params.ts）；
//   - pdf：pdf、pdfs（本地 PDF 原生模式下整个文件发给模型提供方）；
//   - image_generate、music_generate：参考图 image、images；video_generate 另有参考视频 video、videos 与参考音频
//     audioRef、audioRefs；
//   - sessions_send：message 里的 MEDIA: 指令把本地文件作为附件交给另一个会话（splitMediaFromOutput）。
var fileRefs = map[string]refSpec{
	"view_image": {keys: []string{"path", "paths", "filePath"}},
	"message": {
		keys:   []string{"media", "mediaUrl", "path", "filePath", "fileUrl", "image", "mediaUrls"},
		nested: []nestedRefs{{"attachments", []string{"media", "mediaUrl", "path", "filePath", "fileUrl", "url"}}},
	},
	"pdf":            {keys: []string{"pdf", "pdfs"}},
	"image_generate": {keys: []string{"image", "images"}},
	"music_generate": {keys: []string{"image", "images"}},
	"video_generate": {keys: []string{"image", "images", "video", "videos", "audioRef", "audioRefs"}},
	"sessions_send":  {mediaLines: []string{"message"}},
}

// mediaLineRe 是 MEDIA: 指令（一行，src/media/parse-output.ts 的 MEDIA_TOKEN_RE）。
var mediaLineRe = regexp.MustCompile("(?i)\\bMEDIA:\\s*`?([^\\n`]+)`?")

// snake 返回 camelCase 键的 snake_case 写法。
func snake(k string) string {
	var b strings.Builder
	for _, c := range k {
		if c >= 'A' && c <= 'Z' {
			b.WriteByte('_')
			c += 'a' - 'A'
		}
		b.WriteRune(c)
	}
	return b.String()
}

// stringsOf 取出 v 里的字符串：字符串本身，或字符串列表里的各项；其余类型 OpenClaw 的参数校验会拒绝，不取。
func stringsOf(v any) []string {
	switch x := v.(type) {
	case string:
		return []string{x}
	case []any:
		var out []string
		for _, e := range x {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// refsOf 返回工具参数里引用的全部文件（未经判断是不是本地文件）。
func refsOf(tool string, raw json.RawMessage) []string {
	spec, ok := fileRefs[tool]
	if !ok || extadapter.IsNull(raw) {
		return nil
	}
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return nil
	}
	both := func(keys []string) []string {
		var out []string
		for _, k := range keys {
			out = append(out, k)
			if s := snake(k); s != k {
				out = append(out, s)
			}
		}
		return out
	}
	var refs []string
	for _, k := range both(spec.keys) {
		refs = append(refs, stringsOf(m[k])...)
	}
	for _, n := range spec.nested {
		items, _ := m[n.list].([]any)
		for _, it := range items {
			obj, _ := it.(map[string]any)
			for _, k := range both(n.keys) {
				refs = append(refs, stringsOf(obj[k])...)
			}
		}
	}
	for _, k := range spec.mediaLines {
		for _, text := range stringsOf(m[k]) {
			for _, mm := range mediaLineRe.FindAllStringSubmatch(text, -1) {
				refs = append(refs, mm[1])
			}
		}
	}
	return refs
}

// refReads 把工具参数里引用的本地文件换成读文件的动作（去掉重复的）。
func refReads(tool string, raw json.RawMessage, platform string) []guard.Action {
	var acts []guard.Action
	seen := map[string]bool{}
	for _, ref := range refsOf(tool, raw) {
		p, ok := localRef(ref, platform)
		if !ok || seen[p] {
			continue
		}
		seen[p] = true
		if act, ok := extadapter.File(guard.ActionFileRead, p); ok {
			acts = append(acts, act)
		}
	}
	return acts
}

var (
	mediaPrefixRe  = regexp.MustCompile(`(?i)^\s*MEDIA\s*:\s*`)
	schemeRe       = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.-]*:`)
	driveRe        = regexp.MustCompile(`^[A-Za-z]:[\\/]`)
	encodedSepRe   = regexp.MustCompile(`(?i)%(?:2f|5c)`)
	urlDrivePathRe = regexp.MustCompile(`^/[A-Za-z]:(?:/|$)`)
)

// localRef 按 OpenClaw 的规则判断一个文件引用是不是本地文件，是时返回它的路径：
//   - 去掉开头的 MEDIA: 前缀（media:// 是 OpenClaw 的媒体库，不是本地路径；normalizeMediaReferenceSource）；
//   - file: URL 与 OpenClaw 的 safeFileURLToPath 一样解码：主机只能为空或 localhost，路径里不能有编码的分隔符
//     （%2F、%5C），其余百分号编码解码；Windows 上 /C:/x 是 C:\x。OpenClaw 拒绝的 URL 不会读文件，不算；
//   - Windows 盘符路径（C:\、C:/）与不带 scheme 的路径（含相对路径与 ~）是本地文件；
//   - 其余带 scheme 的引用（http(s)、data:、media:// 等）不是。
func localRef(ref, platform string) (string, bool) {
	ref = strings.TrimSpace(ref)
	if !strings.HasPrefix(strings.ToLower(ref), "media://") {
		ref = strings.TrimSpace(mediaPrefixRe.ReplaceAllString(ref, ""))
	}
	if ref == "" {
		return "", false
	}
	if driveRe.MatchString(ref) {
		return ref, true
	}
	if !schemeRe.MatchString(ref) {
		return ref, true
	}
	if len(ref) < 5 || !strings.EqualFold(ref[:5], "file:") {
		return "", false
	}
	return fileURLPath(ref, platform)
}

// fileURLPath 是 safeFileURLToPath（@openclaw/fs-safe）的对应：OpenClaw 拒绝的 file: URL 返回 false。
func fileURLPath(ref, platform string) (string, bool) {
	u, err := url.Parse(ref)
	if err != nil || !strings.EqualFold(u.Scheme, "file") {
		return "", false
	}
	if h := strings.ToLower(u.Hostname()); h != "" && h != "localhost" {
		return "", false
	}
	escaped := u.EscapedPath()
	if u.Opaque != "" { // file:x 与 file:/x 一样按 file:///x 解析
		escaped = "/" + strings.TrimPrefix(u.Opaque, "/")
	}
	if encodedSepRe.MatchString(escaped) {
		return "", false
	}
	p, err := url.PathUnescape(escaped)
	if err != nil || p == "" || strings.ContainsRune(p, 0) {
		return "", false
	}
	if platform == "win32" {
		if !urlDrivePathRe.MatchString(p) {
			return "", false // Windows 上没有盘符的 file: URL 不是绝对路径（fileURLToPath 报错）
		}
		return strings.ReplaceAll(p[1:], "/", `\`), true
	}
	return p, true
}
