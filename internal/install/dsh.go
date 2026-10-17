package install

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/cyberchen1995/h-guard/extensions"
)

// dshRowID 是 h-guard 的插件在 cordis.patch.yml 里那一行的 id：这个 id 的行归本项目所有。
const dshRowID = "h-guard"

// DSHHome 是 DeepSeek Harness 的主目录：$DSH_HOME，默认 ~/.dsh。
func DSHHome(t Target) string {
	if d := t.Getenv("DSH_HOME"); d != "" {
		return d
	}
	return filepath.Join(t.Home, ".dsh")
}

// DSHPatch 是对全部配置档生效的用户补丁文件 $DSH_HOME/cordis.patch.yml。
func DSHPatch(t Target) string { return filepath.Join(DSHHome(t), "cordis.patch.yml") }

// DSHPlugin 是写出的插件：<config_dir>/extensions/dsh/h-guard.mjs。
func DSHPlugin(t Target) string {
	return filepath.Join(t.ConfigDir, "extensions", "dsh", "h-guard.mjs")
}

// DSHModule 是补丁里挂载插件的模块名：POSIX 上是绝对路径；Windows 上是 file: URL，因为 dsh 把非相对的模块名
// 直接交给 import()，C:\… 的盘符会被当作 URL 协议。
func DSHModule(t Target, plugin string) string {
	if t.GOOS != "windows" {
		return plugin
	}
	return (&url.URL{Scheme: "file", Path: "/" + strings.ReplaceAll(plugin, `\`, "/")}).String()
}

// dshModulePath 把补丁里的模块名换回路径（file: URL 取出路径，其余原样），供 status 与插件路径比较。
func dshModulePath(t Target, name string) string {
	u, err := url.Parse(name)
	if err != nil || u.Scheme != "file" {
		return name
	}
	p := u.Path
	if t.GOOS == "windows" {
		p = strings.TrimPrefix(p, "/")
	}
	return filepath.FromSlash(p)
}

// DSH 计划 DeepSeek Harness 的安装或移除：
//   - 把内嵌的插件写到 <config_dir>/extensions/dsh/h-guard.mjs（CONFIG 一行是 h-guard 的命令与超时）；
//   - 在 $DSH_HOME/cordis.patch.yml 里插入挂载它的一行 {id: h-guard, name: <插件的绝对路径>}，补丁里的其他内容保留
//     （YAML 的排版可能被规整）。
//
// 移除先删掉这一行（空了的 insert 一并删掉），再删插件文件。只计划，不写入（Apply 执行）。
func DSH(t Target, remove bool) ([]Step, error) {
	plugin := DSHPlugin(t)
	data, err := renderExt(extensions.DSH, "dsh", t)
	if err != nil {
		return nil, err
	}
	file, err := extFileStep(t, plugin, "dsh-plugin", data, remove)
	if err != nil {
		return nil, err
	}
	if !remove {
		file.Summary = "write h-guard's DeepSeek Harness plugin"
	}
	patch := DSHPatch(t)
	module := DSHModule(t, plugin)
	change := func(old []byte, exists bool) ([]byte, error) { return dshPatchEdit(old, exists, module, remove) }
	old, err := os.ReadFile(patch)
	exists := err == nil
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	next, err := change(old, exists)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", patch, err)
	}
	summary, preview := "mount the plugin in the DeepSeek Harness patch", fmt.Sprintf("- insert:\n    - id: %s\n      name: %s\n", dshRowID, module)
	if remove {
		summary, preview = "remove the plugin from the DeepSeek Harness patch", fmt.Sprintf("remove the row with id %s\n", dshRowID)
	}
	ed := t.editor()
	// 预览只显示本项目的这一行：补丁的其他内容可能有秘密
	set := Step{Path: patch, Summary: summary, Preview: []byte(preview), changes: next != nil && !bytes.Equal(next, old), lockDir: ed.LockDir,
		apply: func() error {
			if _, err := ed.editLocked(patch, change); err != nil {
				return fmt.Errorf("%s: %w", patch, err)
			}
			return nil
		}}
	if remove {
		return []Step{set, file}, nil
	}
	return []Step{file, set}, nil
}

// dshPatchEdit 在补丁里加入或去掉本项目的一行。补丁是行覆盖与 - insert: [行…] 组成的 YAML 列表；本项目的行
// 放在根上的一个 insert 里。重装时已有且相同的行不改动，不同（路径变了、加了 disabled 等）就换成本项目的写法，
// 重复的删掉。没有变化时返回原文；文件不存在且是移除时返回 nil（不新建）。
func dshPatchEdit(old []byte, exists bool, module string, remove bool) ([]byte, error) {
	if !exists && remove {
		return nil, nil
	}
	var doc yaml.Node
	if exists && len(bytes.TrimSpace(old)) > 0 {
		if err := yaml.Unmarshal(old, &doc); err != nil {
			return nil, err
		}
	}
	if doc.Kind == 0 || (len(doc.Content) == 1 && doc.Content[0].Tag == "!!null") {
		doc = yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{{Kind: yaml.SequenceNode}}}
	}
	root := doc.Content[0]
	if root.Kind != yaml.SequenceNode {
		return nil, errors.New("the patch is not a list")
	}
	ours := dshRow(module)
	found, same := 0, false
	var items []*yaml.Node
	for _, item := range root.Content {
		rows := mapValue(item, "insert")
		if rows == nil || rows.Kind != yaml.SequenceNode {
			items = append(items, item)
			continue
		}
		var kept []*yaml.Node
		for _, row := range rows.Content {
			if id := mapValue(row, "id"); id == nil || id.Kind != yaml.ScalarNode || id.Value != dshRowID {
				kept = append(kept, row)
				continue
			}
			found++
			same = found == 1 && rowEqual(row, ours)
		}
		if len(kept) == len(rows.Content) {
			items = append(items, item)
			continue
		}
		if len(kept) == 0 && len(item.Content) == 2 {
			continue // 只有本项目的行的 insert 整个去掉
		}
		rows.Content = kept
		items = append(items, item)
	}
	if (!remove && found == 1 && same) || (remove && found == 0) {
		return old, nil
	}
	if !remove {
		items = append(items, &yaml.Node{Kind: yaml.MappingNode, Content: []*yaml.Node{
			{Kind: yaml.ScalarNode, Value: "insert"}, {Kind: yaml.SequenceNode, Content: []*yaml.Node{ours}},
		}})
	}
	root.Content = items
	var b bytes.Buffer
	enc := yaml.NewEncoder(&b)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// dshRow 是挂载插件的一行。
func dshRow(module string) *yaml.Node {
	return &yaml.Node{Kind: yaml.MappingNode, Content: []*yaml.Node{
		{Kind: yaml.ScalarNode, Value: "id"}, {Kind: yaml.ScalarNode, Value: dshRowID},
		{Kind: yaml.ScalarNode, Value: "name"}, {Kind: yaml.ScalarNode, Value: module},
	}}
}

// rowEqual 报告补丁里的行是否正好是 {id, name}，取值与 want 相同。
func rowEqual(row, want *yaml.Node) bool {
	if row.Kind != yaml.MappingNode || len(row.Content) != len(want.Content) {
		return false
	}
	for i := 0; i+1 < len(want.Content); i += 2 {
		v := mapValue(row, want.Content[i].Value)
		if v == nil || v.Kind != yaml.ScalarNode || v.Value != want.Content[i+1].Value {
			return false
		}
	}
	return true
}

// mapValue 返回映射 m 中 key 的值节点；m 不是映射或没有这个键时为 nil。
func mapValue(m *yaml.Node, key string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

// dshMounted 报告补丁里挂载本项目插件的行：found 是 id 为 h-guard 的行数，name 是第一行的路径。
func dshMounted(b []byte) (found int, name string, err error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return 0, "", err
	}
	if len(doc.Content) == 0 || doc.Content[0].Kind != yaml.SequenceNode {
		return 0, "", nil
	}
	for _, item := range doc.Content[0].Content {
		rows := mapValue(item, "insert")
		if rows == nil || rows.Kind != yaml.SequenceNode {
			continue
		}
		for _, row := range rows.Content {
			if id := mapValue(row, "id"); id != nil && id.Value == dshRowID {
				found++
				if found == 1 {
					if n := mapValue(row, "name"); n != nil {
						name = n.Value
					}
				}
			}
		}
	}
	return found, name, nil
}
