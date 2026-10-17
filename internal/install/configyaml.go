package install

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Value 是要写进 h-guard 配置文件的一个标量：Path 是键的路径（如 judge、enabled），Tag 是 YAML 类型（!!str、!!bool、!!int）。
type Value struct {
	Path  []string
	Value string
	Tag   string
	// KeepExisting：键已有取值时保留用户的取值，只在没有时写入（migrate 补全后端的字段）
	KeepExisting bool
}

// ConfigValues 计划把 vals 写进 h-guard 的配置文件（<config_dir>/config.yaml）：文件不存在时新建（version: 1）；
// 已有的配置与注释保留（YAML 的排版可能被规整）；取值都已相同时不改动。
func ConfigValues(t Target, summary string, vals []Value) (Step, error) {
	path := filepath.Join(t.ConfigDir, "config.yaml")
	change := func(old []byte, exists bool) ([]byte, error) { return setValues(old, exists, vals) }
	old, err := os.ReadFile(path)
	exists := err == nil
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return Step{}, err
	}
	preview, err := change(old, exists)
	if err != nil {
		return Step{}, fmt.Errorf("%s: %w", path, err)
	}
	ed := t.editor()
	return Step{Path: path, Summary: summary, Preview: preview, changes: !bytes.Equal(preview, old), lockDir: ed.LockDir,
		apply: func() error {
			if _, err := ed.editLocked(path, change); err != nil {
				return fmt.Errorf("%s: %w", path, err)
			}
			return nil
		}}, nil
}

// HarnessShell 计划把 harnesses.<harness>.shell 写进 h-guard 的配置文件。
func HarnessShell(t Target, harness, shell string) (Step, error) {
	return ConfigValues(t, fmt.Sprintf("set harnesses.%s.shell to %s", harness, shell),
		[]Value{{Path: []string{"harnesses", harness, "shell"}, Value: shell, Tag: "!!str"}})
}

func setValues(old []byte, exists bool, vals []Value) ([]byte, error) {
	var doc yaml.Node
	if exists && len(bytes.TrimSpace(old)) > 0 {
		if err := yaml.Unmarshal(old, &doc); err != nil {
			return nil, err
		}
	}
	if doc.Kind == 0 {
		doc = yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{{Kind: yaml.MappingNode}}}
		v := setKey(doc.Content[0], "version")
		v.SetString("1")
		v.Tag = "!!int"
	}
	if doc.Content[0].Kind != yaml.MappingNode {
		return nil, errors.New("the config is not a mapping")
	}
	changed := false
	for _, val := range vals {
		node := doc.Content[0]
		for i, key := range val.Path {
			child := setKey(node, key)
			if i == len(val.Path)-1 {
				if child.Kind == yaml.ScalarNode && (child.Value == val.Value || val.KeepExisting && child.Tag != "!!null") {
					break
				}
				if child.Kind != 0 && child.Kind != yaml.ScalarNode {
					return nil, fmt.Errorf("%s is not a scalar", strings.Join(val.Path[:i+1], "."))
				}
				*child = yaml.Node{Kind: yaml.ScalarNode, Value: val.Value, Tag: val.Tag}
				changed = true
				break
			}
			if child.Kind != yaml.MappingNode {
				if child.Kind != 0 && !(child.Kind == yaml.ScalarNode && child.Tag == "!!null") {
					return nil, fmt.Errorf("%s is not a mapping", strings.Join(val.Path[:i+1], "."))
				}
				*child = yaml.Node{Kind: yaml.MappingNode}
			}
			node = child
		}
	}
	if !changed && exists {
		return old, nil
	}
	var b bytes.Buffer
	enc := yaml.NewEncoder(&b)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// setKey 返回映射 m 中 key 的值节点，没有时在末尾新增（值节点为空，由调用方填）。
func setKey(m *yaml.Node, key string) *yaml.Node {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	k := &yaml.Node{Kind: yaml.ScalarNode, Value: key}
	v := &yaml.Node{}
	m.Content = append(m.Content, k, v)
	return v
}
