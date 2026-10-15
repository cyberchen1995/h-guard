package install

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"go.yaml.in/yaml/v3"
)

// HarnessShell 计划把 harnesses.<harness>.shell 写进 h-guard 的配置文件（<config_dir>/config.yaml，spec §5.3、§12）：
// 文件不存在时新建（version: 1）；已有的配置与注释保留（YAML 的排版可能被规整）。
func HarnessShell(t Target, harness, shell string) (Step, error) {
	path := filepath.Join(t.ConfigDir, "config.yaml")
	change := func(old []byte, exists bool) ([]byte, error) { return setHarnessShell(old, exists, harness, shell) }
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
	return Step{Path: path, Summary: fmt.Sprintf("set harnesses.%s.shell to %s", harness, shell), Preview: preview,
		changes: !bytes.Equal(preview, old), lockDir: ed.LockDir,
		apply: func() error {
			if _, err := ed.editLocked(path, change); err != nil {
				return fmt.Errorf("%s: %w", path, err)
			}
			return nil
		}}, nil
}

func setHarnessShell(old []byte, exists bool, harness, shell string) ([]byte, error) {
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
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return nil, errors.New("the config is not a mapping")
	}
	harnesses := setKey(root, "harnesses")
	if harnesses.Kind != yaml.MappingNode {
		if harnesses.Kind != 0 && !(harnesses.Kind == yaml.ScalarNode && harnesses.Tag == "!!null") {
			return nil, errors.New("harnesses is not a mapping")
		}
		*harnesses = yaml.Node{Kind: yaml.MappingNode}
	}
	h := setKey(harnesses, harness)
	if h.Kind != yaml.MappingNode {
		if h.Kind != 0 && !(h.Kind == yaml.ScalarNode && h.Tag == "!!null") {
			return nil, fmt.Errorf("harnesses.%s is not a mapping", harness)
		}
		*h = yaml.Node{Kind: yaml.MappingNode}
	}
	s := setKey(h, "shell")
	if s.Kind == yaml.ScalarNode && s.Value == shell && exists {
		return old, nil
	}
	s.SetString(shell)
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
