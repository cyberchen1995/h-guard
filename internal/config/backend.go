package config

import (
	"errors"
	"fmt"
	"strings"

	"github.com/cyberchen1995/h-guard/pkg/judge"
	"go.yaml.in/yaml/v3"
)

// BackendConfig 是 backends.<name> 的一项：type 与 profile 由框架使用，其余字段原样交给该类型的
// 工厂严格解码（judge.Factory 的 decode），所以每种后端的未知字段同样报错。
type BackendConfig struct {
	Type    string
	Profile string
	options yaml.Node
}

// UnmarshalYAML 取出 type、profile，其余字段留给后端工厂。
func (b *BackendConfig) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind != yaml.MappingNode {
		return fmt.Errorf("line %d: a backend must be a mapping", n.Line)
	}
	*b = BackendConfig{options: yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}}
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, v := n.Content[i], n.Content[i+1]
		switch k.Value {
		case "type":
			if err := v.Decode(&b.Type); err != nil {
				return err
			}
		case "profile":
			if err := v.Decode(&b.Profile); err != nil {
				return err
			}
		default:
			b.options.Content = append(b.options.Content, k, v)
		}
	}
	if b.Type == "" {
		return fmt.Errorf("line %d: backend type is missing", n.Line)
	}
	return nil
}

// Decode 把后端自己的字段严格解码进 v（未知字段报错）。
func (b BackendConfig) Decode(v any) error {
	opts := b.options
	if opts.Kind == 0 {
		opts = yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	}
	data, err := yaml.Marshal(&opts)
	if err != nil {
		return err
	}
	if err := strictDecode(data, v); err != nil {
		// 行号指向重新序列化后的片段，没有意义，只保留说明；原值不回显
		issues := yamlIssues(err)
		msgs := make([]string, len(issues))
		for i, is := range issues {
			msgs[i] = is.Msg
		}
		return errors.New(strings.Join(msgs, "; "))
	}
	return nil
}

// NewBackend 按配置创建名为 name 的后端。只构造对象，不发起任何网络请求。
func (c *Config) NewBackend(name string) (judge.Backend, error) {
	bc, ok := c.Backends[name]
	if !ok {
		return nil, errors.New("no such backend")
	}
	f, ok := judge.LookupType(bc.Type)
	if !ok {
		return nil, fmt.Errorf("unknown backend type (known: %s)", strings.Join(judge.Types(), ", "))
	}
	return f(name, bc.Decode)
}

// Option 返回后端自己的字段 key 的标量值；没有或不是标量时为空。
func (b BackendConfig) Option(key string) string {
	for i := 0; i+1 < len(b.options.Content); i += 2 {
		if k, v := b.options.Content[i], b.options.Content[i+1]; k.Value == key && v.Kind == yaml.ScalarNode {
			return v.Value
		}
	}
	return ""
}
