package judge

import (
	"fmt"
	"maps"
	"slices"
	"sync"

	"github.com/cyberchen1995/h-guard/pkg/guard"
)

// Factory 按配置创建后端。name 是配置里的后端名（如 jev）；
// decode 把该后端的配置解码进调用方传入的指针，与具体配置格式无关。
type Factory func(name string, decode func(v any) error) (Backend, error)

var (
	typesMu sync.RWMutex
	types   = map[string]Factory{}
)

// RegisterType 注册一种后端类型（如 typesafe、openai）。f 为 nil、名字非法或重复时返回错误。
func RegisterType(typ string, f Factory) error {
	if f == nil {
		return fmt.Errorf("judge: nil factory for backend type %q", typ)
	}
	if !guard.ValidName(typ) {
		return fmt.Errorf("judge: invalid backend type %q", typ)
	}
	typesMu.Lock()
	defer typesMu.Unlock()
	if _, dup := types[typ]; dup {
		return fmt.Errorf("judge: backend type %q already registered", typ)
	}
	types[typ] = f
	return nil
}

// LookupType 返回已注册的后端类型。
func LookupType(typ string) (Factory, bool) {
	typesMu.RLock()
	defer typesMu.RUnlock()
	f, ok := types[typ]
	return f, ok
}

// Types 返回已注册的后端类型名，按字母排序。
func Types() []string {
	typesMu.RLock()
	defer typesMu.RUnlock()
	return slices.Sorted(maps.Keys(types))
}
