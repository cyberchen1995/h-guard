package harness

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"sync"

	"github.com/cyberchen1995/h-guard/pkg/guard"
)

var (
	adaptersMu sync.RWMutex
	adapters   = map[string]Adapter{}
)

// Register 注册一个 adapter。a 为 nil、名字非法或重复时返回错误。
func Register(a Adapter) error {
	if a == nil {
		return errors.New("harness: nil adapter")
	}
	name := a.Name()
	if !guard.ValidName(name) {
		return fmt.Errorf("harness: invalid adapter name %q", name)
	}
	adaptersMu.Lock()
	defer adaptersMu.Unlock()
	if _, dup := adapters[name]; dup {
		return fmt.Errorf("harness: adapter %q already registered", name)
	}
	adapters[name] = a
	return nil
}

// Lookup 返回已注册的 adapter。
func Lookup(name string) (Adapter, bool) {
	adaptersMu.RLock()
	defer adaptersMu.RUnlock()
	a, ok := adapters[name]
	return a, ok
}

// Names 返回已注册的 adapter 名，按字母排序。
func Names() []string {
	adaptersMu.RLock()
	defer adaptersMu.RUnlock()
	return slices.Sorted(maps.Keys(adapters))
}
