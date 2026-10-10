package harness_test

import (
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/cyberchen1995/h-guard/pkg/guard"
	"github.com/cyberchen1995/h-guard/pkg/harness"
)

type namedAdapter struct{ name string }

func (a namedAdapter) Name() string { return a.name }
func (namedAdapter) Capabilities() harness.Caps {
	return harness.Caps{MinVersion: "1", Events: map[guard.EventKind]harness.EventCaps{guard.EventAction: {Block: true}}}
}
func (namedAdapter) Parse([]byte) (guard.Event, error)               { return guard.Event{}, nil }
func (namedAdapter) CapsFor(guard.Event) harness.EventCaps           { return harness.EventCaps{} }
func (namedAdapter) Render(guard.Event, guard.Outcome) ([]byte, int) { return nil, 0 }

func TestRegister(t *testing.T) {
	name := "test-adapter-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	if err := harness.Register(namedAdapter{name}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := harness.Register(namedAdapter{name}); err == nil {
		t.Error("duplicate adapter accepted")
	}
	if err := harness.Register(namedAdapter{"Bad Name"}); err == nil {
		t.Error("invalid name accepted")
	}
	if err := harness.Register(nil); err == nil {
		t.Error("nil adapter accepted")
	}
	if a, ok := harness.Lookup(name); !ok || a.Name() != name {
		t.Error("Lookup did not return the registered adapter")
	}
	if _, ok := harness.Lookup("missing-adapter"); ok {
		t.Error("Lookup found an unregistered adapter")
	}
	names := harness.Names()
	if !slices.Contains(names, name) || !slices.IsSorted(names) {
		t.Errorf("Names() = %v, want sorted and containing %q", names, name)
	}
}
