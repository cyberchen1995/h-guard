package guardtest_test

import (
	"context"
	"strings"
	"testing"

	"github.com/cyberchen1995/h-guard/pkg/guard"
	"github.com/cyberchen1995/h-guard/pkg/guard/guardtest"
)

type denyRecursiveRM struct{}

func (denyRecursiveRM) Name() string { return "test.deny-rm" }

func (denyRecursiveRM) Applies(ev guard.Event) bool { return ev.Kind == guard.EventAction }

func (denyRecursiveRM) Evaluate(ctx context.Context, ev guard.Event, commit func(guard.Verdict)) (guard.Verdict, error) {
	if err := ctx.Err(); err != nil {
		return guard.Verdict{Decision: guard.DecisionPass}, err
	}
	for _, a := range ev.Actions {
		if a.Exec != nil && strings.Contains(a.Exec.Command, "rm -rf") {
			deny := guard.Verdict{Decision: guard.DecisionDeny}
			commit(deny) // 本地 deny 先提交，之后的步骤出错也不会丢
			return deny, nil
		}
	}
	return guard.Verdict{Decision: guard.DecisionPass}, nil
}

func TestRunCheck(t *testing.T) {
	guardtest.RunCheck(t, denyRecursiveRM{}, []guard.Event{
		{Kind: guard.EventAction, Harness: "test", Actions: []guard.Action{
			{Kind: guard.ActionExec, Exec: &guard.ExecAction{Command: "rm -rf /tmp/x", Shell: guard.ShellPOSIX}},
		}},
		{Kind: guard.EventPrompt, Harness: "test", Text: "hello"},
	})
}
