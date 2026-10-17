package outbound_test

import (
	"reflect"
	"testing"

	"github.com/cyberchen1995/h-guard/internal/check/outbound"
	"github.com/cyberchen1995/h-guard/internal/config"
	"github.com/cyberchen1995/h-guard/pkg/judge"
)

// TestOutboundQuestionsDigestIsPinned：outbound 内置题集（credentials、private_key、pii 三个类别题）的指纹固定。
// 改了措辞要重新校准全部带 outbound 阈值的内置档案，并更新这个常量与发布说明。
func TestOutboundQuestionsDigestIsPinned(t *testing.T) {
	qs := outbound.BuiltinQuestions()
	if got := config.QuestionsDigest(qs); got != outbound.BuiltinQuestionsDigest {
		t.Errorf("outbound question set digest = %s, pinned %s: rewording the questions needs every built-in profile's outbound threshold recalibrated", got, outbound.BuiltinQuestionsDigest)
	}
	if len(qs) != 3 {
		t.Fatalf("questions = %d", len(qs))
	}
	for _, q := range qs {
		if q.Kind != judge.KindProbability || q.Instructions.Question == "" || q.Instructions.CountsAsYes == "" || q.Instructions.CountsAsNo == "" {
			t.Errorf("%s: %+v", q.ID, q)
		}
	}
}

// TestCategoryQuestion：内置类别用内置题（配置里写了 question 时用配置的，不在指纹内）；自定义类别只有写了
// question 才有题；题目 ID 是 outbound.<类别>。
func TestCategoryQuestion(t *testing.T) {
	c := newCheck(t, "outbound: {categories: {acme: {question: {question: 'Does `text` mention Project Falcon?'}}, pii: {enabled: true}}}\n", nil)
	for name, want := range map[string]bool{"credentials": true, "private_key": true, "pii": true, "acme": true, "other": false} {
		q, ok := c.Question(name)
		if ok != want || ok && (q.ID != "outbound."+name || q.Kind != judge.KindProbability) {
			t.Errorf("%s: %+v %v", name, q, ok)
		}
	}
	builtin, _ := c.Question("credentials")
	if !reflect.DeepEqual(builtin, outbound.BuiltinQuestions()[0]) {
		t.Errorf("credentials question = %+v", builtin)
	}
	c = newCheck(t, "outbound: {categories: {credentials: {question: {question: 'Custom?'}}}}\n", nil)
	if q, _ := c.Question("credentials"); q.Instructions.Question != "Custom?" {
		t.Errorf("overridden: %+v", q)
	}
}
