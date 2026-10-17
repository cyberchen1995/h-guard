package judge

import (
	"context"
	"errors"
)

// ErrorKind 是后端错误的分类，决定重试与降级方式。
type ErrorKind string

const (
	Unavailable ErrorKind = "unavailable"
	Timeout     ErrorKind = "timeout"
	Auth        ErrorKind = "auth"
	RateLimit   ErrorKind = "rate_limit"
	BadResponse ErrorKind = "bad_response"
)

// Error 是带分类的后端错误。
type Error struct {
	Kind ErrorKind
	Err  error
}

func (e *Error) Error() string {
	if e.Err == nil {
		return "judge: " + string(e.Kind)
	}
	return "judge: " + string(e.Kind) + ": " + e.Err.Error()
}

func (e *Error) Unwrap() error { return e.Err }

// KindOf 返回 err 的分类：*Error 取其 Kind；context 超时或取消视为 Timeout；
// 其余视为 Unavailable。err 为 nil 时返回空字符串。
func KindOf(err error) ErrorKind {
	if err == nil {
		return ""
	}
	var je *Error
	if errors.As(err, &je) {
		return je.Kind
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return Timeout
	}
	return Unavailable
}
