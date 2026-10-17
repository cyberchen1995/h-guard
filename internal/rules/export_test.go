package rules

// ParseBuiltin 按内置规则解析 data（可用 locked），供测试内置规则才允许的写法。
func ParseBuiltin(data []byte) (*Rule, error) { return parseRule(data, "builtin:test.yaml", true) }
