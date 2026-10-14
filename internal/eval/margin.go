package eval

// Margin 是一条结论离翻转最近的阈值变化（Task 4 实现 Margins）。
type Margin struct {
	Known bool    // 该条结论随阈值变化（见 Outcome.Calibratable）
	Param string  // 使结论翻转的阈值名；在合法范围与 marginReach 内没有翻转时为空
	Delta float64 // 离翻转的最小距离；Param 为空时为 marginReach
}
