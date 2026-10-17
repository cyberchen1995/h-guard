package eval

// 测试钩子：只在测试里可见。
var ThresholdKey = thKey

var LegalRange = legalRange

var Within = func(a, best Score, runs int) bool { return a.within(best, runs) }

var Better = func(a, b Score) bool { return a.better(b) }
