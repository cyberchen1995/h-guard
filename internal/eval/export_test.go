package eval

import "github.com/cyberchen1995/h-guard/pkg/guard"

// 测试钩子：只在测试里可见。
var ThresholdKey = thKey

var LegalRange = legalRange

var Within = func(a, best Score, runs int) bool { return a.within(best, runs) }

var Better = func(a, b Score) bool { return a.better(b) }

// CorpusFiles 暴露阈值扫描读取的内置语料文件。
func CorpusFiles() map[guard.Shell]string { return corpusFiles }
