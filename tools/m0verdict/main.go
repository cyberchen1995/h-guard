// Command m0verdict 根据录制脚本采集的事实，按前提、正对照与文档预期判定每个覆盖单元（spec §7.5）：
// pass、fail、inconclusive 或 observed。
package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	harnessName := flag.String("harness", "", "claudecode 或 codex（必填）")
	factsPath := flag.String("facts", "", "录制脚本写的事实表（必填）")
	flag.Parse()
	f, err := os.Open(*factsPath)
	if err != nil {
		fail(err)
	}
	facts, err := ReadFacts(f)
	_ = f.Close()
	if err != nil {
		fail(err)
	}
	vs, err := Judge(*harnessName, facts)
	if err != nil {
		fail(err)
	}
	if err := WriteMarkdown(os.Stdout, vs, facts); err != nil {
		fail(err)
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "m0verdict:", err)
	os.Exit(1)
}
