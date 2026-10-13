// h-guard 是 coding agent 的安全护栏。用法见 h-guard help。
package main

import (
	"os"

	"github.com/cyberchen1995/h-guard/internal/app"
)

func main() {
	os.Exit(app.Main(os.Args[1:], app.Options{}))
}
