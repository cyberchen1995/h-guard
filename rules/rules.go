// Package rules 是内置规则包，以 go:embed 打包进二进制。
// 每条规则一个 YAML 文件，格式见 internal/rules（action/ 是动作规则，outbound/ 是提示词与工具输出的规则）；用户目录中同 id 的规则整条覆盖（硬规则除外）。
package rules

import "embed"

// FS 是内置规则包。
//
//go:embed action/*.yaml outbound/*.yaml
var FS embed.FS
