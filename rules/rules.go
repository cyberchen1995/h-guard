// Package rules 是内置规则包（spec §5.2），以 go:embed 打包进二进制。
// 每条规则一个 YAML 文件，格式见 internal/rules；用户目录中同 id 的规则整条覆盖（硬规则除外）。
package rules

import "embed"

// FS 是内置规则包。
//
//go:embed action/*.yaml
var FS embed.FS
