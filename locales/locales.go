// Package locales 内嵌消息目录：每种语言一个 YAML 文件，键到模板的映射，
// 模板中的 {name} 由参数替换。
package locales

import "embed"

// FS 是全部消息目录。文件名（去掉 .yaml）即语言标识，如 en、zh-CN。
//
//go:embed *.yaml
var FS embed.FS
