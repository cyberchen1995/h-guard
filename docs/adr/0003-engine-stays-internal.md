# ADR 0003：Engine 的组装 API 首版留在 internal

- 状态：已采纳
- 日期：2026-10-17

## 背景

第三方扩展 h-guard 有三种方式，按需要的工作量从小到大：

- **配置与规则包。** 用 YAML 写规则包（action 与 outbound 两类）、调整类别的启用与动作、配置判断后端与校准档案。不需要写代码；`schema/` 里有编辑器用的 JSON Schema，`config validate` 会运行规则包里的样例。
- **exec 协议。** 判断后端 `exec` 把问题以 `h-guard.judge/v1` 交给外部程序，从 stdout 读回答案；harness 一侧的薄扩展按 `h-guard.ext/v1` 把原始事件转交给 h-guard 二进制。任何语言都能实现。
- **Go 库。** `pkg/` 下的公开包（`guard`、`harness`、`judge`、`detect`）让第三方在自己的 module 里实现 harness 的 adapter、`guard.Check` 和判断后端，并通过注册表接入。

第三方只靠 `pkg/` 就能做到这些，由 `internal/apicheck` 保证：它在一个独立的 module（`testdata/extmod`，只通过 `replace` 指向本仓库、只导入 `pkg/`）里编译并测试一个自定义 adapter、Check 与后端。

没有公开的是把这些部件组装起来的那一层：`internal/engine` 的 `Engine`（运行 Check、聚合结论、渲染原因、处理降级）和 `internal/app` 的入口（读配置、装配后端与规则、读写同意与日志）。第三方想要“自己的 h-guard 二进制，加上自己的 Check”，目前需要的是这一层。

## 决定

首版不公开 Engine 的组装 API。`internal/engine` 与 `internal/app` 留在 `internal/`。

需要组装自己的二进制时，fork 本仓库，改 `cmd/h-guard` 与 `internal/app`：在入口注册自己的 adapter、Check 或后端，其余照用。只需要新增规则、判断后端或 harness 接入的，用上面的前两种方式或 `pkg/` 即可，不需要 fork。

理由：

- 组装层还在变。降级方式、同意范围、决策日志与 outbound 判断层的接入点在首版前后都有调整；现在公开它，会把这些形状冻结成兼容性承诺。
- 公开的 API 一旦被依赖就难以收紧。h-guard 的结论只会变严，不会变松，而 Engine 的组装方式（Check 的顺序、聚合、失败时的降级）正是这条保证的一部分；让外部代码任意组装，需要先把哪些部分可以替换、哪些必须固定想清楚。
- 目前没有真实的嵌入需求。已知的扩展需求都能用 `pkg/` 满足。

## 后果

- `internal/engine` 和 `internal/app` 可以自由重构，不产生兼容性负担。
- 想把 h-guard 当库嵌入到别的程序、自己组装 Engine 的使用者，现在只能 fork；升级时要自己合并 `cmd/h-guard` 与 `internal/app` 的变化。
- `pkg/` 在 v1.0 之前仍可能有不兼容变更，会记入 `CHANGELOG.md`。
- 出现实际的嵌入需求时，再为 Engine 设计公开 API，并另写一篇 ADR 说明接口、哪些部分可替换以及如何保持“只变严”的保证。
