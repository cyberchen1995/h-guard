# picoclaw 接入调研

- 状态：调研结论，尚未实现
- 日期：2026-10-20
- 调研对象：[sipeed/picoclaw](https://github.com/sipeed/picoclaw) `main`，commit `bbf6893`（2026-08-19），最新 tag `v0.3.1`。本文引用的源码路径都相对于 picoclaw 仓库。

## 结论

picoclaw 可以接入，而且比 OpenClaw 与 Hermes 都省事：它自带一个**进程外 hook 协议**（JSON-RPC 2.0，每行一条消息，走 stdio），覆盖工具调用前、工具审批、工具结果、每次模型调用前四个同步拦截点，决定由 picoclaw 自己落实。h-guard 不需要再写任何扩展脚本（没有 `.mjs`、`.py` 要内嵌），只要：

1. 让 `h-guard hook picoclaw` 以常驻进程的方式讲这套 JSON-RPC（这是新东西：现有 harness 都是一事件一进程）；
2. 写一个 `picoclaw` adapter，把四个 hook 的参数解析成 h-guard 的事件，把结论渲染成 JSON-RPC 的 `result`；
3. `install picoclaw` 往 `$PICOCLAW_HOME/config.json` 的 `hooks.processes` 写一条记录。

能做到的事与 Codex 相当：动作能拦（deny），不能问（ask 降为 deny），不能向用户显示警告；提示词能挡在模型之前；工具结果能替换。与其他 harness 的差别集中在三点：审批 hook 是 fail-closed 的（可作兜底）、提示词原文会留在会话里每轮重发（adapter 要每轮重新遮蔽）、定时任务里的 shell 命令在 hook 之外执行（只能在排程时检查）。

建议做。工作量按 Hermes 的接入估计：adapter 与常驻进程约一千行 Go（含测试），`install`/`status` 几百行，文档与冒烟测试一到两天。下面是依据。

## picoclaw 是什么

单个 Go 二进制的个人 agent，面向低资源设备（官方宣传 10 MB 内存）。运行形态：

| 形态 | 入口 | 说明 |
|---|---|---|
| Gateway | `picoclaw gateway` | 常驻进程，接 Telegram、Discord、飞书、企业微信、Slack、LINE、钉钉、Matrix、WhatsApp 等渠道，也承载 Web UI 的 `pico` 渠道、cron 与心跳 |
| CLI | `picoclaw agent -m "…"` 或交互模式 | 一次性进程，用同一个 `AgentLoop`，渠道名 `cli` |

配置是 `$PICOCLAW_HOME/config.json`（默认 `~/.picoclaw`），纯 JSON，由 `encoding/json` 读写（`pkg/config/config.go`）。工作区默认 `~/.picoclaw/workspace`，每个 agent 可以有自己的工作区（`agents.defaults.workspace`、`agents.list[].workspace`）。

picoclaw 自带的防护，与 h-guard 的关系：

- **`exec` 默认只许内部渠道**（`cli`、`system`、`subagent`）调用，`tools.exec.allow_remote` 才向聊天渠道开放（`pkg/tools/shell.go` `executeRun`，GHSA-pv8c-p6jf-3fpp）。所以 Gateway 里来自聊天的 `exec` 默认已经被 picoclaw 自己拒绝，h-guard 在 Gateway 的主要价值在文件工具、提示词与工具结果，以及打开 `allow_remote` 之后的命令检查。
- **命令黑名单**（`tools.exec.enable_deny_patterns`，正则：`rm -rf`、`sudo`、`git push`、`curl | sh`、`$(…)` 等）与 **工作区限制**（`agents.defaults.restrict_to_workspace`，默认开；`tools.allow_read_paths`、`allow_write_paths` 放行例外）。这些在工具执行内部生效，在所有 hook 之后，不影响 h-guard 看到的内容。
- **敏感值过滤**（`tools.filter_sensitive_data`，默认开）：把配置里的 API key 等已知值从工具结果里替换掉，在 `after_tool` 之后再做一遍。它只认配置里的值，不认形态；h-guard 的凭据检测是补充。

## 接入点：进程外 hook

实现在 `pkg/agent/hooks.go`、`hook_process.go`、`hook_mount.go`；协议文档在 `docs/architecture/hooks/hook-json-protocol.md`。要点：

**配置。** `hooks.enabled`（默认 `true`）；`hooks.processes.<name>`：`enabled`、`priority`、`transport`（只有 `stdio`）、`command`（argv 数组，不经 shell）、`dir`、`env`、`observe`（事件通知）、`intercept`（`before_llm`、`after_llm`、`before_tool`、`after_tool`、`approve_tool` 的子集）。超时只有全局的 `hooks.defaults`：`interceptor_timeout_ms`（默认 5000）、`approval_timeout_ms`（默认 60000）、`observer_timeout_ms`（500）。

**生命周期。** `AgentLoop` 第一次处理消息时（`ensureHooksInitialized`，`sync.Once`）启动所有进程 hook，Gateway 与 CLI 都是；进程常驻，`Close` 时关 stdin、2 秒后 kill。启动后 5 秒内必须答复 `hook.hello`，否则进程被杀、挂载失败。**任何一个 hook 启动失败都会让这个 `AgentLoop` 之后的每条消息都报错**（`initErr` 被记住，用户收到 `Error processing message: start process hook "h-guard": …`）。这是 fail-closed，但也意味着 h-guard 二进制被移走或损坏时 picoclaw 整体不可用，`status` 要能指出来。进程中途退出不会重启，之后每个请求都按失败处理。

**进程环境。** 子进程继承 Gateway 的全部环境变量（含模型 API key）再加 `env`；`dir` 是工作目录。通过 `isolation.Start` 启动：`isolation.enabled`（默认关）打开时在 Linux 上用命名空间隔离，HOME 等目录被重定向到实例目录，h-guard 会找不到自己的 `XDG_CONFIG_HOME`/`~/.config/h-guard`。`install` 要检查这一项：开着时提示用 `isolation.expose_paths` 暴露 h-guard 的配置与缓存目录，或在 `env` 里设 `XDG_CONFIG_HOME` 与 `XDG_CACHE_HOME`。

**传输。** picoclaw → hook 的请求每行一条，长度不限；hook → picoclaw 的回复每行最多 **1 MiB**（`processHookReadBufferSize`），超过时读循环退出、所有未决请求失败。stderr 逐行写进 Gateway 日志（warn 级别）。请求按 `id` 对应，可能并发（多个会话同时运行 turn），回复顺序不要求。

**hook 点、能返回的动作、失败时的行为：**

| hook | 时机 | 参数 | 可返回 | 超时与失败 |
|---|---|---|---|---|
| `hook.before_llm` | 每次调用模型前 | `meta`、`context`、`model`、完整 `messages`、`tools`、`options` | `continue`、`modify`（改 `request`）、`abort_turn`、`hard_abort` | interceptor 超时；失败或超时**跳过**这个 hook，继续（fail-open） |
| `hook.after_llm` | 模型回复后 | `response` | 同上 | 同上 |
| `hook.before_tool` | 工具执行前 | `tool`、`arguments`、`meta`、`context` | `continue`、`modify`、`respond`、`deny_tool`、`abort_turn`、`hard_abort` | 同上（fail-open） |
| `hook.approve_tool` | `before_tool` 之后、执行前 | `tool`、`arguments`（已含其他 hook 的改动）、`meta`、`context` | `{approved, reason}` | approval 超时；失败或超时**拒绝**执行（fail-closed） |
| `hook.after_tool` | 工具执行后 | `tool`、`arguments`、`result`（`for_llm` 等）、`duration` | `continue`、`modify`（换 `result`）、`abort_turn`、`hard_abort` | interceptor 超时（fail-open） |
| `hook.runtime_event` | 事件通知 | `kind`、`scope`、`payload` | 无回复 | 无 |

`modify` 对 `before_llm` 有限制：系统消息与工具定义改了会被还原（`applyBeforeLLMControls`），用户消息可以改。`meta` 字段没有 JSON tag，键是 `AgentID`、`TurnID`、`ParentTurnID`、`SessionKey`、`Iteration` 等。`context` 是 `{inbound: {channel, chat_id, sender_id, …}, route: {AgentID, Channel, …}, scope}`，没有工作区路径。

**决定落地后用户与模型看到什么**（`pkg/agent/pipeline_execute.go`、`pipeline_llm.go`、`turn_coord.go`）：

- `deny_tool`：工具不执行，模型读到一条 tool 消息 `Tool execution denied by hook: <reason>`，turn 继续。`approved: false` 同理，前缀是 `Tool execution denied by approval hook`。两者都写进会话历史。
- `after_tool` `modify`：返回的 `result.for_llm` 代替原结果进入模型上下文与会话历史（picoclaw 的敏感值过滤随后再过一遍）。`is_error` 可一并设置。
- `abort_turn`：turn 以错误结束，渠道里用户收到固定文本 `Error processing message: hook requested turn abort`（`formatProcessingError`），**不带 hook 的 reason**；这轮已写入会话的消息（用户消息在循环开始前就已写入，`pipeline_setup.go`）留在历史里。
- `hard_abort`：名字叫“停整个 loop”，实际是取消这个 turn（`requestHardAbort` 取消 turn 与 provider 的 context），然后 `abortTurn` 把会话**恢复到 turn 开始前**（`restoreSession`），用户什么也收不到。
- `respond`：hook 自己给出工具结果、跳过执行与审批。h-guard 不用它。

**会话与来源。** `meta.SessionKey` 是会话 id；`context.inbound.sender_id` 为 `cron`、`heartbeat` 时是定时与心跳运行；渠道 `system` 是异步工具结果与系统消息；`meta.ParentTurnID` 非空是子 agent 的 sub-turn。`spawn`、`subagent`、`delegate` 都走 `SubTurn`（`agent_init.go` 为三者都 `SetSpawner(NewSubTurnSpawner(al))`），与主 turn 同一条流水线，hook 照常触发。运行中到达的消息（steering）在下一次模型调用前以 `user` 角色追加进 `messages`，`before_llm` 能看到，没有 OpenClaw `steer` 模式那样的盲区。

**定时任务的命令在 hook 之外执行。** `cron` 工具创建的任务可以带 `command`（需要 `tools.cron.allow_command` 与 `command_confirm`）。任务触发时 `pkg/tools/cron.go` 直接调用 `execTool.Execute`，不经过 agent 循环，hook 看不到。只有创建任务那一次 `cron` 调用（`action: add|update`，参数里有 `command`）经过 `before_tool`/`approve_tool`，h-guard 要在那时把 `command` 当作 exec 动作检查；h-guard 安装前已经存在的任务不会被检查。带 `message` 的任务触发时会发起一个新的 turn（`ProcessDirectWithChannel`，sender `cron`），照常检查。

## 工具清单与动作映射

picoclaw 自带的工具（`pkg/tools`，按 `Name()`）：

| 工具 | 参数 | h-guard 动作 |
|---|---|---|
| `exec` | `action`（`run`、`list`、`poll`、`read`、`write`、`kill`、`send-keys`）、`command`、`cwd`、`pty`、`background`、`timeout` | `run`：`exec`，shell 按平台定（Unix `sh -c`，Windows `powershell -NoProfile -NonInteractive -Command`），`cwd` 相对工作区；`write`（`data`）、`send-keys`（`keys`）是向运行中的进程写入，按 POSIX 命令检查并总是请求确认（与 Hermes 的 `process_manage write` 一样）；`kill` 请求确认；`list`、`poll`、`read` 放行 |
| `read_file`、`list_dir`、`load_image` | `path` | `file_read` |
| `write_file`、`append_file` | `path`、`content` | `file_write` |
| `edit_file` | `path`、`old_text`、`new_text` | `file_write` |
| `send_file` | `path` | `file_read`（文件离开本机） |
| `message` | `content`、`media[]`（本地路径或 URL） | 本地附件按 `file_read` |
| `cron` | `action`、`command`、`message`、… | `add`/`update` 带 `command` 时按 `exec` 检查（见上）；其余放行 |
| `web_search`、`web_fetch`、`find_skills`、`spawn_status`、`reaction` | | 放行 |
| `spawn`、`subagent`、`delegate` | `task`、`agent_id` | 放行：子 turn 里的每次调用自己会被检查 |
| `install_skill`、`clawhub` | 从仓库下载并写入 `skills/` | 请求确认（`tool_unknown`） |
| `serial`、`spi`、`i2c` | 硬件设备 | 请求确认（`tool_unknown`） |
| `send_tts` | | 放行 |
| MCP 工具 | | 按其他 harness 的惯例放行；命名规则实现时在 `pkg/agent/agent_mcp.go` 核对 |

未列出的名字请求确认，`harnesses.picoclaw.read_only_tools` 可放行。

**工作目录。** hook 参数里没有工作区。picoclaw 把 `exec` 的 `cwd` 与文件工具的相对路径都按 agent 的工作区解析。h-guard 的常驻进程继承 Gateway 的 `PICOCLAW_HOME`，可以读 `config.json` 取 `agents.defaults.workspace` 与 `agents.list[].workspace`，按 `meta.AgentID` 选；读不到时相对路径按“无法解析”请求确认。这与 OpenClaw adapter 读 `openclaw.json` 的做法一致。

## 事件映射与决定的落地

| h-guard 事件 | picoclaw hook | 落地 |
|---|---|---|
| 动作 | `approve_tool`（主）| `deny` → `{approved: false, reason}`，模型读到原因；`ask` → 按 `policy.when_ask_unsupported` 变成 `deny`（`ask_unsupported`）；`warn` → 只能记日志（`warn_undelivered`） |
| 工具结果 | `after_tool` | `deny` → `modify`，`result.for_llm` 换成 h-guard 的说明，`is_error: true`；`warn` → 日志 |
| 提示词 | `before_llm` | `deny` → `modify`，把这一轮新的用户消息内容换成 h-guard 的说明（模型只读到说明，仍会回答；会话里保留原文，与 pi 的 `context` 事件相同）；`warn` → 可以在用户消息前加一句说明给模型（像 Claude Code 与 Hermes 那样），或只记日志 |

几个设计选择的理由：

**用 `approve_tool` 而不是 `before_tool` 检查动作。** `approve_tool` 在所有 `before_tool` 之后运行，看到的是其他 hook 改动后的最终参数；它失败或超时时 picoclaw 拒绝执行，是安全方向；预算是 60 秒，够判断后端用。`before_tool` 则相反：失败就跳过（fail-open），5 秒预算，而且排在前面的 hook 返回 `respond` 时链条中断，后面的 hook 根本看不到。h-guard 不需要同时注册 `before_tool`。唯一绕过 `approve_tool` 的是别的 hook 的 `respond`，这是 picoclaw 自己文档里承认的设计缺口，h-guard 无法弥补，文档里写明。

**提示词用 `modify` 而不是 `abort_turn`。** `abort_turn` 给用户的是固定的错误文本，没有原因；`hard_abort` 把会话回滚、用户什么也看不到；两者都不如把说明交给模型让它回复用户。代价是原文留在会话历史里，**之后每一轮的 `before_llm` 都会再带上它**，adapter 必须每次重新遮蔽。做法：常驻进程按会话记住被拒消息的指纹（文本哈希），后续调用里凡是命中的用户消息直接替换，不再重新检查（不再触发判断后端）。只检查新消息：每个 turn 第一次调用时取最后一条 assistant 消息之后的 `user` 消息，之后的迭代只取上次调用以后追加的 `user` 消息（steering）。

**失败行为**与其他扩展 harness 一致：动作检查失败时工具被拒（picoclaw 自己做的）；工具结果与提示词检查失败时放行，但没有向用户说明的途径，只能进 Gateway 日志。

**不能做的事。** picoclaw 没有向用户确认的机制（其文档明确列为未支持：“Suspending a turn and waiting for human approval replies”），hook 也不能主动发消息、没有 `picoclaw send` 之类的命令行，所以没有确认、没有警告、没有频道通知。`h-guard allow` 的一次性放行目前只对 Codex 开放（`internal/app/hook.go` 按 adapter 名判断），接入 picoclaw 时可以一起放开给“不能问”的 harness，这是另一处改动。

## h-guard 侧要做的事

1. **常驻进程模式。** `h-guard hook picoclaw` 读 stdin 的 JSON-RPC 行：回答 `hook.hello`，忽略 `hook.runtime_event`，对每个拦截请求**启动一个子进程** `h-guard hook picoclaw --event <hook>`（与现有一事件一进程的模型相同：每次重新读配置与规则，沿用预算、看门狗、健康记录与决策日志），把子进程的回复包进 `{"jsonrpc":"2.0","id":…,"result":…}` 写回。并发请求各自一个子进程，天然隔离。读 stdin 要用大缓冲（`before_llm` 带完整历史，h-guard 的输入上限是 16 MiB）。stdout 上不能写任何别的东西。回复要控制在 1 MiB 内。
2. **`picoclaw` adapter**（`pkg/harness/picoclaw`）：`Parse` 读 `approve_tool`、`after_tool`、`before_llm` 的参数，`Render` 输出对应的 `result` 对象（`{approved, reason}`、`{action: "modify", result: …}`、`{action: "modify", request: …}` 或 `{action: "continue"}`）。能力声明：动作 block 是、ask 否、warn 否；提示词 block 是；工具结果 replace 是。工作区解析与被拒消息指纹放在常驻进程这一层。
3. **`install picoclaw`**：改 `$PICOCLAW_HOME/config.json`（纯 JSON，复用 `internal/install/jsonobj.go`）：`hooks.enabled: true`；`hooks.processes["h-guard"] = {enabled: true, transport: "stdio", command: [<h-guard>, "hook", "picoclaw", "--timeout", N], intercept: ["before_llm", "approve_tool", "after_tool"]}`；`hooks.defaults.interceptor_timeout_ms` 低于 `(N+5)*1000` 时抬高（全局设置，影响其他进程 hook，文档说明），`approval_timeout_ms` 同理。`isolation.enabled` 为真时提示上面说的目录问题。之后要重启 Gateway（`picoclaw gateway`，没有 restart 子命令）；CLI 下一次启动生效。`--remove` 只删这条记录。`status` 检查记录是否存在、命令是否指向当前二进制、超时是否够，并像 Codex 一样靠 hook 运行记录判断“已验证”。
4. **`selftest picoclaw`**：不需要 picoclaw 本身，直接按协议向 `h-guard hook picoclaw` 发 `hook.hello` 与一条 `rm -rf /` 的 `approve_tool`、一条带假 API key 的 `before_llm`，检查两者都被拦。
5. **文档与测试**：`docs/guide/harnesses.md` 新增一节与能力表一列，`protocols.md` 的 hook 表加 `picoclaw` 行（请求的 `data` 就是 picoclaw 的 `params`），README 与 CHANGELOG；adapter 单元测试；冒烟测试用源码构建 picoclaw，配一个模拟的 OpenAI 兼容模型服务，以 `picoclaw agent -m` 驱动（与 OpenClaw 的做法相同）。

## 未覆盖与风险

- 定时任务的 `command` 在触发时不经过 hook；只能在排程时检查，安装前的任务不检查。
- 其他 hook 的 `respond` 绕过审批。
- `hard_abort`、`respond` 等强动作 h-guard 不用；`abort_turn` 不用。
- hook 进程持有 Gateway 的全部环境变量（含模型 API key）；h-guard 的子进程同样继承。与其他 harness 相同，判断后端的 key 也从这里来。
- `before_llm` 每次调用都带完整历史与系统提示（含工作区的 `AGENTS.md`、记忆与技能），h-guard 只检查新的用户消息，系统提示不检查。
- 图片与媒体不检查。
- 提示词被拒后原文留在会话里；用户在 picoclaw 里 `/new` 之前它一直在历史中。
- h-guard 不可用时 picoclaw 整体拒绝处理消息（启动失败）或拒绝所有工具调用（运行中失败），比其他 harness 更“硬”；`status` 与文档要说清楚。
- Windows 未验证：`exec` 用 PowerShell，命令行形式与路径引号要像 Codex 一样核对。
