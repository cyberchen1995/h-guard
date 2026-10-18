# h-guard

[English](README.md)

**支持的 harness：** Claude Code · Codex · opencode · pi · oh-my-pi · DeepSeek Harness · Hermes Agent，其他 agent harness 可以通过 [generic JSON 契约](docs/guide/protocols.md#generic-harness-contract-v1)接入。<br>
**拦截范围：** 灾难性命令与 fork 炸弹、递归删除、破坏性 git 与分支操作、发布、绕过检查、执行编码内容、篡改护栏与读取秘密文件，以及提示词和工具输出里的凭据、私钥和个人信息（需开启）；由本地规则与判断模型共同把关，取决于你是否要求过的情况交给模型判断（[详见](#检查什么)）。

h-guard 是 agent harness 的安全护栏。它检查 agent 将要执行的操作（shell 命令与文件操作）和经过它的内容（你的提示词与工具输出），在破坏性操作执行或秘密外泄之前拒绝、请求确认或提示。

<p align="center"><img src=".github/assets/how-it-works.zh-CN.svg" alt="h-guard 工作原理" width="720"></p>

**建议搭配判断模型使用。** 本地规则只处理界限分明的情况。常见的危险操作（递归删除、破坏性 git、发布等）要由模型判断是不是你要求的、会造成多大损失，h-guard 才能只在真正危险时打断你。运行 `h-guard init`，选择 `claude-haiku`（推荐：快、已校准）或 `gemma4-local`（在本机运行、不外发，但较慢）。

> **模型默认关闭。** 模型关闭时，h-guard 只运行本地规则，不向任何地方发送数据，也不需要 API key。模型关闭时仍然生效的有：
>
> - 灾难性命令（删除 `/` 或主目录、覆写块设备、格式化文件系统）与 fork 炸弹直接拒绝；
> - 改动 h-guard 自身配置或 harness 的 hook 设置请求确认（护栏自我保护）；
> - 执行经过编码的内容（例如 `base64 -d | sh`）请求确认；
> - 用 harness 的文件工具读取通常存放秘密的文件（`.env`、私钥、`~/.ssh`、云服务凭据）请求确认；
> - 提示词里的凭据与私钥被拦下。
>
> 模型关闭时，有六类危险操作**不做判断**。`recursive_delete`、`destructive_git`、`branch_ops`、`publish`、`verify_bypass` 完全不打断：没有模型，h-guard 判断不了这个操作是不是你要求的、会造成多大损失，所以它们的本地命中只写入日志。`guard_tampering` 的本地命中仍然一律请求确认，但正则漏掉的改动没有人再看。运行 `h-guard init` 选择后端并开启模型。

## 安装

**Homebrew**（macOS）：

```sh
brew install cyberchen1995/tap/h-guard
```

**GitHub Releases。** 每个版本提供 macOS、Linux、Windows（amd64 与 arm64）的压缩包，以及 `checksums.txt` 和它的 Sigstore 签名包 `checksums.txt.sigstore.json`。先用 [cosign](https://docs.sigstore.dev/cosign/system_config/installation/) 验证校验和文件，再用它核对压缩包：

```sh
VERSION=0.1.0
BASE=https://github.com/cyberchen1995/h-guard/releases/download/v$VERSION
ARCHIVE=h-guard_${VERSION}_linux_amd64.tar.gz      # 或 darwin_arm64、windows_amd64.zip 等
curl -L -O "$BASE/$ARCHIVE" -O "$BASE/checksums.txt" -O "$BASE/checksums.txt.sigstore.json"
cosign verify-blob checksums.txt \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp '^https://github\.com/cyberchen1995/h-guard/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
sha256sum --check --ignore-missing checksums.txt    # macOS：shasum -a 256 --check --ignore-missing checksums.txt
tar -xzf "$ARCHIVE" h-guard                        # Windows 的压缩包是 zip：用 unzip 或 Expand-Archive
```

把 `h-guard` 放到 `PATH` 中的某个目录。

**从源码安装**（Go 工具链版本见 `go.mod`）：

```sh
go install github.com/cyberchen1995/h-guard/cmd/h-guard@latest
```

`h-guard version` 显示已安装的版本。

## 快速开始

把 h-guard 接入 harness。不带 `--write` 时，`install` 只显示将要做的改动；带 `--write` 时先备份每个要改的文件，再写入。

```sh
h-guard install claudecode            # 预览
h-guard install claudecode --write    # Claude Code：安装 h-guard 插件
h-guard install codex --write         # Codex：在 ~/.codex/hooks.json 中注册 hook
h-guard install opencode --write      # opencode 1.x：把插件写到 ~/.config/opencode/plugins
h-guard install pi --write            # pi：把扩展写到 ~/.pi/agent/extensions
h-guard install omp --write           # oh-my-pi：把扩展写到 ~/.omp/agent/extensions
h-guard install dsh --write           # DeepSeek Harness：在 ~/.dsh/cordis.patch.yml 中挂载插件
h-guard install hermes --write        # Hermes Agent：把插件写到 ~/.hermes/plugins 并启用
```

Codex 用户需要打开 Codex，运行 `/hooks` 检查并信任 h-guard 的 hook。新增或改动过的 hook 在信任之前不会运行。

确认它真的在保护你。`selftest` 按 harness 会运行的入口运行 h-guard，送入一条模拟的 `false && rm -rf /`（从不执行）和一条带编造 API key 的提示词，核对两者都被拦下：

```sh
h-guard selftest  # 端到端检查已安装的入口；不执行任何命令，也不向外发送
h-guard status    # 开头是保护摘要
```

`status` 开头写明你实际受到的保护。每个 harness 分开显示三层：配置已写入、harness 真正运行过 hook（h-guard 读不到 Codex 的信任状态，Codex 在真正运行 hook 之前显示「unverified」）、最近一次自测通过。随后列出哪些规则会打断、哪些只记录、哪些停用，以及哪些情况不在保护范围内。

```console
protection:
  claudecode: config written: yes | hook running: yes, last 2 min ago (PreToolUse, prompt.submit, tool.result) | self-test: passed 3 min ago
  codex: config written: yes | hook running: unverified (Codex has not run the hooks since they were installed; trust them with /hooks in Codex) | self-test: passed 3 min ago
  interrupts: catastrophic (deny), fork_bomb (deny), guard_tampering (ask), obfuscated_exec (ask), sensitive_read (ask, file tools only)
  matched but not interrupting, and not recorded (log.decisions is off) (judge off; h-guard init turns it on): branch_ops, destructive_git, publish, recursive_delete, verify_bypass
  prompts and tool output: credentials deny, private_key deny (scans prompts)
  not covered: shell commands that read secret files (cat ~/.ssh/id_rsa): ...
```

开启模型：

```sh
h-guard init      # 选择后端，查看它会收到什么，同意后开启判断
h-guard status    # 入口、判断、同意、不生效的规则、近期的降级
```

不经过 harness 试一条命令。`check` 与 hook 走同一套检查；`--no-judge` 只运行本地规则：

```console
$ h-guard check 'rm -rf /' --no-judge
decision: deny
reason: Blocked: Catastrophic operation: deleting the root or home directory, overwriting a block device, or formatting a file system [rule]. Operation: `rm -rf /`. Impact: It would destroy data that cannot be recovered: a whole file system, the home directory or a device. Safer way: If this is really intended, the user should run it themselves after checking the target.
hint: Ask the user to run it themselves.
finding: catastrophic (local)
finding: recursive_delete (local)
signals: {"action":{"judge":"off"}}
$ h-guard check 'git push origin main' --no-judge
decision: pass
finding: publish (local)
signals: {"action":{"judge":"off","judge_disabled_hits":["publish"]}}
```

第二条命令命中了 `publish`，但模型关闭时这条规则不打断。模型开启后，同一条命令会请求确认，除非你最近的提示词里要求过推送（用 `--request 'push this to origin'` 模拟）。原因与提示的语言依次取自配置的 `locale`、环境变量 `LC_ALL` 与 `LANG`，上面是英文环境下的输出；中文环境下 `reason` 与 `hint` 显示为中文。

## 拦下之后

每次打断都讲清四件事：agent 准备做什么、作用在哪里（命令与工作目录，或文件），为什么拦（命中的规则；模型开启时还有你是否要求过、影响范围），会造成什么后果，以及怎样继续。例如模型开启时：

```text
h-guard: agent 自行决定的危险操作需要确认：丢弃未提交改动或未跟踪文件的 git 操作 [正则+模型 0.97]。
影响范围 2.0/3。用户最近的指令未明确要求此操作（0.03）。操作：在 /home/me/proj 中运行 `git reset --hard HEAD~1`。
后果：这个工作区里未提交的改动或未跟踪的文件会丢失，git 无法找回。
更稳妥的做法：先保存：提交，或 git stash push --all（连 git clean -x 会删的被忽略文件一起保存）；git stash drop 或 clear 之前先记下这些条目的提交号（git stash list --format=%H），以便找回。然后再重试。
```

在 Claude Code 里这就是权限确认框的说明：确实要做就批准。Codex 不能请求确认，h-guard 改为阻止；除护栏自我保护外，原因末尾会给出单次授权：

```text
如需只运行这一次，请用户在自己的终端里运行 `h-guard allow 3f9a2c1d0e`（批准后 10 分钟内有效，
只适用于这个目录中的这条命令），然后原样重试；或请用户自己手动执行。
```

`h-guard allow` 列出最近一小时被拦下的操作；`h-guard allow <id>` 显示这次操作并在终端里请你确认。授权绑定 harness、工作目录与完整的工具输入，只适用于 shell 命令（不包括读写文件），第一次重试就用掉，10 分钟后失效（`--ttl`，最长 1 小时）。没有「接下来都允许」：不必为了继续工作关掉整个护栏。agent 不能替你批准：`allow` 只能在交互终端里确认，经由 harness 运行它会请求确认。

## 检查什么

**动作（action）** 是 agent 将要执行的命令与文件操作。内置规则：

| 规则 | 拦什么 | 结论 | 是否需要模型 |
|---|---|---|---|
| `catastrophic` | 删除 `/` 或主目录、覆写块设备、格式化文件系统 | deny | 否（锁定） |
| `fork_bomb` | fork 炸弹 | deny | 否（锁定） |
| `guard_tampering` | 改动 h-guard 的配置、同意记录、缓存或 harness 的 hook 设置 | ask | 否（锁定）；模型可以补报 |
| `obfuscated_exec` | 把编码内容交给解释器执行 | ask | 否 |
| `sensitive_read` | 用 harness 的文件工具读取 `.env`、`*.pem`、`*.key`、`id_rsa*`、`~/.ssh`、`~/.aws`、`~/.gnupg`、`~/.netrc` 等（shell 里的 `cat` 不算） | ask | 否 |
| `recursive_delete` | 递归删除文件或目录 | ask | 是 |
| `destructive_git` | 丢弃未提交改动或未跟踪文件的 git 操作 | ask | 是 |
| `branch_ops` | 改写历史、强制删除分支、改动上游 | ask | 是 |
| `publish` | push、PR/MR、release、发布包、修改远端的 API 调用 | ask | 是 |
| `verify_bypass` | 绕过 git hook、检查或签名 | ask | 是 |

模型开启后，需要模型的规则只在 agent 自作主张时打断：模型判断你最近的提示词里有没有明确要求这个操作，以及它会造成多大损失。锁定规则与 `obfuscated_exec` 不能因为你的要求而放行。

**外发（outbound）** 检查扫描你的提示词与工具输出：

| 类别 | 识别 | 默认 |
|---|---|---|
| `credentials` | 带已知前缀的 API token、Bearer token、秘密赋值、AWS access key ID、URL 中的密码（另有高熵检测器，默认关闭） | deny |
| `private_key` | PEM 私钥块 | deny |
| `pii` | 邮箱、电话号码（中国大陆与国际）、中国居民身份证号、美国 SSN、公网 IP | 关闭 |

被拦下的提示词或工具输出只报告类别、命中数与行号，原因文本里不会出现命中的原文。

**档位** 决定检查范围（锁定规则在任何档位都生效）：

| `action.tier` | 检查 | | `outbound.tier` | 扫描 |
|---|---|---|---|---|
| 1 | shell 命令 | | 1（默认） | 提示词 |
| 2（默认） | + 文件读、写、删除、重命名 | | 2 | + 工具读出的文件内容 |
| 3 | + 其他工具调用（暂无内置规则） | | 3 | + 全部工具输出 |

结论只会收紧：`deny > ask > warn > pass`。h-guard 从不回答 `allow`，所以不会越过 harness 自己的权限确认；后端出错也不会变成本地规则不会给出的放行。

## 判断后端与同意

判断层是一个模型，回答关于命令的固定问题。内置后端：

| 后端 | 类型 | 发送到 | API key |
|---|---|---|---|
| `claude-haiku`（推荐） | `anthropic` | `https://api.anthropic.com` | `ANTHROPIC_API_KEY` |
| `claude-sonnet`（推荐） | `anthropic` | `https://api.anthropic.com` | `ANTHROPIC_API_KEY` |
| `gemma4-local`（推荐） | `openai` | `http://localhost:11434/v1`（Ollama，模型 `gemma4:12b-mlx`） | 不需要 |
| `jev` | `typesafe` | `https://api.typesafe.ai` | `TYPESAFE_API_KEY` |

每个后端都带校准档案，不需要自己校准。`jev` 是默认配置里写的后端（`judge.backend: jev`）；`init` 列出全部四个。API key 放在 harness 启动 h-guard 时的环境变量里，或者 h-guard 配置目录下的 `.env` 文件（`h-guard status` 显示目录位置）。配置里只写变量名。

模型开启后，agent 运行的每条 shell 命令（已被直接拒绝的除外）都会把以下内容发给后端：

- 命令、工作目录、harness 与工具名；
- 本会话里你最近的至多 3 条提示词（`policy.request_window`）。

外发判断也开启时（模型开启后的默认设置），本地规则没有拦下、且不短于 200 字符的提示词与工具输出，会分成至多 4 块、每块至多 4000 字符发送。模型在这里的发现只作为提示，从不拦截，所以在显示不了提示的 harness（Codex）上，提示词与工具输出不会发送。h-guard 能识别的凭据、私钥与个人信息在发送前遮蔽；识别不了的原样发送。设置 `outbound.judge: false` 可以停止发送提示词与工具输出。

**同意之前不发送任何内容。** `h-guard init` 与 `h-guard backend enable <name>` 会说明将发送什么、发到哪里，并在终端里询问。同意绑定后端的名字、类型与目标（scheme、主机与端口；`exec` 后端是程序与参数），其中任何一项改变，同意即失效。本地后端同样需要同意。`h-guard backend disable <name>` 撤回同意；`h-guard backend list` 显示各后端的状态。agent 不能替你同意：经 harness 运行 `init` 或 `backend enable` 会请求确认（`backend disable` 只撤回同意，照常放行）。

## 配置

```sh
h-guard config init       # 写出带注释的 config.yaml（不覆盖已有文件）
h-guard config show       # 合并后的配置
h-guard config validate   # 检查配置并运行你的规则的样例
```

配置文件是 h-guard 配置目录下的 `config.yaml`（设置了 `XDG_CONFIG_HOME` 时为 `$XDG_CONFIG_HOME/h-guard`，否则 macOS 为 `~/Library/Application Support/h-guard`，Linux 为 `~/.config/h-guard`，Windows 为 `%AppData%\h-guard`）。模板的第一行让支持 YAML 语言服务的编辑器按 [`schema/config.schema.json`](schema/config.schema.json) 补全与检查。你自己的规则放在同一目录的 `rules/` 下。

```yaml
version: 1
judge: {enabled: true, backend: claude-haiku}
action: {tier: 2}
outbound:
  categories:
    pii: {enabled: true, action: warn}
rules:
  publish: {enabled: false}
```

全部字段见[配置指南](docs/guide/configuration.md)，写规则见[规则包指南](docs/guide/rules.md)（指南为英文）。

## 支持的版本

| Harness | 支持 | 经过验证的版本 |
|---|---|---|
| Claude Code | 2.1.290 及以上（工具输出与提示词的检查依赖 mods） | 2.1.296 |
| Codex | 经过验证的版本及以上 | 0.162.1 |
| opencode | 1.x（opencode 2.x 的插件 API 不同，不支持） | 1.19.3（冒烟测试） |
| pi | 测试过的版本及以上 | 1.3.0（冒烟测试） |
| oh-my-pi | 测试过的版本及以上 | 18.11.3（冒烟测试） |
| DeepSeek Harness | 测试过的版本及以上 | 0.2.1-rc.2（冒烟测试） |
| Hermes Agent | 测试过的版本及以上 | 2026.9.24（直接调用插件 hook） |

opencode、pi、oh-my-pi 与 DeepSeek Harness 的扩展按各 harness 的源码编写，在 CI 里用模拟的 harness API 测试，并在真实 harness 里配合模拟的模型服务做过冒烟测试（拒绝、请求确认、替换工具输出、拦下提示词）。它们还没有录制会话。Hermes Agent 的插件按 Hermes 的源码编写，在 CI 里用模拟的插件上下文测试，并由 Hermes 自己的插件管理器加载、直接调用各个 hook 验证过；还没有配合模型或消息网关运行过。

harness 版本未经验证时，`install` 与 `status` 会说明，但不拒绝。其他 agent harness 可以通过 [generic 契约](docs/guide/protocols.md#generic-harness-contract-v1)调用 h-guard。各 harness 的接入方式、能做与不能做的事见 [harness 指南](docs/guide/harnesses.md)。

平台：macOS 与 Linux。Windows 版本照常发布，Windows 相关代码在 CI 中测试，但还没有在 Windows 上与真实 harness 一起验证过。

## 已知限制

- **Codex 不支持请求确认。** Codex 的 hook 无法请求用户确认，所以那里的 `ask` 一律变成 `deny`（`policy.when_ask_unsupported`）。
- **Codex 的 hook 需要信任。** `install codex --write` 之后要在 Codex 里用 `/hooks` 信任这些 hook，否则它们不运行。h-guard 读不到 Codex 的信任状态：在 Codex 真正运行某个 hook 之前，`h-guard status` 显示为 unverified。
- **单次授权的强度取决于 agent 能碰到哪些文件。** 授权是 h-guard 缓存目录里的一条记录，用配置目录里的密钥（`grant.key`，第一次拦下可以授权的操作时生成）签名，`h-guard allow` 显示给你的被拦操作同样签了名。agent 以你的用户身份运行：读到这个密钥、再用 `guard_tampering` 认不出的写法写入一条签了名的记录，就能自己批准自己的操作。密钥让「只写缓存」不再足够，但挡不住存心绕过 h-guard 的 agent。`h-guard allow` 的终端检查也一样：agent 可以把程序复制成别的名字、在伪终端（`script -c …`）里运行它，自己回答确认。模型读取的指令缓存（作为你最近的提示词）有同样的问题。授权绑定的是被拦下的会话、完整的工具输入、工作目录的真实路径与它的文件身份，不包括命令里提到的路径在执行时指向哪里，也不包括命令读取的文件与设置（`git push origin` 推到执行那一刻 `.git/config` 里 `origin` 指向的地方）。授权也只绑定 Codex 报给 hook 的工作目录：Codex 在 hook 输入里没有写出的目录里执行命令，或目录在 hook 运行之后才建出来，授权都分辨不出。批准前请核对这些路径与目标。
- **opencode 同样不支持请求确认。** opencode 的插件 API 没有请求用户确认的办法，所以那里的 `ask` 同样变成 `deny`；提示以 TUI 的 toast 显示，`opencode run` 里看不到。
- **DeepSeek Harness 显示不了提示。** 提示只写进它的日志；被拦下的提示词直接丢弃，对话里没有说明。
- **oh-my-pi 的 `eval` 工具一律请求确认。** h-guard 读不懂 Python 与 JavaScript 代码，所以每次 `eval` 调用都需要你确认。
- **Hermes Agent 在消息平台以外拦不下提示词。** 在 CLI、TUI 或 Desktop 里输入、h-guard 本应拦下的提示词已经交给了模型；h-guard 改为在这一轮里加一段提示（`prompt_not_blocked`）。`--yolo` 或 `approvals.mode: off` 时 h-guard 的请求确认变成拒绝；除了可选的渠道通知，Hermes 没有向你显示提示的办法。
- **Hermes Agent 的 `execute_code` 一律请求确认。** 脚本能直接启动进程、改动文件，所以每次调用都需要你确认。
- **pi、oh-my-pi、DeepSeek Harness 与 Hermes Agent 上不认识的工具请求确认。** 不在 h-guard 对这几个 harness 自带工具的名单里的工具（比如扩展添加的）需要你确认，直到你把它列进 `harnesses.<name>.read_only_tools`。
- **提示词的来源靠推断。** Claude Code 会标出自动消息（定时任务、子 agent 回报）；Codex 不标，h-guard 按已知格式识别它的自动消息。识别不出的自动消息算作你本人的话，模型开启时可能被当作你对某个操作的要求。
- **Windows 没有经过实机验证。** Windows 上的路径处理、PowerShell 的 hook 外包脚本与 Codex 的命令形式只在 CI 与交叉编译中测试过。
- **路径规则只看文件工具。** `sensitive_read` 等文件规则检查的是 harness 的文件工具（Claude Code 的 Read、Codex 的补丁、generic 的文件动作）。在 shell 里读同一个文件的命令（如 `cat ~/.ssh/id_rsa`）不会被它们拦下。`outbound.tier: 2`（默认是 1）时，被识别为读文件的 shell 命令的输出会在读取之后扫描其中的凭据与私钥。
- **个人信息检测有误报。** 开发工作中邮箱与公网 IP 很常见，所以 `pii` 默认关闭。可以用类别的 `ignore` 列表或单独停用规则。
- **被拦下的内容可能留在 harness 自己的记录里。** 被拦下的提示词可能留在 harness 的本地历史中；即使 h-guard 替换了给模型看的工具输出，Codex 仍会把原输出写进它的 transcript。h-guard 无法清除这些记录。
- **副作用已经发生。** 工具输出的检查发生在工具运行之后；替换输出只改变模型看到的内容。
- **模型的回答经过校准，但没有保证。** 判断可能漏报或多打断；`h-guard status` 显示后端的阈值是否经过校准。

## 卸载

```sh
h-guard install claudecode --remove --write
h-guard install codex --remove --write
h-guard install opencode --remove --write   # pi、omp、dsh、hermes 同理
```

`--remove` 只删除 h-guard 自己的条目，harness 配置里的其他内容保持不变。之后删除程序（`brew uninstall h-guard` 或直接删除文件），如有需要再删除 h-guard 的配置目录。

## 文档

- [配置](docs/guide/configuration.md)：全部字段、合并顺序、后端与校准档案。
- [规则包](docs/guide/rules.md)：编写 action 与 outbound 规则。
- [协议](docs/guide/protocols.md)：判断 exec 协议、generic harness 契约与扩展接入协议。
- [Harness](docs/guide/harnesses.md)：各 harness 的接入方式及各自的能力。
- [更新记录](CHANGELOG.md)、[安全策略](SECURITY.md)、[贡献指南](CONTRIBUTING.md)。

指南与上述文件为英文。

## 许可证

Apache License 2.0，见 [LICENSE](LICENSE) 与 [NOTICE](NOTICE)。
