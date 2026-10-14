# ADR 0002：判断后端直接用 HTTP，不用服务商 SDK

- 状态：已采纳
- 日期：2026-10-13

## 背景

h-guard 有三个走 HTTP 的内置判断后端：

- typesafe；
- openai：OpenAI 兼容接口，也覆盖 Ollama、vLLM 等本地服务；
- anthropic：Anthropic Messages API。

它们共用内部包 `pkg/judge/internal/httpx`，用标准库 `net/http` 直接发 JSON 请求，没有用服务商的 Go SDK。

h-guard 以 hook 的形式运行在 agent 的每一次工具调用上，有几个特点：

- 每次调用都是一个新进程，时间预算只有几秒；
- 发给模型的是用户的命令、指令与工具输出，请求里带着用户的 API key；
- 后端出错时，结论只会变严（请求确认），不会放行。

因此判断后端要满足这几条：

- **只发往用户同意过的目标。** 同意绑定的是后端身份，即后端名、后端类型，加上配置里 `base_url` 的 scheme、主机和端口。其中任何一项变了，同意就失效。
- **凭据只有一个来源。** key 只从配置项 `api_key_env` 指定的环境变量读取，配置文件不接受明文 key。
- **错误说明不泄露内容。** 错误说明会出现在 stderr、eval 报告和健康记录里，不能含 key、响应体或 URL。
- **不超出 hook 的截止时间。** 超时和重试都要在截止时间之内结束。

服务商 SDK 的默认行为与其中几条冲突。

## 决定

判断后端直接用 HTTP，理由如下。

1. **端点与凭据的来源。**
   - SDK 默认从环境变量读取 base URL（如 `ANTHROPIC_BASE_URL`、`OPENAI_BASE_URL`），还会按顺序从多处查找凭据：几个环境变量、本机的登录配置等。
   - hook 进程继承 harness 的环境。环境里多一个变量，数据就可能发往另一台主机，而同意记录显示的仍是配置里的目标。
   - h-guard 的端点只来自配置的 `base_url`，key 只来自 `api_key_env`。
2. **错误文本。**
   - SDK 的错误字符串通常带着请求 URL 和响应体。服务端的错误说明可能回显请求内容，有的连 key 也回显。
   - h-guard 的错误说明只用固定文本：类别加状态码（如 `HTTP 400`），或写死的说明（如 `the response has no text block`）。
3. **重试要配合 hook 的时间预算。**
   - SDK 有自己的重试次数、退避和以分钟计的默认超时，不知道 hook 还剩多少时间。
   - httpx 只在剩余时间够完成一次请求时才重试；429、503 的 `Retry-After` 超过剩余时间时立即返回。
4. **重定向与响应大小。** httpx 只跟随同源重定向（scheme、主机、端口都相同），响应体上限 1 MiB。
5. **进程开销与供应链。**
   - hook 每次都是新进程，SDK 增加的二进制体积和初始化开销，每次工具调用都要付一次。
   - h-guard 能读到用户的命令和 key，依赖越少，要审计的代码就越少。
6. **接口很窄。**
   - 每个后端只用一个端点，发一种 POST 请求。
   - 回复里只读答案、模型名、用量和 `stop_reason`。
   - 请求构造与解析只有一两百行，用 `httptest` 就能完整测试。

## 后果

- **服务商 API 的变化要自己跟进。**
  - 例如，Anthropic 的较新模型拒绝强制工具调用，有的还拒绝 `temperature`；Messages API 另有原生结构化输出（`output_config.format`）可用。
  - h-guard 把请求形态做成显式配置，如 anthropic 后端的 `answer` 和 `temperature`。
  - 不在运行时探测模型能力，也不在收到 400 后自动换一种方式：换了方式，模型给出的概率也会变，需要分别校准。
  - 收到 400 时，h-guard 可以给出改哪个配置项的提示。提示只依据状态码和当前方式，不依据响应体。
- **每个 HTTP 后端都有两类测试。**
  - 用 `httptest` 做的契约测试。
  - `judgetest.RunHTTP` 的通用安全测试，覆盖跨主机重定向、错误响应体里的 canary、超大响应、`Retry-After` 超过截止时间、200 但不是 JSON 等情形。第三方 HTTP 后端也应该调用它。
- **少了 SDK 的类型和辅助功能。** 流式输出、工具调用循环等，判断后端都用不到。

## 以后某个后端改用 SDK 时

接口变复杂，或者需要只有 SDK 才支持的认证方式时，可以让个别后端改用 SDK，但要满足以下几点：

- **HTTP 客户端。** 给 SDK 注入与 httpx 配置相同的 `*http.Client`：只跟随同源重定向，有单次请求超时。另在 Transport 上限制响应体大小。
- **重试。** 关掉 SDK 自己的重试（重试次数设为 0），仍由 h-guard 按剩余时间决定是否重试。
- **端点与凭据。** 不让 SDK 从环境变量或本机配置读取端点和凭据：显式传入配置的 `base_url`，以及从 `api_key_env` 读到的 key。要有测试确认：设置 SDK 认识的环境变量（如 `ANTHROPIC_BASE_URL`）不会改变请求发往的目标。
- **错误映射。** 把 SDK 的错误映射回 `judge.Error` 的类别（`auth`、`rate_limit`、`unavailable`、`timeout`、`bad_response`）。说明只用固定文本和状态码，不使用 SDK 的错误字符串。
- **测试。** 照旧通过 `judgetest.Run` 和 `judgetest.RunHTTP`。
