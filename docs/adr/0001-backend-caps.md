# ADR 0001：判断后端显式声明能力

- 状态：已采纳
- 日期：2026-10-13

## 背景

h-guard 的动作检查会把一组判断题交给判断后端，取回概率。题有两种题型：`probability`（给出一个 [0, 1] 的概率）和 `scale`（给出各级别上的分布）。某道题的答案缺失或无效时，这道题按未答处理，不会产生放行。

内置后端取得答案的方式各不相同：

- typesafe：服务端原生给出概率。
- openai：读模型作答位置的 logprobs，或者用结构化输出（`response_format` 的 json_schema）让模型直接写出概率。
- anthropic：Messages API 不提供 logprobs，用强制工具调用让模型按 schema 作答。原生结构化输出（`output_config.format`）和非强制工具调用也是可选的方式。
- exec：交给外部程序，取答方式由程序决定。

此前 `judge.BackendCaps` 只有 `Calibrated` 与 `Batch` 两项。取答方式只体现在各后端自己的配置项和 `Info.Probability` 里，框架看不到。后端能回答哪些题型也没有地方声明，框架默认每个后端两种题型都能答。实际使用中出现了三个问题：

- exec 调用的外部程序可能只实现了概率题。scale 题照样发给它，它答不出或者答错，只能在运行时表现为缺题或后端出错。
- 同一服务商的较新模型会拒绝某些请求方式。例如 Anthropic 的部分新模型对强制工具调用返回 HTTP 400，有的模型拒绝 `temperature`，有的不提供 logprobs。后端出错不会产生放行，所以失败方式是安全的；但问题要等真正发请求才暴露，用户看到的只有一个状态码。
- `status` 和 `backend list` 没法告诉用户某个后端用什么方式取答。

其他 LLM 抽象层常见的做法是 Provider 接口加能力声明。有些「批量判断」抽象（一批问题进去，概率或选项出来，形态与 `judge.Backend.Ask` 相同）会在发请求前按后端支持的题型预检。

## 决定

### 1. 取答方式

`pkg/judge` 新增 `type Mechanism string` 和六个常量：

| 常量 | 值 | 含义 | 内置使用者 |
|---|---|---|---|
| `MechanismNative` | `native` | 服务端原生给出概率 | typesafe |
| `MechanismLogprobs` | `logprobs` | 读模型作答位置候选字符的 logprob | openai（`probability: logprobs`） |
| `MechanismJSONSchema` | `json_schema` | 结构化输出：OpenAI `response_format`、Anthropic `output_config.format` | openai（`probability: verbalized`）、anthropic（`answer: structured`） |
| `MechanismForcedTool` | `forced_tool` | 强制模型调用参数为答案的工具 | anthropic（`answer: tool`，默认） |
| `MechanismAutoTool` | `auto_tool` | 提供答案工具但不强制调用，模型没有调用就没有答案 | anthropic（`answer: auto_tool`） |
| `MechanismProgram` | `program` | 外部程序，取答方式由程序决定 | exec |

`Mechanism` 只用于显示和诊断，能力判断只看下一节的 `Kinds`；它也不进入校准指纹。指纹仍然用 `Info.Probability` 区分取答方式：请求形态不同、概率分布也就不同的方式，要用不同的 `Info.Probability` 分别校准。

### 2. 能回答的题型

`BackendCaps` 新增 `Mechanism`、`Kinds []Kind` 两个字段和方法 `Supports(k Kind) bool`：

- `Kinds` 为 nil 表示全部题型都能答。这是为了兼容：没有声明这一项的第三方后端，行为与以前相同。
- `Kinds` 为空切片（非 nil）表示一种都不能答。
- JSON 序列化时不省略 `kinds`。如果用 `omitempty`，空切片会被写成「没有这一项」，解码后成了 nil，「一种都不能答」就变成了「全部都能答」。

### 3. 发请求前预检

`judge.AskAll` 先去掉 `Supports` 为假的题，再按 `Batch` 一次问完或者逐题提问。去掉的题保持未答，和答案缺失一样处理，不会产生放行。一道题都不剩时不调用后端，返回空答案和 nil 错误。

exec 后端在自己的 `Ask` 里也只把声明的题型发给程序。即使有调用方绕过 `AskAll` 直接调用 `Ask`，程序也收不到其他题型；一道都不剩时不启动程序。

### 4. 配置期校验

能在配置阶段发现的错误，不留到运行时：

- exec 后端新增配置项 `kinds`，默认 `[probability, scale]`。取值只能是 `probability` 或 `scale`；空列表和重复都是配置错误。错误说明不回显配置的值。
- 开启模型时，所选后端的 `Kinds` 必须覆盖内置题集用到的全部题型，否则是配置错误，说明里写出后端名和缺少的题型。题集属于动作检查，配置解析本身不依赖它，所以这项检查放在加载配置的流程里。

### 5. 内置后端的声明

| 后端 | Mechanism | Kinds |
|---|---|---|
| typesafe | `native` | probability、scale |
| openai，`probability: logprobs` | `logprobs` | probability、scale |
| openai，`probability: verbalized` | `json_schema` | probability、scale |
| anthropic | 按配置项 `answer`：`forced_tool`（默认）、`json_schema` 或 `auto_tool` | probability、scale |
| exec | `program` | 配置项 `kinds`，默认两种 |

### 6. 一致性测试

`pkg/judge/judgetest` 的 `Run` 新增子测试 `caps`，检查以下几点：

- `Mechanism` 非空。
- `Kinds` 非 nil 时，只含已知题型。
- 对 `Supports` 为假的题型，直接调用 `Ask` 时答案里不能出现（返回错误也可以）。

只有 `caps` 子测试会把后端不支持的题型发给它；其余子测试只问 `Supports` 为真的题，所以收到不支持的题型就报错的后端同样能通过。经 `AskAll` 调用时不支持的题型根本不会发出，这是 `AskAll` 自己的行为，由 `pkg/judge` 的测试覆盖，不算后端的检查。

第三方后端在自己的测试里调用 `Run`，就能得到这些检查。

### 7. 不做的事

能力只来自后端类型和配置，是静态声明。我们不维护「模型到能力」的数据表，不在运行时探测，也不在收到 400 后自动换一种取答方式。模型的能力变化很快；探测和自动切换会让同一份配置在不同时刻用不同的方式取答，而不同的方式需要不同的校准。

## 后果

好处：

- 题型不匹配不再表现为运行时缺题。不支持的题在发请求前就被排除；开启模型时，这类配置在配置阶段就报错。
- `status` 和 `backend list` 可以显示每个后端的取答方式和题型。
- 新增一种取答方式，只要加一个常量并在后端里声明，框架逻辑不用改。

兼容性：

- `BackendCaps` 增加了字段。带字段名的复合字面量不受影响，不带字段名的写法（如 `BackendCaps{true, true}`）需要改写。
- `BackendCaps` 现在含切片字段 `Kinds`，不再是可比较的类型：`caps == judge.BackendCaps{…}` 这样的比较、把它用作 map 的键，都不能再编译。要改为逐个字段比较，或者用 `reflect.DeepEqual`。发布说明里也要写明。
- 不声明 `Kinds` 的第三方后端行为不变。但 `judgetest` 现在要求 `Mechanism` 非空，第三方后端要补上这项声明；内置常量都不合适时，可以用自己的取值。
- `BackendCaps` 的 JSON 多了 `mechanism` 和 `kinds` 两项。

安全性：

- 新增的路径只会让发出的题变少、答案缺失，不会让答案变多。缺题本来就不产生放行，所以这项改动不会放宽任何结论。
- 最坏的情况是声明得过窄。没有问出的题按未答处理：缺了规则题，这条命中不能被模型否决；缺了「用户是否明确要求过」，不能按授权豁免；缺了影响范围，范围按最大计。已经答出的题照常起作用。例如只声明 `probability` 时，影响范围（`scale`）没有问出，但模型有把握的否决仍然有效，「用户明确要求过」的豁免也照常适用，因为这项豁免本来就不看影响范围。所以过窄的声明只会让判断少了依据，结论不会比全部作答时更宽。
- 对内置题集，这种情形在开启模型时不会出现：所选后端缺少内置题集用到的任何一种题型，都是配置错误（见决定 4）。
- 声明了 `Kinds` 的后端要自己保证不回答不支持的题型，`judgetest` 会检查这一点。
