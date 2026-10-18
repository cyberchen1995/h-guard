# Configuration

h-guard reads one YAML configuration, merged from up to three layers. This
guide lists every field. Run `h-guard config show` to see the merged result and
`h-guard config validate` to check it.

## Files and merge order

| Layer | Where |
|---|---|
| Built-in defaults | compiled into the binary |
| User configuration | `config.yaml` in h-guard's configuration directory |
| Extra file | `--config <file>` on `hook`, `check`, `eval`, `backend`, `status` and `config` |

The configuration directory is `$XDG_CONFIG_HOME/h-guard` when
`XDG_CONFIG_HOME` is set to an absolute path (macOS and Linux), otherwise
`~/Library/Application Support/h-guard` on macOS, `~/.config/h-guard` on Linux
and `%AppData%\h-guard` on Windows. `h-guard status` prints it. The same
directory holds:

- `rules/`: your rule packs (any `*.yaml` below it, see [rule packs](rules.md));
- `.env`: environment variables for API keys (`KEY=value` lines; variables
  already set in the environment win);
- `consent.json`: recorded consent (written by `backend enable` and `init`);
- `extensions/claudecode/`: the Claude Code plugin written by `install`.

When the configuration directory cannot be determined (for example `HOME` is not
set), h-guard uses the built-in defaults only. It never falls back to the
current directory, so files in a project cannot configure the guard.

Merging:

- Every file must declare `version: 1`.
- Parsing is strict: unknown fields, wrong types and more than one YAML document
  in a file are errors.
- Fields are overridden one by one. Map fields (`backends`, `profiles`, `rules`,
  `harnesses`) are merged by key; an entry with the same key replaces the
  lower one as a whole.
- `outbound.categories.<name>` is merged field by field: a layer that only sets
  `ignore` keeps the lower layer's `enabled` and `action`.

Error messages name the field path or YAML line and the constraint, never the
value you wrote (a wrong value may be a secret).

`h-guard config init` writes a commented template to `config.yaml` and never
overwrites an existing file. If you generate the configuration from another
language (Pkl, Jsonnet, CUE), render it to YAML.

## Editor support

The first line of the template,

```yaml
# yaml-language-server: $schema=https://raw.githubusercontent.com/cyberchen1995/h-guard/main/schema/config.schema.json
```

lets editors with YAML language support complete and check fields against
[`schema/config.schema.json`](../../schema/config.schema.json). Rule packs have
their own schemas, see [rule packs](rules.md#editor-support).

The schema checks the shape of the file. It does not know every value check:
ranges that depend on other fields, references between backends and profiles,
and whether regular expressions compile are checked by `h-guard config
validate`, which is authoritative. In particular, `backends.<name>.type` in the
schema lists only the four built-in types; a backend type registered by an
extension compiled into your binary is valid for `config validate`, but an
editor using the schema will flag it.

## Top-level fields

```yaml
version: 1
locale: en
judge:    {enabled: false, backend: jev}
action:   {tier: 2}
outbound: {tier: 1, categories: {...}}
rules:    {publish: {enabled: false}}
backends: {...}
profiles: {...}
policy:   {on_unavailable: pass, when_ask_unsupported: deny, request_window: 3, max_command_chars: 8000, max_request_chars: 2000}
harnesses: {codex: {shell: posix}}
log:      {decisions: false, retention_days: 14}
```

| Field | Default | Meaning |
|---|---|---|
| `version` | required | Configuration format version; must be `1` in every file. |
| `locale` | from `LC_ALL` or `LANG`, else `en` | Language of the messages shown to you and the agent: `en` or `zh-CN` (forms such as `zh_CN.UTF-8` are accepted). |
| `judge.enabled` | `false` | Ask the judge. `h-guard init` turns it on after you consent. |
| `judge.backend` | `jev` | Name of the backend to use (a key under `backends`). |
| `action.tier` | `2` | What actions are checked, `1`..`3` (see below). |
| `outbound.tier` | `1` | What text is scanned, `1`..`3` (see below). |
| `outbound.judge` | `true` | Use the judge for prompts and tool output. `false`: they are never sent to a backend and consent does not cover them. |
| `outbound.judge_min_chars` | `200` | Texts shorter than this are not sent to the judge (`>= 0`). |
| `outbound.judge_max_chunks` | `4` | Long texts are split into at most this many chunks (`>= 1`); the rest is covered by local rules only. |
| `outbound.judge_chunk_chars` | `4000` | Maximum characters per chunk (`>= 500`). |
| `outbound.categories` | see below | Policy per outbound category. |
| `rules.<id>.enabled` | (rule's own) | Turn a rule on or off by id. `enabled` is required in each entry; an unknown id is an error. |
| `backends.<name>` | four built-in | Judge backends, see below. |
| `profiles.<name>` | four built-in | Calibration profiles, see below. |
| `policy.on_unavailable` | `pass` | When the judge is on but cannot be used and no local rule matched: `pass`, `ask` or `deny`. (When a local rule matched, it asks.) |
| `policy.when_ask_unsupported` | `deny` | When the harness cannot ask for confirmation: `deny` or `pass`. |
| `policy.request_window` | `3` | Number of your most recent prompts sent to the judge to decide whether you asked for an operation (`>= 1`). |
| `policy.max_command_chars` | `8000` | Longer commands are shortened in the middle before sending (`>= 1`). A shortened command cannot be released by a request or withdrawn by the judge. |
| `policy.max_request_chars` | `2000` | Longer prompts are shortened in the middle before sending (`>= 1`), with the same effect. |
| `harnesses.<name>.shell` | `posix` | Shell assumed when the harness does not say which shell runs a command (Codex, opencode): `posix` or `powershell`. `install codex` and `install opencode` ask for it on Windows. |
| `harnesses.<name>.read_only_tools` | `[]` | pi, oh-my-pi (`omp`), DeepSeek Harness (`dsh`) and OpenClaw (`openclaw`): tools h-guard does not know that only read, so they need no confirmation. Names may use `*` and `?`. h-guard keeps its own list of each harness's read-only tools and asks for any other tool it does not know; tools it knows (shells, file tools, patches) are always checked, whatever this list says. See the [harness guide](harnesses.md#tools-h-guard-does-not-know). |
| `log.decisions` | `false` | Write a decision log with the full commands (credentials h-guard recognizes are masked). The health log of degradations is always written. |
| `log.retention_days` | `14` | Days to keep log files (`>= 1`). |

Logs are in h-guard's cache directory (`$XDG_CACHE_HOME/h-guard` or the
platform cache directory); `h-guard status` prints the paths.

### Tiers

| `action.tier` | Actions checked |
|---|---|
| 1 | shell commands (`exec`) |
| 2 | + file reads, writes, deletes and renames |
| 3 | + other tool calls and HTTP requests (reserved; no built-in rules) |

| `outbound.tier` | Text scanned |
|---|---|
| 1 | your prompts |
| 2 | + tool output that is file content (file-reading tools, and shell commands recognized as reading files) |
| 3 | + all tool output |

Locked rules (`catastrophic`, `fork_bomb`, `guard_tampering`) apply at every
tier. Changing a tier does not need a new `install`: every entry point is always
registered, and the tier decides what is checked at run time.

### Rules on and off

`rules.<id>.enabled` turns a single rule on or off, built-in or your own:

```yaml
rules:
  publish: {enabled: false}
  credentials.high_entropy: {enabled: true}   # off by default
```

Turning off a locked rule is allowed, but `config validate` and `install` warn
about it. A locked rule cannot be replaced by a rule pack.

## Outbound categories

Detection rules live in rule packs; a category only holds the policy.

| Field | Default | Meaning |
|---|---|---|
| `enabled` | `true` | Whether the category is checked. |
| `action` | `deny` | `deny` blocks, `warn` only reports. Harnesses cannot ask for confirmation on prompts and tool output, so `ask` is not allowed. |
| `ignore` | none | Values that are not counted as hits (compared after trimming spaces; email addresses case-insensitively). |
| `question` | built-in for the three categories | Question the judge is asked about the text: `{question, counts_as_yes, counts_as_no}`, in English. |

Built-in categories:

```yaml
outbound:
  categories:
    credentials: {enabled: true, action: deny}
    private_key: {enabled: true, action: deny}
    pii: {enabled: false, action: deny}
```

A category that is used by a rule but not configured is enabled with
`action: deny`. A category that has a `question` but no local rule depends on
the judge alone; enabling it while `judge.enabled` or `outbound.judge` is
`false` is a configuration error, because it would check nothing.

The judge only adds findings: what it reports is shown as a warning, and it
never withdraws a local hit. Before text is sent, every credential, private key
and personal-data value that h-guard recognizes is masked, including shapes the
local PII rules ignore in development text (such as SSH addresses and version
numbers).

## Backends

`backends.<name>` defines a judge backend. Only `type` and `profile` are common
to all backends; every other field depends on the type, and each type rejects
fields it does not know. A backend with the same name as a built-in one
replaces it.

| Field | Meaning |
|---|---|
| `type` | `typesafe`, `openai`, `anthropic` or `exec` (or a type registered by an extension). |
| `profile` | Calibration profile (a key under `profiles`). Without a matching profile, conservative thresholds are used. |

API keys are never written in the configuration. `api_key_env` names an
environment variable; writing a key itself there is an error. h-guard also reads
`.env` from the configuration directory. Endpoints come only from
`base_url`, never from environment variables, so the host you consented to
cannot be changed behind your back. HTTP backends do not follow redirects to
another host.

### `anthropic`

Anthropic Messages API. The model states probabilities in its answer.

| Field | Default | Meaning |
|---|---|---|
| `model` | required | Model name. |
| `base_url` | `https://api.anthropic.com` | API endpoint. |
| `api_key_env` | `ANTHROPIC_API_KEY` | Variable holding the API key. |
| `answer` | `tool` | How the answer is returned: `tool` (forced tool call), `structured` (structured JSON output) or `auto_tool` (a strict tool the model is asked to call). Newer models reject forced tool calls (HTTP 400); use `structured` for them. |
| `effort` | not sent | `low`, `medium`, `high`, `xhigh` or `max`. |
| `max_tokens` | `1024` | Output token limit. |
| `temperature` | not sent | `0`..`1`. Newer models reject it. |
| `timeout_ms` | `12000` | Per request. |
| `retries` | `1` | `0`..`5`. |

### `openai`

Any OpenAI-compatible `/chat/completions` server: OpenAI, Ollama, vLLM, LM
Studio and others.

| Field | Default | Meaning |
|---|---|---|
| `model` | required | Model name. |
| `base_url` | `https://api.openai.com/v1` | API endpoint, including `/v1`. |
| `api_key_env` | none | Variable holding the API key. Without it no authorization header is sent (local servers). |
| `probability` | `verbalized` | `verbalized` (one structured request, the model states probabilities) or `logprobs` (one request per question, probabilities read from token log-probabilities; the server must return them). |
| `reasoning_effort` | not sent | Sent as is, for example `none` for a local thinking model. |
| `temperature` | `0` with `logprobs`, otherwise not sent | `0`..`1`. |
| `timeout_ms` | `8000` | Per request. |
| `retries` | `1` | `0`..`5`. |

### `typesafe`

TypeSafe's API, which returns native probabilities.

| Field | Default | Meaning |
|---|---|---|
| `model` | `jev-latest` | Model name. |
| `base_url` | `https://api.typesafe.ai` | API endpoint. |
| `api_key_env` | `TYPESAFE_API_KEY` | Variable holding the API key. |
| `timeout_ms` | `6000` | Per request. |
| `retries` | `1` | `0`..`5`. |

### `exec`

An external program that speaks the [judge exec protocol](protocols.md#judge-exec-protocol-v1).

| Field | Default | Meaning |
|---|---|---|
| `command` | required | Absolute path of the program. It is run directly, not through a shell. |
| `args` | none | Arguments. |
| `env` | none | Names of extra environment variables passed to the program. Only `PATH`, `HOME`, `LANG` and these are passed. |
| `model` | none | Declared by the program's author; used only for the calibration fingerprint. |
| `probability` | `verbalized` | `native`, `logprobs` or `verbalized`; the first two mean the probabilities are calibrated. Used for the fingerprint. |
| `kinds` | both | Question kinds the program answers: `probability`, `scale`. |
| `timeout_ms` | `10000` | For the whole run. |

### Built-in backends

```yaml
backends:
  jev: {type: typesafe, model: jev-latest, profile: jev, api_key_env: TYPESAFE_API_KEY}
  claude-haiku: {type: anthropic, model: claude-haiku-5-5, profile: claude-haiku}
  claude-sonnet: {type: anthropic, model: claude-sonnet-5-5, answer: structured, effort: low, max_tokens: 4096, profile: claude-sonnet}
  gemma4-local: {type: openai, base_url: "http://localhost:11434/v1", model: "gemma4:12b-mlx", probability: logprobs, reasoning_effort: none, timeout_ms: 30000, profile: gemma4-local}
```

`h-guard backend list` shows each backend's destination, how it answers,
consent and calibration. A backend that sends over plain `http://` to a host
other than the local machine gets a warning: the data and the API key are not
encrypted.

## Consent

Nothing is sent to a backend until you consent in a terminal, with
`h-guard init` or `h-guard backend enable <name>`. Both show what will be sent
and where. Consent is recorded for the backend's name, type and destination
(scheme, host and port for HTTP backends; the program path and arguments for
`exec`) and for a scope: `action`, plus `outbound` unless `outbound.judge` is
`false`, plus `pii` when the `pii` category is enabled. Changing the
destination, program or arguments withdraws it. Enabling `pii` later needs new
consent; until then the judge is not asked about personal data. Changing tiers
or chunk settings does not ask again.

When the judge is on but consent is missing, it is not called; local matches
ask for confirmation and the reason says which command gives consent.
`h-guard backend disable <name>` withdraws consent; it works without a
terminal and even when the configuration has errors.

## Calibration profiles

A profile holds the thresholds for one backend:

```yaml
profiles:
  my-model:
    thresholds:
      hit: 0.3          # a rule question at or above this is a hit
      veto: 0.05        # at or below this, the judge's "no" withdraws a local hit
      requested: 0.9    # at or above this, you asked for the operation
      radius_floor: {recursive_delete: 1.25}   # per rule, 0..3
      outbound: 0.5     # an outbound category question at or above this is a hit
    fingerprint:
      model: my-model
      probability: verbalized
      questions: "sha256:<64 hex digits>"
      outbound_questions: "sha256:<64 hex digits>"
```

`hit`, `veto` and `requested` (`0`..`1`) must be written together; a profile
calibrated only for outbound may write `outbound` alone. The profile is used
only when its fingerprint matches the backend's model, how the backend obtains
probabilities, and the digest of the question set; otherwise the backend counts
as uncalibrated and conservative thresholds are used (`hit 0.3`, `veto 0.05`,
`requested 0.9`, outbound `0.5`). `h-guard status` and `h-guard backend list`
show which applies and why.

`h-guard eval --backend <name> --sweep` replays the built-in labeled corpus
through a backend, reports miss and false-alarm rates and suggests a profile
with its fingerprint; `h-guard eval --outbound --sweep` does the same for the
outbound threshold. `eval` sends the corpus to the backend and asks before it
starts (`--yes` skips the question).

## Migrating from the Python version

`h-guard migrate <questions.json>` converts the changes you made to the Python
version's `questions.json` into a configuration and rule packs. Without
`--write` it only shows what it would write.
