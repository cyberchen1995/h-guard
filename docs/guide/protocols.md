# Protocols

h-guard talks to other programs through three JSON protocols. Each has its own
version, independent of h-guard's release version: adding an optional field
does not change the version; changing the meaning of an existing field does.

| Protocol | Identifier | Between |
|---|---|---|
| Judge exec protocol | `h-guard.judge/v1` | h-guard and an external judge program (`exec` backend) |
| Generic harness contract | `"version": 1` | any agent harness or script and `h-guard hook generic` |
| Extension protocol | `h-guard.ext/v1` | a thin extension inside a harness and `h-guard hook <harness>` |

## Judge exec protocol v1

An `exec` backend runs a program of yours as the judge. Configure it under
`backends` (fields in the [configuration guide](configuration.md#exec)):

```yaml
backends:
  my-judge: {type: exec, command: /usr/local/bin/my-judge, args: [--fast], model: my-judge-1}
judge: {enabled: true, backend: my-judge}
```

**Running.** For each judgment h-guard starts the program once, by absolute
path and with the configured arguments, without a shell. The working directory
is h-guard's configuration directory. The environment contains only `PATH`,
`HOME`, `LANG` and the variables listed in `env`, so API keys from h-guard's
environment are not passed unless you list them. The request is written to
stdin; the response is read from stdout. Stderr is discarded. When the run
ends or the deadline (`timeout_ms`, default 10 seconds) passes, the whole
process group is terminated (on Unix; on Windows only the process), so the
program must not leave a long-running service in its own process group.

**Request** (stdin):

```json
{
  "protocol": "h-guard.judge/v1",
  "state": {
    "call": {"command": "git push origin main", "cwd": "/home/dev/project", "harness": "claudecode", "tool": "Bash"},
    "user_requests": ["fix the failing test"]
  },
  "questions": [
    {
      "id": "publish",
      "kind": "probability",
      "instructions": {
        "question": "Would executing `call.command` publish something or mutate state outside this machine: ...?",
        "counts_as_yes": "git push in any form ...",
        "counts_as_no": "git fetch, git pull ...",
        "criteria": {"true": "...", "false": "..."}
      }
    },
    {
      "id": "blast_radius",
      "kind": "scale",
      "instructions": {"question": "If `call.command` runs as written from `call.cwd`, how much would be lost or changed ...?"},
      "levels": ["No lasting effect ...", "Loses only regenerable artifacts ...", "Loses unique local work ...", "Damage outside the project ..."]
    }
  ]
}
```

- `state` is what the question is about. For a command it holds `call`
  (`command`, `cwd`, `harness`, `tool`, and `shell: "powershell"` for PowerShell
  commands) and `user_requests`, the user's recent prompts, oldest first. For
  outbound checks it holds `text` (one chunk, with recognized secrets masked),
  `source` (`prompt` or `tool_output`), `chunk` (`"1/3"`) and, for tool output,
  `tool`. Credentials h-guard recognizes are masked in every field; long
  commands and prompts are shortened in the middle.
- `questions` lists what to answer. `kind` is `probability` (answer one number
  in `[0, 1]`: how likely the answer is yes) or `scale` (answer a distribution
  over `levels`, one probability per level, in order). `instructions` explains
  the question in English. Treat the ids as opaque; besides rule ids there are
  `explicitly_requested` and `blast_radius` for commands, and
  `outbound.<category>` for text.
- The program receives only the kinds listed in the backend's `kinds`
  (default both). If no question is left, the program is not started.

**Response** (stdout, at most 1 MiB):

```json
{
  "answers": {
    "publish": {"p": 0.97},
    "explicitly_requested": {"p": 0.02},
    "blast_radius": {"dist": [0.05, 0.15, 0.7, 0.1]}
  },
  "model": "my-judge-1",
  "usage": {"input_tokens": 0, "output_tokens": 0}
}
```

- Answer a `probability` question with `{"p": <number>}` and a `scale`
  question with `{"dist": [...]}`. `model` and `usage` are optional.
- A question that is missing, `{}`, `{"p": null}`, or a distribution containing
  `null` counts as **not answered**, never as `0`. An answer outside the valid
  range is invalid. Unanswered or invalid questions cannot withdraw a local hit
  or release an operation.
- A non-zero exit, a timeout, output larger than 1 MiB or output that is not
  this JSON makes the backend unavailable for that check: local matches ask for
  confirmation. Nothing fails open.

`model` and `probability` in the backend configuration are declared by you and
go into the calibration fingerprint; see
[calibration profiles](configuration.md#calibration-profiles). A minimal
program in Python:

```python
#!/usr/bin/env python3
import json, sys

def probability(question, state):
    # Return a probability in [0, 1], or None when you have no answer.
    command = state["call"]["command"]
    if question["id"] == "publish":
        return 0.95 if "git push" in command else 0.02
    return None

def distribution(question, state):
    # One probability per entry in question["levels"], or None.
    return None

request = json.load(sys.stdin)
assert request["protocol"] == "h-guard.judge/v1"
answers = {}
for q in request["questions"]:
    if q["kind"] == "probability":
        p = probability(q, request["state"])
        if p is not None:
            answers[q["id"]] = {"p": p}
    elif q["kind"] == "scale":
        d = distribution(q, request["state"])
        if d is not None:
            answers[q["id"]] = {"dist": d}
json.dump({"answers": answers, "model": "my-judge-1"}, sys.stdout)
```

`h-guard eval --backend <name>` replays the labeled corpus through your program
and reports how its answers turn into decisions.

## Generic harness contract v1

An agent harness without a built-in adapter (or any script) can use h-guard by
running

```sh
h-guard hook generic --event <action|prompt|tool_output> [--timeout <seconds>] [--config <file>]
```

with one JSON object on stdin, and applying the decision itself. `install` does
not set this up; wire it into your harness's hook or plugin mechanism.

**Input:**

| Field | Required | Meaning |
|---|---|---|
| `version` | yes | `1`. |
| `kind` | yes | `action`, `prompt` or `tool_output`. |
| `actions` | for `action` | List of actions (below). |
| `text` | for `prompt`, `tool_output` | The prompt, or the tool output as text. |
| `tool` | no | Name of the tool. |
| `cwd` | no | Working directory. Needed when a file action has a relative path. |
| `requests` | no | Recent user prompts, oldest first: `[{"text": ..., "source": "user" \| "automated"}]`. `source` defaults to `user`. Mark scheduled tasks, sub-agent reports and other automated messages `automated`; they never count as the user asking for something. For `prompt` without `requests`, the prompt itself is a user request. |
| `session_id` | no | Session id; used for logs and the cache of recent prompts. |
| `call_id` | no | Tool call id; used for logs. |
| `file_content` | no | For `tool_output`: `true` when the output is file content (scanned at outbound tier 2). |

Actions:

| `kind` | Fields |
|---|---|
| `exec` | `command`, `shell` (`posix` or `powershell`, default `posix`) |
| `file_read`, `file_write`, `file_delete` | `path` |
| `file_rename` | `path`, `to` |

Unknown fields are ignored. An unknown version, kind, action kind or source, an
empty command, or a relative file path without `cwd` makes the input not
understood.

**Output** is always one JSON object, also for `pass`:

| Field | Meaning |
|---|---|
| `version` | `1`. |
| `decision` | `pass`, `warn`, `ask` or `deny`; never `allow`. |
| `raw_decision` | The decision before adjusting to the harness's abilities (same as `decision` for generic). |
| `reason` | Localized reason for the user and the agent. |
| `hint` | Localized way forward (for example "ask the user to run it themselves"). |
| `reasons` | Machine-readable reasons: `[{"code": ..., "params": {...}}]`. |
| `findings` | What matched: `rule`, `category` (outbound), `source` (`local`, `judge`, `both`), `probability` (from the judge), `locations` (`line`, `start`, `end` byte offsets in `text`). |
| `signals` | Diagnostic signals, for example whether the judge was used. |
| `fallbacks` | Codes for anything that degraded the check, for example `judge_unavailable`, `judge_timeout`, `judge_consent_missing`, `evidence_truncated`, `input_too_large`, `tool_unknown`, `local_budget_exceeded`, `regex_timeout`. |
| `error` | Present only when h-guard gave no decision. |

How to apply the decision:

| `decision` | `action` | `prompt` | `tool_output` |
|---|---|---|---|
| `pass` | let the harness's own permission flow continue | send it | pass the output on |
| `warn` | continue, show `reason` to the user | send it, show `reason` | pass the output on, show `reason` |
| `ask` | ask the user; if you cannot ask, treat it as `deny` | treat as `deny` | treat as `deny` |
| `deny` | do not run it; give `reason` to the agent | do not send it; show `reason` | replace the output with `reason` |

The process exits `0` when the output carries a decision. When the input is not
understood or stdin cannot be read, it prints
`{"version":1,"error":"input not understood"}` and exits `1`; your integration
decides what to do then (failing closed is the safe choice). `--timeout`
(default 20) is the time your harness allows the hook; h-guard answers before
it runs out. Input is limited to 16 MiB. When the input is too large or time
runs out, h-guard still decides for the event named by `--event` (with the
fallback `input_too_large` or `local_budget_exceeded`); without `--event` it
prints the error instead.

Example, with the default configuration:

```console
$ echo '{"version":1,"kind":"action","session_id":"s1","cwd":"/work","tool":"read","actions":[{"kind":"file_read","path":".env"}]}' | h-guard hook generic --event action
{"version":1,"decision":"ask","raw_decision":"ask","reason":"This file operation touches .env, which a path rule covers, so it needs your confirmation: Reads a file that usually holds secrets (.env, private keys, cloud or SSH credentials) [rule].","hint":"Ask the user to run it themselves.","reasons":[{"code":"action.file_rule","params":{"paths":".env","rules":"Reads a file that usually holds secrets (.env, private keys, cloud or SSH credentials) [rule]"}},{"code":"hint.manual"}],"findings":[{"rule":"sensitive_read","source":"local"}],"signals":{"action":{"judge":"off"}}}
$ echo '{"version":1,"kind":"prompt","session_id":"s1","text":"deploy with aws_access_key_id = AKIAIOSFODNN7EXAMPL0"}' | h-guard hook generic --event prompt
{"version":1,"decision":"deny","raw_decision":"deny","reason":"Contains credentials (1 found, line 1).","hint":"Remove the sensitive content and try again; for a false positive, ask the user to add the value to the category's ignore list or disable the rule in the h-guard config.","reasons":[{"code":"outbound.credentials","params":{"count":"1","lines":"1"}},{"code":"hint.outbound"}],"findings":[{"rule":"credentials.aws_access_key","category":"credentials","source":"local","locations":[{"line":1,"start":32,"end":52}]}]}
```

The recent user prompts that the judge uses to decide whether the user asked
for an operation come from `requests`, and from earlier `prompt` events of the
same `session_id`.

## Extension protocol v1

Some harnesses deliver events only to code running inside them (Claude Code's
mods, opencode's plugins, pi's and oh-my-pi's extensions, DeepSeek Harness's
Cordis plugins and OpenClaw's native plugins are the built-in cases). A thin extension inside the harness forwards each
event to h-guard and turns the reply into the harness's own return value. It
makes no decisions itself; the harness-specific parsing lives in h-guard's
adapter for that harness.

The extension runs

```sh
h-guard hook <harness> --event <hook> [--timeout <seconds>]
```

with the request on stdin and reads the reply from stdout. Exit code `0` means
the reply is valid. Requests are limited to 16 MiB.

**Request:**

| Field | Meaning |
|---|---|
| `protocol` | `h-guard.ext/v1`. |
| `harness` | Harness name, matching an adapter registered in h-guard (`claudecode`, `opencode`, `pi`, `omp`, `dsh`, `openclaw`). |
| `harness_version` | The version string the harness reports, passed on as is. Optional. |
| `hook` | The harness's hook name (table below). |
| `session` | `{"id": ..., "cwd": ...}`; `id` is required. |
| `data` | The harness's original event: unchanged, or its serializable fields when the event holds live objects. Required. |
| `result` | For tool-result hooks: the tool result. |
| `decided` | For permission hooks: the decision the harness reached before h-guard. |

The built-in extensions send these hooks:

| Harness | `hook` | `data` | `result` |
|---|---|---|---|
| `claudecode` | `tool.result`, `prompt.submit` | the mod's event | the tool result (`tool.result`) |
| `opencode` | `tool.execute.before`, `tool.execute.after` | `{tool, sessionID, callID, args}` | `{output, content}` (`tool.execute.after`) |
| `opencode` | `chat.message` | `{sessionID, agent, parts, parentID}` | |
| `pi`, `omp` | `tool_call`, `tool_result` | `{toolCallId, toolName, input}` | `{content}` (`tool_result`) |
| `pi`, `omp` | `input` | `{text, source}`; oh-my-pi also sends prompts found on its `context` event, with `source: "context"` | |
| `dsh` | `tools/pre-execute`, `tools/post-execute` | `{name, callId, arguments, nested}` | `{isError, content}` (`tools/post-execute`) |
| `dsh` | `agent/pre-step` | `{messages: [{source: {kind}, content}], session: {origin, delegationDepth}}` | |
| `openclaw` | `before_tool_call` | `{toolName, params, toolKind, toolInputKind, toolCallId, derivedPaths, platform, execHost}` | |
| `openclaw` | `tool_result` (the tool result middleware) | `{toolName, toolCallId, args, isError, platform}` | `{content}` |
| `openclaw` | `before_agent_run` | `{prompt, trigger, provenance, sessionKey, channel}` | |

Only text content blocks are passed on; images are left out.

**Reply:** `{"protocol": "h-guard.ext/v1", "action": "pass|deny|ask|warn",
"message": "...", "hint": "...", "subject": "..."}`. `message` and `hint` are
localized. `subject` is optional: a summary of the call (tool, command, files)
with the credentials h-guard recognizes masked, which some adapters (OpenClaw)
add to `ask` so the extension can show it to a person instead of the raw
arguments. Every
reply other than `pass` carries a non-empty `message`; a reply without one is
not valid. There is no `allow`. Every request that h-guard understands gets a
reply, `pass` included; a tool call that has nothing to check (such as an MCP
tool) gets `pass`. A request h-guard does not understand gets no output, which
the extension treats as a failure.

```console
$ echo '{"protocol":"h-guard.ext/v1","harness":"claudecode","harness_version":"2.1.296","hook":"prompt.submit","session":{"id":"s1","cwd":"/work"},"data":{"text":"deploy with aws_access_key_id = AKIAIOSFODNN7EXAMPL0","origin":{"kind":"user"}}}' | h-guard hook claudecode --event prompt.submit
{"protocol":"h-guard.ext/v1","action":"deny","message":"Contains credentials (1 found, line 1).","hint":"Remove the sensitive content and try again; for a false positive, ask the user to add the value to the category's ignore list or disable the rule in the h-guard config."}
```

The extension must handle failure itself: when h-guard cannot be started, times
out, exits non-zero or returns a reply it cannot read, a permission hook asks
for confirmation (an existing deny stays a deny) and other hooks let the event
through and tell the user. It must also apply `deny` and `ask` even if
`message` is somehow empty, using a fixed text.

The stock binary has adapters for `claudecode`, `codex`, `opencode`, `pi`,
`omp`, `dsh`, `openclaw` and `generic`; all but `codex` and `generic` read extension
requests. Connecting a new harness this way needs
an adapter for it, written against `pkg/harness` and `pkg/harness/extproto` and
registered in your own build of h-guard (see
[ADR 0003](../adr/0003-engine-stays-internal.md)). A harness that can run a
command per event is usually easier to connect through the generic contract.
