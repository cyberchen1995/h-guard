# Rule packs

Rules are YAML files, one rule per file. h-guard loads its built-in rules
(`rules/action` and `rules/outbound` in this repository) and then every
`*.yaml` file under the `rules/` directory in h-guard's configuration directory
(subdirectories included). A file with a `category` field is an outbound rule;
any other file is an action rule.

- A rule of yours with the id of a built-in rule replaces it as a whole, except
  locked rules (`catastrophic`, `fork_bomb`, `guard_tampering`), which cannot be
  replaced. Use `rules.<id>.enabled` in the configuration to turn a rule off
  instead.
- Action and outbound rules share one id space; the same id twice is an error.
- Rule ids use lowercase letters, digits, `.`, `_` and `-`, starting with a
  letter or digit. `explicitly_requested` and `blast_radius` are reserved.
- Parsing is strict: unknown fields, wrong types and more than one YAML
  document per file are errors.

## Checking a rule pack

```sh
h-guard config validate --rules ./my-rules   # one rule pack directory, without reading the configuration
h-guard config validate                      # the configuration and the rules in the configuration directory
```

Both compile every regular expression and run every rule's examples: each
`hit` example must match and each `miss` example must not. A failing example is
reported with the rule id and the example. Write examples for every rule; they
are the rule's tests.

## Editor support

Start a rule file with the line for its kind, and editors with YAML language
support complete and check the fields:

```yaml
# yaml-language-server: $schema=https://raw.githubusercontent.com/cyberchen1995/h-guard/main/schema/rule-action.schema.json
```

```yaml
# yaml-language-server: $schema=https://raw.githubusercontent.com/cyberchen1995/h-guard/main/schema/rule-outbound.schema.json
```

The schemas are [`schema/rule-action.schema.json`](../../schema/rule-action.schema.json)
and [`schema/rule-outbound.schema.json`](../../schema/rule-outbound.schema.json).
They check the shape; `h-guard config validate` is authoritative for values
(regular expressions, path patterns, examples).

## Action rules

Action rules check what an agent is about to run: shell commands (`exec`) and
file operations.

```yaml
schema: 1
id: terraform_destroy
action: ask
on: [exec]
reason:
  en: 'Destroys infrastructure managed by Terraform'
  zh-CN: '销毁 Terraform 管理的基础设施'
match:
  exec:
    any:
      - '\bterraform\s+(?:destroy\b|apply\b[^\n;&|]*-destroy\b)'
examples:
  hit:
    - {shell: posix, command: "terraform destroy -auto-approve"}
    - {shell: posix, command: "terraform apply -destroy"}
  miss:
    - {shell: posix, command: "terraform plan"}
```

| Field | Default | Meaning |
|---|---|---|
| `schema` | required | Rule pack format version: `1`. |
| `id` | required | Rule id. |
| `enabled` | `true` | Whether the rule is active; `rules.<id>.enabled` in the configuration overrides it. |
| `action` | required | `ask` or `deny`. |
| `on` | required | Action kinds: `exec`, `file_read`, `file_write`, `file_delete`, `file_rename`. |
| `reason` | required | Reason text by locale; `en` is required, `zh-CN` is used when the locale is Chinese. |
| `match` | required | `match.exec` for `exec`, `match.file` for file actions. |
| `requires_judge` | `false` | The rule interrupts only when the judge is on; with the judge off its hits are only logged. Needs a `question`. |
| `question` | none | Question sent to the judge (`exec` rules only), see below. |
| `radius_floor` | `0` | With the judge on, a hit is dangerous only when the judge rates the blast radius (`0`..`3`) at or above this. |
| `bypassable_by_request` | `true` | Whether your explicit request (judged by the model) lets a hit pass. |
| `vetoable_by_judge` | `true` | Whether a confident "no" from the judge withdraws a local hit. |
| `examples` | none | `hit` and `miss` lists, run by `config validate`. |
| `locked` | `false` | Built-in rules only. |

Which rules apply depends on `action.tier`: `exec` rules at tier 1 and above,
file rules at tier 2 and above.

How a hit becomes a verdict:

1. A `deny` rule that matches denies, without asking the judge.
2. With the judge off, `ask` rules that match ask, except rules with
   `requires_judge: true`, which are only logged.
3. With the judge on but unavailable (no consent, error, timeout), every
   matching rule asks.
4. With the judge answering, a match is withdrawn when the judge is confidently
   sure it is not one (`vetoable_by_judge`), passes when you explicitly asked
   for the operation (`bypassable_by_request`), and passes when the blast
   radius is below `radius_floor`. The judge can also report a hit for a rule
   whose patterns did not match.

### `match.exec`

Regular expressions are matched case-insensitively against each command h-guard
extracts from the command line (pipelines, `&&` chains, `sh -c` and similar
wrappers, `xargs`, `find -exec` and PowerShell constructs are expanded first).
The dialect supports lookahead and lookbehind; write `(?-i:...)` for a
case-sensitive part. Each match has a time limit; a match that runs out of time
counts as a hit (a `deny` rule then asks instead).

There are three groups of patterns, chosen by the shell the command runs in:

| Group | Used for |
|---|---|
| `any` | every shell |
| `posix` | POSIX shells only (sh, bash, zsh) |
| `powershell` | PowerShell only |

The shell comes from the harness when it says (Claude Code distinguishes Bash
and PowerShell tools); otherwise from `harnesses.<name>.shell` (Codex), and
`h-guard check --shell` for manual checks.

Options:

| Field | Meaning |
|---|---|
| `command_position` | Match only the text at command positions, not arguments of other commands. Use it for `deny` rules. |
| `strip_quotes` | Blank out quoted text before matching. |
| `redirects` | Patterns matched against redirections (POSIX), each written as `command fd-operator target`, for example `dd 2>/dev/sda`. |
| `encoded` | Also hit when encoded content (base64, `-EncodedCommand` and similar) is handed to an interpreter. A rule with `encoded: true` needs no patterns. |

An `exec` rule needs at least one pattern or `encoded: true`.

Patterns can use the same placeholders as file patterns (see the table under
`match.file`), anywhere in the pattern except inside a character class. A
placeholder becomes the directory or file h-guard sees, matched literally
(regular-expression characters in it are escaped), case-insensitively, with
`/` and `\` both accepted as separators and a space optionally preceded by
`\`. When the value is under your home directory, the home part may also be
written `~`, `$HOME`, `${HOME}`, `$env:HOME`, `$env:USERPROFILE` or
`%USERPROFILE%`. A placeholder without a value (the variable is unset) never
matches, so the part of the pattern that needs it does not match; the rest of
the pattern and the rule still work. Write `\{name}` for literal braces; other
names in braces are left as they are.

```yaml
match:
  exec:
    any:
      - '\brm\b[^\n;&|]*{pi_agent_dir}[/\\]+extensions[/\\]+my-ext\.js'
```

### `match.file`

File rules match the target path of a file operation (and the destination of a
rename):

```yaml
schema: 1
id: prod_env
action: ask
on: [file_read, file_write]
reason:
  en: 'Touches production deployment settings'
match:
  file:
    paths:
      - '**/deploy/prod/**'
    exclude:
      - '**/deploy/prod/README.md'
examples:
  hit:
    - {action: file_write, path: "deploy/prod/values.yaml"}
  miss:
    - {action: file_read, path: "deploy/prod/README.md"}
    - {action: file_read, path: "deploy/staging/values.yaml"}
```

Patterns start with `/`, `~/`, `**/` or a placeholder, and contain no `.` or
`..` segments. `**/` matches zero or more directories, a trailing `/**` matches
the directory and everything below it, `*` and `?` do not cross `/`. On Windows,
write patterns with `**/` or `~/` (not a drive letter). Placeholders:

| Placeholder | Expands to |
|---|---|
| `{config}` | h-guard's configuration directory in use |
| `{cache}` | h-guard's cache directory in use |
| `{extra_config}` | the file passed with `--config` (no match without one) |
| `{claude_config}` | `$CLAUDE_CONFIG_DIR` (no match when unset) |
| `{codex_home}` | `$CODEX_HOME` (no match when unset) |
| `{xdg_config}` | `$XDG_CONFIG_HOME` (no match when unset) |
| `{pi_agent_dir}` | `$PI_CODING_AGENT_DIR`, with a leading `~` expanded (no match when unset) |
| `{omp_config}` | `$PI_CONFIG_DIR` under the home directory (no match when unset) |
| `{dsh_home}` | `$DSH_HOME`, with a leading `~` expanded (no match when unset) |

Relative targets are resolved against the working directory and symbolic links
are resolved, so a link to a protected file matches too. `exclude` patterns are
compared with the path as written, without resolving links. File rules never
ask the judge; a path hit is the verdict.

File rules see only file actions: the harness's file tools (Claude Code's Read,
Write and Edit, Codex's patches, generic file actions). A shell command that
reads or writes the same path (`cat .env`, `echo x > .env`) is an `exec` action
and is matched only by `exec` rules. At `outbound.tier: 2` the output of shell
commands recognized as reading files is scanned by outbound rules.

File examples (`{action, path}`) are matched literally, without touching the
file system, with the home directory `/home/user`, the working directory
`/home/user/project`, `{config}` = `/xdg/config/h-guard`, `{cache}` =
`/xdg/cache/h-guard`, `{extra_config}` = `/etc/guard/extra.yaml`,
`{pi_agent_dir}` = `/opt/pi/agent` and `{dsh_home}` = `/home/user/my dsh`; the
other placeholders are unset. Command examples use the same values for
placeholders in `exec` patterns.

### `question`

A question lets the judge decide the rule. It is sent in English with the
command; the answer is a probability.

```yaml
question:
  kind: probability
  instructions:
    question: 'Would executing `call.command` destroy cloud infrastructure?'
    counts_as_yes: 'terraform destroy; terraform apply -destroy; pulumi destroy.'
    counts_as_no: 'terraform plan; the text only mentioned in a commit message or echo.'
  criteria:
    'true': 'Running the command would actually destroy infrastructure.'
    'false': 'It only plans or reads, or the text is never executed.'
```

The judge sees `call.command`, `call.cwd`, `call.harness`, `call.tool` and your
recent prompts as `user_requests`; refer to them in the question by those
names. Calibration fingerprints cover only the built-in questions: your own
questions do not invalidate a backend's profile, and they are judged with the
thresholds calibrated for the built-in ones. Check how a backend answers them
with `h-guard eval --cases <file>`.

## Outbound rules

Outbound rules scan your prompts and tool output. A hit counts toward the
rule's category; the category's `action`, `ignore` list and judge question are
set in the configuration (`outbound.categories.<name>`, see the
[configuration guide](configuration.md#outbound-categories)).

```yaml
schema: 1
id: internal.hostname
category: internal_hosts
on: [prompt, tool_output]
match:
  regex:
    - '\b[a-z0-9-]+\.corp\.example\.com\b'
examples:
  hit:
    - "ssh build-07.corp.example.com"
  miss:
    - "see docs.example.com"
```

| Field | Default | Meaning |
|---|---|---|
| `schema` | required | `1`. |
| `id` | required | Rule id. |
| `enabled` | `true` | Overridden by `rules.<id>.enabled`. |
| `category` | required | Category name; a new name creates a category (enabled, `deny`, unless configured). |
| `on` | required | `prompt`, `tool_output` or both. Which tool output is scanned depends on `outbound.tier`. |
| `match.regex` | | Regular expressions (case-insensitive). |
| `match.detector` | | One built-in detector instead of `regex`. |
| `examples` | none | `hit` and `miss` lists of texts. |

`action`, `question` and `locked` are not allowed in outbound rules. Exactly one
of `regex` and `detector` is required. Built-in detectors:

| Detector | Detects |
|---|---|
| `credentials.prefixed_token` | API tokens with well-known prefixes |
| `credentials.bearer` | `Bearer` tokens |
| `credentials.assignment` | secrets assigned to key, token, password and similar names |
| `credentials.aws_access_key` | AWS access key IDs |
| `credentials.url_password` | passwords in URLs |
| `credentials.high_entropy` | high-entropy strings (the built-in rule is off by default) |
| `private_key.pem` | PEM private key blocks |
| `pii.email` | email addresses (not reserved domains, noreply addresses or SSH remotes) |
| `pii.phone_cn` | mainland China mobile numbers |
| `pii.phone_intl` | international phone numbers |
| `pii.cn_id` | Chinese resident ID numbers (checksum verified) |
| `pii.us_ssn` | US social security numbers |
| `pii.ip` | public IP addresses |

A blocked text is reported with the category, the number of hits and their line
numbers; the matched text is never put in the reason or the logs.

## Built-in rules

The built-in rules are in [`rules/action`](../../rules/action) and
[`rules/outbound`](../../rules/outbound). Their examples run in this
repository's tests. `h-guard status` lists rules that are not in effect and
why: turned off, outside the current tier, needing the judge while it is off,
or in a disabled category.
