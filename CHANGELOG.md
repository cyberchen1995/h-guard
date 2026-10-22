# Changelog

All notable changes are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

Before v1.0 the public Go packages under `pkg/` may change incompatibly between
minor releases. Every such change is recorded in this file.

## [Unreleased]

### Added

- `h-guard status` starts with a protection summary. For each harness it shows
  three separate layers: the configuration is written, the harness has really
  run the hook (recorded on each hook run; Codex shows "unverified" until it
  runs one, since its trust state cannot be read), and the last self-test.
  It then lists which rules interrupt, which only log, which are off, and what
  is not covered.
- `h-guard selftest [claudecode|codex]` runs the installed entries the way the
  harness does, with a simulated `rm -rf /` (never executed) and a prompt with
  a made-up API key, and checks that both are blocked. Nothing is executed and
  the judge is not called. Entries that run another h-guard program, and
  Claude Code plugin files that differ from what this h-guard writes, are not
  run: reinstall with this h-guard first.
- Every interruption now names the operation and its target (the command and
  working directory), the impact and a safer way to continue. Action rules can
  carry localized `impact` and `advice` texts; all built-in rules do.
- One-time approvals for harnesses that cannot ask (Codex): a blocked operation
  that is not a hard rule gets an id, and `h-guard allow <id>`, run by the user
  in an interactive terminal, lets exactly that operation (harness, working
  directory, command or files) run once within 10 minutes (`--ttl`, at most
  1h). `h-guard allow` lists recent blocks, `--revoke` withdraws an approval.
  Running `h-guard allow` through a harness asks (`guard_tampering`).
  Approvals are signed with a key in the configuration directory
  (`grant.key`, created the first time an approval is offered), and so are the
  stopped operations `h-guard allow` shows; unsigned or edited records are
  ignored, and used approvals are recorded in the configuration directory so
  they cannot be replayed. An approval is bound to the exact tool input, and
  only shell commands get one: tool calls with file actions, partly unparsed
  operations and commands too long to show in full get no approval. Records keep only a digest and a redacted copy of the operation.
- Three protection scenarios work with the model off
  ([docs/guide/scenarios.md](docs/guide/scenarios.md)):
  - keeping your work: `git reset --hard`, `git clean`, `git checkout .`,
    `git stash clear`, a force push without lease, `git filter-branch` /
    `filter-repo` and recursive deletes under `~`, `..` or of `.git` ask;
  - stopping unasked publishing: `npm`/`pnpm`/`yarn publish`, `cargo publish`,
    `twine upload`, `uv publish`, `gem push`, `docker`/`podman push`,
    `gh release create`/`upload`/`delete`, `Publish-Module` and `nuget push`
    ask (dry runs do not);
  - keeping credentials in: `sensitive_read` also checks the files that common
    shell reads name (`cat`, `head`, `grep`, `sed`, `base64`, `< file`,
    PowerShell's `Get-Content`), not only the harness's file tools.
- Action rules can mark such forms with `match.exec.local`: patterns matched
  at each command position that interrupt even with the judge off, in
  `requires_judge` rules. The rest of the rule still needs the judge.
- `h-guard eval --compare` replays held-out sessions through the Claude Code
  hook under five configurations (no h-guard, local rules only, the judge, a
  judge that times out, a judge that fails) and reports, for each, justified
  and needless interruptions, misses, judge calls, estimated tokens and
  latency, as text and with `--json` as JSON. It runs offline: the judge is
  an in-process stand-in that answers from the sample labels, so its row is
  an upper bound. The samples are new and kept out of threshold sweeps: 88
  held-out steps in `corpus/holdout.jsonl` and five multi-step task scripts
  in `corpus/tasks/` ([docs/guide/evaluation.md](docs/guide/evaluation.md)).

### Changed

- With the judge off, `recursive_delete`, `destructive_git`, `branch_ops` and
  `publish` interrupt their high-impact forms instead of only logging every
  match. The interruption no longer says that the agent chose the operation on
  its own, which h-guard cannot tell without the judge.

### Harnesses

- `h-guard install opencode|pi|omp|dsh` connects opencode 1.x, pi, oh-my-pi
  and DeepSeek Harness. Each gets a thin extension that hands tool calls, tool
  output and prompts to h-guard through the extension protocol v1: a plugin in
  opencode's plugin directory, an extension in pi's or oh-my-pi's extensions
  directory, and a Cordis plugin mounted in `$DSH_HOME/cordis.patch.yml`.
  `status` reports them. The extensions were written against each harness's
  source and have not yet been verified with recorded sessions.
- pi, oh-my-pi and DeepSeek Harness: h-guard keeps a list of each harness's
  read-only tools and asks for any other tool it does not know (`tool_unknown`).
  `harnesses.<name>.read_only_tools` adds your own read-only tools; it cannot
  loosen the checks on tools h-guard knows.
- opencode cannot ask, so `ask` becomes `deny` there; `install opencode` takes
  `--shell` and writes `harnesses.opencode.shell`, as for Codex.
- opencode: the plugin marks MCP tools by the MCP servers opencode reports, and
  h-guard treats them as tools it does not know, so they are blocked unless
  listed in `harnesses.opencode.read_only_tools`. Custom and plugin tools
  still pass. When the servers cannot be looked up, or the plugin predates
  this, any tool that is not one of opencode's own is treated the same way;
  run `h-guard install opencode --write` again after upgrading.
- The locked `guard_tampering` rule also protects the new extensions and the
  settings that can turn them off (oh-my-pi's `config.yml`, pi's and oh-my-pi's
  `settings.json`, DeepSeek Harness's patches), also under `XDG_CONFIG_HOME`,
  `PI_CODING_AGENT_DIR`, `PI_CONFIG_DIR` and `DSH_HOME` and in PowerShell's
  `$env:` form. Path patterns can use `{xdg_config}`, `{pi_agent_dir}`,
  `{omp_config}` and `{dsh_home}`.
- `match.exec` patterns can use the same placeholders (`{pi_agent_dir}`,
  `{dsh_home}`, `{config}` and the others). Each becomes the directory h-guard
  sees, escaped, with `/` and `\` as separators and the `~` and `$HOME` forms
  under the home directory; an unset one never matches. `guard_tampering` uses
  them, so a command that names the actual path under a custom
  `PI_CODING_AGENT_DIR`, `DSH_HOME`, `PI_CONFIG_DIR`, `XDG_CONFIG_HOME`,
  `CLAUDE_CONFIG_DIR` or `CODEX_HOME`, or under h-guard's own directories,
  asks as well.

- `h-guard install openclaw` connects OpenClaw (written against and
  smoke-tested with 2026.10.4). It writes a native plugin to h-guard's
  configuration directory and loads it from `openclaw.json`
  (`plugins.load.paths`, `plugins.entries.h-guard`). When `openclaw.json`
  uses JSON5 syntax or `$include`, or the configuration is read-only
  (`OPENCLAW_NIX_MODE`, `OPENCLAW_CONFIG_READONLY`), it writes only the plugin
  and prints the settings to add yourself. install and status ask OpenClaw
  whether it loads the plugin (`openclaw plugins inspect h-guard --json`, and
  `--runtime` to list its hooks only when the plugin directory holds exactly
  the files h-guard writes) and report "could not verify" when it cannot be
  asked. Tool
  calls are checked in `before_tool_call` (`ask` becomes a
  plugin approval), tool output in the tool result middleware and prompts in
  `before_agent_run` and, for channel messages (including those steered into
  a running turn), `before_dispatch`. A channel message counts as the user's
  instruction once, and only the sender's own text does (the channel envelope
  and quoted messages are checked but never authorize). OpenClaw's own tools are classified like pi's, and for
  `browser`, `message`, `sessions`, `transcripts` and `canvas` by action (only
  observing the browser, reading and sending messages pass). Local files that
  tools send away (message attachments, any `message` parameter whose name
  ends in `Path`, `File` or `Url` since channel plugins can declare their own,
  PDFs, reference media, `MEDIA:` lines) are checked as file reads, with
  `file:` URLs decoded as OpenClaw does and drive-relative `C:foo` taken as a
  path. Other
  tools and actions ask (`tool_unknown`), MCP tools included: the plugin cannot
  tell them from plugin tools with the same kind of name. An opt-in channel notifier
  (`plugins.entries.h-guard.config.notify` in OpenClaw's configuration) sends
  denials and warnings to chats with `openclaw message send`.
- The locked `guard_tampering` rule also protects `openclaw.json` (including
  `OPENCLAW_CONFIG_PATH`, `OPENCLAW_STATE_DIR`, named profiles and the
  pre-rename `clawdbot.json`, the files it pulls in with `$include`, wherever
  they are, for file tools and shell commands alike, and `.json5` files next
  to it), the `~/.openclaw` and `~/.clawdbot`
  directories, and OpenClaw commands that change plugin settings (including
  the `openclaw configure` and `openclaw config` wizards and `openclaw gateway
  call` with `config.set`, `config.patch` or `config.apply`) or disable
  the plugin, reset or uninstall OpenClaw's configuration and state
  (`openclaw reset`, `openclaw uninstall --state`/`--all`, `--reset` on
  `onboard`, `setup` and `gateway`). Path and `exec` patterns can use `{openclaw_config}` and
  `{openclaw_includes}` (matching any included file).
- `h-guard install hermes` connects Hermes Agent through a Python plugin in
  `$HERMES_HOME/plugins/h-guard`, enabled in `plugins.enabled`. Tool calls are
  checked on `pre_tool_call` (`ask` goes to Hermes's own approval, keyed to the
  one call; it becomes `deny` when Hermes would approve without asking), tool
  results and background process output are replaced on `deny`, prompts from
  messaging platforms are blocked when the gateway receives them
  (`pre_gateway_dispatch`), and other prompts get a
  warning on `pre_llm_call`, since they cannot be blocked there. The plugin
  was written against Hermes 2026.9.24 and smoke-tested by driving its hooks
  through Hermes's plugin manager, not yet with a model.
- `harnesses.hermes.notify` (off by default) sends h-guard's masked reason for
  chosen decisions to the originating chat, or a configured `hermes send`
  target, as a best-effort notification.
- New degradation `prompt_not_blocked`: a `deny` on a prompt the harness cannot
  hold back becomes a `warn` that says the prompt has already reached the model.
- The locked `guard_tampering` rule also protects Hermes Agent's
  `config.yaml`, h-guard's plugin directory and the shell-hook allowlist (also
  per profile, under `HERMES_HOME` and on Windows), and the `hermes plugins
  disable|remove` and `hermes config set plugins.*` commands. Path patterns, and
  `exec` patterns, can use `{hermes_home}`, so a command naming the real path of
  a custom `HERMES_HOME` is covered as well; `{hermes_managed}` (Hermes's
  managed scope, `$HERMES_MANAGED_DIR` or `/etc/hermes`) protects the managed
  `config.yaml` the same way. `install hermes` and `status` take the managed
  scope's `plugins` settings into account.

### Public packages

- `pkg/detect/command` adds `ReadTargets`: the files a command reads locally
  (file operands of common read commands, input redirections and PowerShell's
  `Get-Content` paths).
- New adapters `pkg/harness/opencode`, `pkg/harness/pi` (registers `pi` and
  `omp`), `pkg/harness/dsh`, `pkg/harness/openclaw` and `pkg/harness/hermes`.
- `pkg/harness` adds `UnknownToolError` for tools an adapter does not know.
- `pkg/harness/extproto`: `Reply` has an optional `Subject`, a summary of the
  call with recognized credentials masked, for extensions that show the call to
  a person.
- `pkg/harness` adds `ErrNoAction` and the optional `NoActionRenderer`: an
  adapter that answers every request (extension protocol) replies `pass` to a
  tool call with nothing to check, so an empty reply always means h-guard could
  not run.

## [0.1.0] - unreleased

First public release.

### Action checks

- Checks the commands and file operations an agent is about to run against
  built-in rules for catastrophic deletion, recursive delete, destructive git,
  protected-branch operations, publishing, reading sensitive files, tampering
  with the guard itself, bypassing verification, fork bombs and encoded
  execution. Rules are YAML rule packs you can extend or turn off. Three
  locked rules (`catastrophic`, `fork_bomb`, `guard_tampering`) apply at every
  tier and cannot be replaced by a rule pack; turning one off is allowed but
  `config validate` and `install` warn about it.
- Three tiers (`action.tier`, default 2) set what is checked: tier 1 covers
  shell commands, tier 2 adds file reads, writes, deletes and renames, tier 3
  adds other tool calls and HTTP requests. Tier 2 also recognizes file reads
  wrapped in containers and remote shells (`docker`, `podman`, `kubectl exec`,
  `ssh`, `sh -c`), compressed-file reads, `git log -p` and PowerShell
  equivalents.
- Verdicts only get stricter: `deny > ask > warn > pass`. A failure of the
  model or of a backend never turns into a pass that the local rules would not
  have given.
- With the model off (the default), the categories of dangerous operation that
  can only be judged by a model are not judged; only the local rules run.

### Outbound checks

- Scans prompts and tool output for credentials, private keys and, when the
  `pii` category is enabled, personal data (email addresses, mainland China and
  international phone numbers, Chinese resident ID numbers, US SSNs, public IP
  addresses). Credentials and private keys are on by default; `pii` is off.
- A blocked prompt or output is reported with a category, a hit count and line
  numbers only; the matched text is not put in the reason.
- When the model is enabled and no local rule denies, long text can be sent to
  the judge in masked chunks for the categories that need judgment; a model
  hit is reported but never overrides a local hit.
- Judge-layer masking before sending also covers personal-data shapes that the
  local PII detector excludes in developer text (for example SSH addresses,
  version-like numbers and diff markers), so more is masked than is reported.
- PII detection now reports a phone number at the start of a line outside a
  diff hunk, and an email address followed by `:` and whitespace or the end of
  the text. This is a tightening, and applies only when the `pii` category is
  enabled.

### Judge backends and calibration

- Built-in backends: `typesafe`, `openai` (OpenAI-compatible, including local
  servers such as Ollama), `anthropic` and `exec` (an external program).
  Preconfigured backends are `claude-haiku`, `claude-sonnet`, `gemma4-local`
  and `jev` (the default selection); each ships with calibrated thresholds.
- Calibration profiles are pinned to the backend's model, answer mechanism and
  the wording of the questions. A profile that no longer matches is treated as
  uncalibrated.
- Backend use needs explicit, scoped consent that is tied to the backend's
  name, type and endpoint. Nothing is sent to a model until consent is given.
- The `claude-haiku` outbound threshold (0.2) was calibrated on the outbound
  corpus before the wider masking above, so it applies to text masked more
  loosely than it is now.

### Harness integration

- Works with Claude Code (as a plugin, Claude Code 2.1.290 or later) and
  Codex (as a hook), and with any agent harness through the generic JSON
  contract.
- Codex does not support `ask`; where a harness cannot ask, the configured
  fallback (`policy.when_ask_unsupported`, default `deny`) applies.
- Extension authors can add harness adapters, checks and judge backends from
  their own module using only `pkg/`.

### Install and configuration commands

- `h-guard install claudecode|codex` previews the change; `--write` applies it
  and `--remove --write` removes it. A backup is made before existing files
  are overwritten or removed.
- `h-guard init` guides you through choosing a backend, giving consent and
  enabling the model. `h-guard status` reports entry points, consent, rules
  that have no effect, calibration and recent degradations.
- `h-guard config init|show|validate` manage the configuration. JSON Schemas for
  the configuration and for action and outbound rule packs are in `schema/`, and
  the file written by `config init` points editors at the configuration schema.
- `h-guard migrate` converts an earlier Python version's `questions.json`
  edits into a configuration and rule packs.
- `h-guard version` shows the module version for builds made with
  `go install ...@vX.Y.Z`.

### Evaluation

- `h-guard eval` replays the built-in command corpus (and a PowerShell corpus)
  through a backend and reports miss and false-alarm rates; `--sweep` suggests
  thresholds.
- `h-guard eval --outbound` does the same for the outbound corpus, with and
  without the model.
- Corpora are written by the maintainers; no samples come from public datasets.

### Versions

The formats are versioned independently of the program:

| Format | Version |
|---|---|
| Configuration schema (`version:`) | 1 |
| Rule pack schema (`schema:`) | 1 |
| Judge exec protocol (`h-guard.judge/v1`) | v1 |
| Generic harness contract (`version` field) | v1 |
| Extension protocol (`h-guard.ext/v1`) | v1 |
