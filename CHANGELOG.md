# Changelog

All notable changes are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

Before v1.0 the public Go packages under `pkg/` may change incompatibly between
minor releases. Every such change is recorded in this file.

## [Unreleased]

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
- The locked `guard_tampering` rule also protects the new extensions and the
  settings that can turn them off (oh-my-pi's `config.yml`, pi's and oh-my-pi's
  `settings.json`, DeepSeek Harness's patches), also under `XDG_CONFIG_HOME`,
  `PI_CODING_AGENT_DIR`, `PI_CONFIG_DIR` and `DSH_HOME` and in PowerShell's
  `$env:` form. Path patterns can use `{xdg_config}`, `{pi_agent_dir}`,
  `{omp_config}` and `{dsh_home}`.

- `h-guard install hermes` connects Hermes Agent through a Python plugin in
  `$HERMES_HOME/plugins/h-guard`, enabled in `plugins.enabled`. Tool calls are
  checked on `pre_tool_call` (`ask` goes to Hermes's own approval, keyed to the
  one call; it becomes `deny` when Hermes would approve without asking), tool
  results and background process output are replaced on `deny`, prompts from
  messaging platforms are blocked after admission, and other prompts get a
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
  disable|remove` and `hermes config set plugins.*` commands. Path patterns can
  use `{hermes_home}`.

### Public packages

- New adapters `pkg/harness/opencode`, `pkg/harness/pi` (registers `pi` and
  `omp`), `pkg/harness/dsh` and `pkg/harness/hermes`.
- `pkg/harness` adds `UnknownToolError` for tools an adapter does not know.
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
