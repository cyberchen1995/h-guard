# Harnesses

h-guard connects to Claude Code, Codex, opencode, pi, oh-my-pi, DeepSeek
Harness and Hermes Agent with `h-guard install`, and to any other agent harness
through the
[generic contract](protocols.md#generic-harness-contract-v1).
For what h-guard intercepts, see
[What it checks](../../README.md#what-it-checks).
This guide describes how each connection works, what each harness can do with
h-guard's decisions, and what happens when it cannot.

## Installing and removing

```sh
h-guard install claudecode|codex|opencode|pi|omp|dsh|hermes [--write] [--remove] [--timeout <seconds>] [--shell posix|powershell]
```

- Without `--write`, `install` prints what it would change and writes nothing.
  The preview shows only h-guard's own entries, not the rest of the files
  (they may hold secrets).
- With `--write`, each file that is changed is backed up first, then written
  atomically. If someone else changes the file at the same time, `install`
  stops instead of overwriting. Running it again updates h-guard's entries
  without adding duplicates; other hooks and settings are kept.
- `--remove --write` removes only h-guard's entries. It does not read the
  configuration, so it works even when the configuration is broken.
- Before writing, `install` loads the configuration and rules the way the hook
  does: it refuses an invalid configuration and warns about disabled locked
  rules.
- Every entry point is registered once, whatever the tiers; the tiers decide at
  run time what is checked, so changing them needs no new `install`.
- The h-guard path written into the entries is the one on your `PATH` when that
  is the same file as the running binary, otherwise its real path. A binary
  built by `go run` is refused.
- `--timeout` (default 20 seconds) is written both as the harness's hook
  timeout and as `--timeout` for h-guard, which always answers before it.

`h-guard status` reports, for each harness, whether the entries are installed
and match what this h-guard would write (missing, pointing to a binary that no
longer exists, wrong timeout, duplicated), the harness version and whether it
has been verified.

## Claude Code

Supported: Claude Code 2.1.290 or later; verified with 2.1.296. Older versions
lack mods, so tool output and prompts are not checked there.

`install claudecode --write`:

1. writes h-guard's Claude Code plugin to `extensions/claudecode` in h-guard's
   configuration directory, with the h-guard path and timeout in
   `hguard-bin`, `hguard-timeout` and `hguard.json`;
2. adds that directory to `env.CLAUDE_CODE_PLUGIN_DIRS` in
   `~/.claude/settings.json` (under `$CLAUDE_CONFIG_DIR` when set), keeping any
   directories already listed;
3. runs `claude plugin validate` when the `claude` command is available.

Removing unregisters the directory first, then deletes the plugin directory
after checking that it really is h-guard's plugin.

The plugin has two parts:

| Part | Event | What h-guard does |
|---|---|---|
| Classic `PreToolUse` hook | every tool call, before it runs | checks the actions (commands, file reads, writes, deletes, renames); answers `deny` or `ask` through Claude Code's permission decision |
| Mod, `tool.result` | after a tool ran, before Claude sees the result | scans the output (outbound); on `deny` the result is withheld and Claude reads h-guard's reason instead |
| Mod, `prompt.submit` | before a prompt is sent | scans the prompt; on `deny` the prompt is not sent and the reason is shown |

Actions go through the classic hook because its `ask` always opens Claude
Code's permission prompt in interactive sessions, in the default, auto and
bypass-permissions modes. In `-p` (print) mode and the `dontAsk` mode there is
nobody to ask and Claude Code refuses the call, which is the safe direction.
A `deny` or `ask` from h-guard is combined with your own permission rules and
the stricter one wins; organization-managed policy can still override it.

When h-guard cannot run (not found, failed to start, non-zero exit), the
`PreToolUse` wrapper answers `ask`, and the mod passes the result or prompt on
and tells you the check did not run. On Windows the wrapper is a PowerShell
script (`powershell -NoProfile -ExecutionPolicy Bypass -File ...`); it has not
been verified on a real Windows machine.

Managed settings can switch parts off: `allowManagedHooksOnly` disables the
plugin's classic hook (actions are no longer checked while the mod still runs),
`allowManagedModsOnly` disables the mod, `disableAllHooks` disables both. In such
organizations the plugin has to be installed through the organization's managed
configuration. Another plugin's mod that answers `tool.check` can make the
`ask` lose its forced permission prompt.

Claude Code labels the origin of each prompt; scheduled tasks, sub-agent
reports and messages from other sessions are treated as automated and never
count as your request. Unknown origins count as yours.

## Codex

Supported: verified with Codex 0.162.1; older versions get a note in `install`
and `status`.

`install codex --write` registers three hooks in `~/.codex/hooks.json` (under
`$CODEX_HOME` when set): `PreToolUse` for all tools, `PostToolUse` and
`UserPromptSubmit`. Each runs
`'<h-guard>' hook codex --event <event> --timeout <seconds>`. Entries are
recognized by that exact form; other entries are kept.

**Trust the hooks.** Codex does not run new or changed hooks until you trust
them: open Codex and run `/hooks`. Until then h-guard does nothing. h-guard
cannot read Codex's trust state, so `h-guard status` shows the hooks as
"unverified" until Codex actually runs one of them (each hook run is recorded
in the cache directory); `h-guard selftest codex` checks that the registered
commands run h-guard and block what they should, but not that Codex trusts them.

| Hook | What h-guard does |
|---|---|
| `PreToolUse` | checks the actions; `deny` stops the tool call. File edits through `apply_patch` are checked as file writes, deletes and renames. |
| `PostToolUse` | scans the output; `deny` replaces the tool result with h-guard's reason. |
| `UserPromptSubmit` | scans the prompt; `deny` blocks it. The interactive interface shows the reason; `codex exec` ends silently. |

Codex differences:

- **No ask.** A Codex hook cannot ask you to confirm; the tool call would just
  run. h-guard therefore turns every `ask` into `deny` on Codex
  (`policy.when_ask_unsupported`, default `deny`, recorded as
  `ask_unsupported`). For an operation you can approve (any `ask` except
  guard self-protection), the reason carries an id, and you can let exactly
  that operation run once: run `h-guard allow <id>` in your own terminal
  (`h-guard allow` alone lists what was stopped in the last hour), confirm,
  then ask the agent to retry it unchanged. The approval covers that command
  in that working directory only, expires after 10 minutes (`--ttl`, at most
  1h), is used up by the first retry, and `h-guard allow --revoke <id>`
  withdraws it. Approvals are signed with a key in h-guard's configuration
  directory (`grant.key`), and so are the stopped operations `h-guard allow`
  shows; records written to the cache without the key are ignored, and a used
  approval is recorded next to the key so putting the same record back does not
  work. The approval is bound to the Codex session it was stopped in, to the
  exact tool input Codex sent, which `h-guard allow` shows, and to the real working directory and its file identity (a
  symlinked one that is retargeted, or another directory moved into the same
  path after approval, does not match; an event without a working directory
  gets no approval). Text written into a running interactive process
  (`write_stdin`) gets none either: the process's directory and state can
  change after approval. Only shell commands get
  one: tool calls with file actions (the approval could not cover what is
  written, or where a path points when it is read) and operations h-guard could
  not fully parse get no approval. An agent that can read that key could still forge one (see the
  known limitations in the README). `allow` only approves in an interactive terminal, and running
  it through a harness asks (guard self-protection). Otherwise run the
  operation yourself, or name it explicitly in your next message when the
  judge is on.
- **No warnings.** Codex hooks cannot show a warning, so `warn` is not
  delivered (recorded as `warn_undelivered`). Because the judge's outbound
  findings are warnings, prompts and tool output are never sent to the judge on
  Codex.
- **Shell.** Codex does not say which shell runs a command. h-guard uses
  `harnesses.codex.shell` (default `posix`); on Windows `install codex` asks
  which shell to use (default `powershell`), or takes `--shell` when not run
  in a terminal. If you later switch shells, update this setting, or the wrong
  set of PowerShell or POSIX patterns is used.
- **Prompt origin.** Codex does not label automated messages. h-guard
  recognizes the known formats of its automated messages (for example
  sub-agent reports and the memory agent); a message it does not recognize
  counts as yours.
- **Timeouts.** Codex treats a hook that times out as passing; h-guard answers
  before `--timeout` runs out.
- **Transcript.** Codex writes the original tool output to its own transcript
  even when h-guard replaced it for the model.
- **Windows.** Paths that would need quoting are refused, and Codex's hook
  command forms on Windows have not been verified.

## opencode

Supported: opencode 1.x; the plugin was written against opencode 1.19.3 and
smoke-tested with it (no recorded sessions yet). opencode 2.x has a
different plugin API and does not load this plugin; `install` and `status`
say so.

`install opencode --write` writes one file, h-guard's plugin, to
`plugins/h-guard.js` in opencode's global configuration directory
(`$XDG_CONFIG_HOME/opencode`, default `~/.config/opencode`, also on Windows).
opencode loads every plugin in that directory at startup, so its configuration
files are not changed. The h-guard path and timeout are written into the
plugin. Restart opencode afterwards. `OPENCODE_PURE=1` or `--pure` disables
all external plugins, h-guard's included.

| Plugin hook | What h-guard does |
|---|---|
| `tool.execute.before` | checks the actions (`bash` commands; `read`, `grep`, `write`, `edit`; the files in an `apply_patch`); on `deny` the plugin throws, the tool does not run and the model reads h-guard's reason |
| `tool.execute.after` | scans the output; on `deny` the output the model sees (and the tool's own copy shown in the interface) is replaced with h-guard's reason |
| `chat.message` | scans the message, including the text of attached files; on `deny` the message is neither saved nor sent, and a toast shows the reason (`opencode run` only reports a generic server error) |

opencode differences:

- **No ask.** The plugin API has no way to ask the user, so `ask` becomes
  `deny` (`policy.when_ask_unsupported`, recorded as `ask_unsupported`), as on
  Codex.
- **Warnings are toasts.** They are shown in the TUI only, not in
  `opencode run` or a headless server.
- **Shell.** On Windows opencode's `bash` tool usually runs PowerShell, and
  the plugin hook does not say which shell runs a command. h-guard uses
  `harnesses.opencode.shell` (default `posix`); on Windows `install opencode`
  asks which shell to use, or takes `--shell` when not run in a terminal.
- **Prompt origin.** A message in a sub-agent's session (the `task` tool) is
  the parent agent's task and counts as automated; the plugin looks up each
  session's parent for this. Other messages count as yours.
- **MCP tools.** opencode names an MCP tool `<server>_<tool>`, the same shape
  as a custom tool in `.opencode/tool/` (`<file>_<export>`). Before each tool
  call the plugin asks opencode for its MCP servers (`client.mcp.status`) and
  marks a tool whose name starts with a server's name as an MCP tool. MCP tools
  are treated as tools h-guard does not know (see
  [below](#tools-h-guard-does-not-know)): since opencode cannot ask, they are
  blocked unless listed in `harnesses.opencode.read_only_tools`, even when the
  name matches one of opencode's own tools (an MCP tool replaces a built-in of
  the same name). If the lookup fails or takes longer than 5 seconds, any tool
  that is not one of opencode's own is treated the same way.
  Custom tools and tools added by plugins pass, as before; one whose name
  starts with an MCP server's name counts as an MCP tool.
- **Not covered.** Commands you type with `!` and terminal sessions do not go
  through tool hooks.

When h-guard cannot run, the plugin blocks the tool call (opencode cannot
ask), and lets tool output and prompts through with a toast saying the check
did not run.

## pi and oh-my-pi

Supported: pi (`pi`, written against and smoke-tested with 1.3.0) and oh-my-pi
(`omp`, a fork of pi, written against and smoke-tested with 18.11.3); there are
no recorded sessions of them yet.

oh-my-pi keeps pi's extension API, so one extension serves both, but it
manages extensions differently. Install for the one you use:

| | pi | oh-my-pi |
|---|---|---|
| `install` | `h-guard install pi --write` | `h-guard install omp --write` |
| Extension written to | `~/.pi/agent/extensions/h-guard.js` | `~/.omp/agent/extensions/h-guard-omp.js` |
| Agent directory | `$PI_CODING_AGENT_DIR`, default `~/.pi/agent` | `$PI_CODING_AGENT_DIR`, default `~/<$PI_CONFIG_DIR or .omp>/agent`; other profiles (`OMP_PROFILE`) are not covered |
| Settings | `settings.json` | `config.yml` (a legacy `settings.json` is still read) |
| Packages | `pi install npm:…` (`packages` in settings) | `omp plugin install …` (`~/.omp/plugins`, `"omp"` or `"pi"` in package.json) |
| Turning extensions off | `--no-extensions` | `--no-extensions`, `disabledExtensions` |
| Prompt event result | `{action: "handled"}` | `{handled: true}`; the extension returns both |

Neither runs Claude Code style command hooks: oh-my-pi reads `.claude`
directories for skills and commands but ignores their `hooks`, so h-guard
connects to both through the extension. Both load files from the global
extensions directory automatically; `install` does not change their settings.
When `PI_CODING_AGENT_DIR` makes pi and oh-my-pi share one directory, both
would load both extensions, so `install` refuses the second one. Run `/reload`
or restart after installing.

| Extension event | What h-guard does |
|---|---|
| `tool_call` | checks the actions (`bash`, pi's `powershell` on Windows; `read`, `grep`, `write`, `edit`; oh-my-pi's patch-style `edit` and `eval`; `ast_edit` only previews, so it is checked as reading its files, and applying it through `xd://resolve` asks); `deny` blocks the call and the model reads the reason; `ask` opens a confirmation dialog |
| `tool_result` | scans the output; `deny` replaces the content the model sees |
| `input` | scans the prompt; `deny` drops it and shows the reason |
| `context` | scans user messages that `input` did not see (pi's expanded `/skill:` and prompt templates, oh-my-pi's `-p` and SDK prompts); `deny` replaces the message the model receives with h-guard's reason |

Differences:

- **Prompts `input` does not see.** pi expands `/skill:` and prompt
  templates after `input`, and oh-my-pi fires `input` only in its interface and
  in RPC mode. These prompts are checked on `context`, just
  before each model request: a denied prompt reaches the model only as
  h-guard's reason and the model still answers it, and the session file keeps
  the original text.
- **Ask without a user.** In print (`-p`) and JSON mode there is no dialog;
  `ask` blocks the call, which is the safe direction. In RPC mode the dialog
  goes to the RPC client.
- **Warnings** are notifications in the interface; without one they go to
  stderr.
- **oh-my-pi's `eval`** runs Python or JavaScript code that h-guard cannot
  read, so every call asks. oh-my-pi's patch-style `edit` (and `apply_patch` in
  that mode) is read from its file headers (`REM` deletes, `MV` renames), and
  its `patch` mode from each entry's `op` and `rename`, and its `sloppy` mode
  from the `*** Edit File:` lines; an edit whose files
  cannot be read asks. `lsp` renames, applied code actions and raw requests
  change files h-guard cannot list, so they ask; so do `lsp` reloads and
  workspace diagnostics (`file: "*"`), which start language servers or run
  `cargo check`, `npx tsc`, `go build` and `pyright`. `read` paths lose their line
  selectors (`a.go:10-20`). Paths are normalized as oh-my-pi does: `file://`
  URLs become the file, and a stray leading `:` or `@` is dropped. oh-my-pi's `write` is checked against the file it
  really changes: an archive entry (`a.zip:inner`) or SQLite row
  (`app.sqlite:users:42`) counts as a write to the archive or database, and
  `xd://resolve` (which applies a previewed `ast_edit` or edit), other `xd://`
  devices, `conflict://` and other internal URLs ask; so does an `edit` of an
  internal URL. A `task` with `isolated: true` asks, because its changes are
  merged back into your workspace without a tool call.
- **Shell.** Both run `bash` commands with a bash-compatible shell on every
  platform (pi uses Git Bash on Windows; oh-my-pi has its own), so they are
  checked as POSIX commands.
- **Prompt origin.** A prompt sent by an extension (`source: "extension"`,
  or on oh-my-pi a message with `attribution: "agent"`) counts as automated, and so does every prompt in an oh-my-pi sub-agent's
  session (the `task` tool, `eval`'s `agent()`); prompts from the interface,
  RPC and `-p` count as yours.
- **Not covered.** Commands you type with `!` do not go through `tool_call`.

When h-guard cannot run, the extension asks before a tool call (and blocks it
without a user), and lets tool output and prompts through with a notification.

## DeepSeek Harness

Supported: DeepSeek Harness (`dsh`), written against and smoke-tested with
0.2.1-rc.2; no recorded sessions yet.

`install dsh --write`:

1. writes h-guard's Cordis plugin to `extensions/dsh/h-guard.mjs` in h-guard's
   configuration directory, with the h-guard path and timeout in it;
2. adds a row `{id: h-guard, name: <plugin path>}` under `- insert:` in
   `$DSH_HOME/cordis.patch.yml` (default `~/.dsh/cordis.patch.yml`), the user
   patch that applies to every profile, keeping the rest of the patch.

Removing deletes the row first, then the plugin. The plugin starts h-guard
itself, outside dsh's shell sandbox. DeepSeek Harness also ships a Claude Code
hooks bridge, but it is off by default and cannot replace tool output, so
h-guard does not use it.

| Plugin event | What h-guard does |
|---|---|
| `tools/pre-execute` | checks the actions (`bash`, `pwsh` on Windows; `read`, `grep`, `write`, `edit`, `str_replace_editor`); `deny` stops the call and the model reads the reason; `ask` goes to dsh's approval service |
| `tools/post-execute` | scans the output; `deny` replaces the result with h-guard's reason, marked as an error |
| `agent/pre-step` | scans the new messages of each step; `deny` rejects the step |

DeepSeek Harness differences:

- **Ask without a user.** Headless and SDK runs have nobody to answer, and
  under `danger-full-access` approvals are never asked; dsh rejects the call in
  both cases, which is the safe direction.
- **No warnings.** dsh has no way for a plugin to show the user a message, so
  `warn` is not delivered (recorded as `warn_undelivered`) and the judge's
  outbound findings are not requested, as on Codex. A rejected prompt is
  dropped without a message in the conversation; the reason goes to dsh's log.
- **Prompt origin.** Each message's `source.kind` is used: `user` is yours,
  anything else (schedules, sub-agent results, injected context) is automated;
  every message in a sub-agent's session counts as automated.
- **Working directory.** The session's current directory (it follows the
  `working_directory` tool), or the command's `workdir`.
- **Code tools.** Calls made from `run_code` are checked one by one as they
  reach the tool pipeline; `run_code` itself is not.
- **Terminals.** Text sent to a persistent terminal (`terminal_send`) is
  checked as a POSIX command and always asks, because the terminal's shell is
  not known; its output is scanned as file content when the text reads files.
  `terminal_open` starts a shell, and `terminal_signal`, `terminal_close` and
  `job_kill` end processes, so they ask.

When h-guard cannot run, the plugin asks before a tool call and lets tool
output and prompts through with a line in dsh's log.

## Hermes Agent

Supported: Hermes Agent (`hermes`), written against the 2026.9.24 release
source and smoke-tested with it: the plugin was loaded by Hermes's own plugin
manager in a temporary home and its hooks were driven directly, without a model
or a messaging gateway. There are no recorded sessions yet.

`install hermes --write`:

1. writes h-guard's Python plugin (`plugin.yaml` and `__init__.py`, standard
   library only) to `plugins/h-guard/` in Hermes's home: `$HERMES_HOME`
   (environment variables and a leading `~` in it expanded as Hermes does),
   default `~/.hermes` (`%LOCALAPPDATA%\hermes` on Windows), with the h-guard
   path and timeout in it;
2. adds `h-guard` to `plugins.enabled` in `config.yaml` there (Hermes loads no
   user plugin that is not listed) and takes it out of `plugins.disabled`,
   keeping the rest of the file (comments are kept, the layout may be
   normalized). When `plugins.hook_callback_timeout` (default 30 seconds) is
   shorter than h-guard's timeout plus 5 seconds, it is raised, because Hermes
   blocks a tool call whose hook does not answer in time; a value that is not
   a number, which Hermes replaces with the default, is replaced the same way,
   and `status` reports it. Hermes accepts at
   most 600 seconds there, so `--timeout` is at most 595 for `hermes`.
   Removing h-guard later leaves a raised timeout as it is. When an
   administrator's managed scope (`/etc/hermes/config.yaml`, or
   `$HERMES_MANAGED_DIR`) sets `plugins.enabled` without h-guard, lists it in
   `plugins.disabled` or sets a `plugins.hook_callback_timeout` that is too
   short, it overrides the user configuration, so `install` stops and says so
   instead of changing a file Hermes would ignore, and `status` reports it.

Hermes asks for no other consent for a plugin enabled this way. Hermes
discovers plugins once per process, and its sessions (CLI, TUI, Desktop,
messaging, cron) run in the gateway process, so restart Hermes (for example
`hermes gateway restart`) and start new sessions afterwards.
Profiles other than the active one (`~/.hermes/profiles/<name>`) are not
changed; run `install` with `HERMES_HOME` set to the profile's directory for
each. Removing takes `h-guard` out of `plugins.enabled` first, then deletes the
plugin directory, without reading h-guard's configuration.

The plugin uses only Python hooks. Hermes also has shell hooks (`hooks:` in
`config.yaml`), but each one needs a per-command consent recorded in
`~/.hermes/shell-hooks-allowlist.json` and is silently skipped in headless
runs until then, and the plugin hooks already cover tool calls, so h-guard does
not use them.

| Plugin hook | What h-guard does |
|---|---|
| `pre_tool_call` | checks the actions (`terminal`; `read_file`, `search_files`, `write_file`; `patch` in replace mode and the files of a V4A patch; `process_manage` input; `execute_code` asks); `deny` returns `block` and the model reads the reason; `ask` returns `approve`, which goes to Hermes's own approval: the CLI prompt, or the approval card with `/approve` and `/deny` on messaging platforms |
| `transform_tool_result` | scans every tool result except `process_manage`; `deny` replaces it with h-guard's reason |
| `transform_terminal_output` | scans the output of background processes (`process_manage` poll, wait and log, and completion and watch notifications); `deny` replaces it |
| `pre_gateway_dispatch` | scans a message from a messaging platform when the gateway receives it, before the turn starts (only from senders Hermes authorizes); `deny` drops it (`skip`) and replies to the chat with the reason, except to bots |
| `pre_llm_call` | scans the user message of every turn, including the CLI, TUI and Desktop; it cannot block, so a `deny` reaches the model as a warning (see below) |

Hermes differences:

- **Approvals.** The approval prompt shows only the text the plugin sends, so
  the plugin adds the command or paths to h-guard's reason. Each request
  carries a `rule_key` made from the tool, its arguments and the reason; a
  "session" answer therefore covers only that same call, and an "always"
  answer stores `plugin_rule:h-guard:<tool>:<hash>` in `command_allowlist` in
  `config.yaml`, which Hermes then approves without asking. Remove the entry to
  be asked again. Without a key Hermes would key the answer by tool name, and
  one "always" would pass every later h-guard question about that tool.
- **Approvals that nobody answers.** With nobody to ask (headless, `-q`, cron
  with `approvals.cron_mode: deny`), Hermes blocks the call, which is the safe
  direction. Under `--yolo`, `/yolo`, `approvals.mode: off`, `hermes -z`, or an
  `approvals.*_mode: approve` that applies, Hermes would approve without
  asking; the plugin reads this from Hermes before each call, and h-guard then
  turns the `ask` into `deny` (`policy.when_ask_unsupported`, recorded as
  `ask_unsupported`). When the plugin cannot tell, it does the same.
- **Prompts in the CLI cannot be blocked.** No plugin hook can hold back a
  prompt typed into the CLI, TUI or Desktop. There h-guard turns a `deny` into
  a warning, recorded as `prompt_not_blocked`: the prompt has already reached
  the model, and h-guard's reason, with a request not to repeat or use the
  sensitive content, is added to that turn as context. On messaging platforms
  the message is checked when it arrives, before the turn starts, and blocked
  there.
- **No warnings for you.** Hermes has no way for a plugin to show you a
  message, so warnings on actions and tool output go to Hermes's log
  (recorded as `warn_undelivered`) and the judge's outbound findings are not
  requested for tool output; prompt warnings reach the model as context.
- **Prompt origin.** A sub-agent's task (`delegate_task`), a cron job's prompt,
  a webhook payload and a message from another bot count as automated;
  everything else counts as yours. Hermes marks bot messages only on the
  event that `pre_gateway_dispatch` sees, so the plugin records them there for
  `pre_llm_call`; a person's message with the same text on the same platform
  then counts as automated too. Messages that a plugin injects into a
  session cannot be told apart and count as yours.
- **Shell and paths.** `terminal` runs a bash-compatible shell everywhere (Git
  Bash on Windows), so commands are checked as POSIX. The working directory is
  the session's terminal directory, which follows `cd`. With a sandboxed
  `terminal.backend` (`docker`, `ssh`, `modal`, `daytona`, `singularity`,
  `vercel_sandbox`), commands and file tools act inside the sandbox, but h-guard
  still checks their paths as host paths, so it may ask about files that only
  exist in the sandbox. Hermes skips its own dangerous-command check on most
  sandboxes; h-guard's checks still run.
- **Code tools.** `execute_code` runs a Python script that can start processes
  and change files directly, so every call asks. The tool calls the script
  makes through `hermes_tools` are checked one by one as well.
- **Background processes.** Text written to a background process
  (`process_manage` `write` and `submit`) is checked as a POSIX command and
  always asks, because the process may not be a shell; `kill` and `close`
  ask as tools h-guard does not know.
- **Other tools that ask.** Hermes's tools that write lasting memory or
  skills (`memory`, `skill_manage`), control the desktop (`computer_use`),
  act in a browser page (`browser_click`, `browser_type`, `browser_press`,
  `browser_dialog`, `browser_cdp`, `browser_vault`, `browser_exec`,
  `browser_console` with an `expression`, and the Desktop preview's clicks),
  schedule or change cron jobs (`cronjob_manage` except `list`), install
  plugins or MCP servers (`manage_catalog`, `manage_connections` except
  `status`), administer a Discord server (`discord_admin`), switch Desktop
  projects or close terminal panes, and every tool a
  plugin adds, ask with the reason `tool_unknown`; the read-only Home Assistant
  tools of the `homeassistant` catalog plugin (`ha_list_entities`,
  `ha_get_state`, `ha_list_services`) pass, and `ha_call_service` asks. `text_to_speech` with an
  `output_path` is checked as a file write.
- **Other plugins.** Another plugin's `block` still wins over h-guard's
  `approve`, and another plugin's `modify` can change a tool's arguments after
  h-guard checked them. For `transform_tool_result` and
  `transform_terminal_output` the first plugin that returns a replacement
  wins, so a plugin that loads before h-guard and rewrites a result keeps
  h-guard's replacement from applying.
- **Not covered.** MCP tools and connectors (`mcp__…`, `connectors__…`) pass,
  as on the other harnesses. Gateway events that Hermes generates itself
  (background-process notifications) skip `pre_gateway_dispatch`; their text
  is process output, which `transform_terminal_output` checks.

When h-guard cannot run, the plugin asks before a tool call (and blocks it when
Hermes would approve it without asking), and lets tool output and prompts
through with a line in Hermes's log.

### Channel notifications

Hermes can deliver h-guard's decisions to a messaging channel. This is off by
default; turn it on in h-guard's configuration:

```yaml
harnesses:
  hermes:
    notify:
      enabled: true
      on: [deny, warn]                # default; ask is also accepted
      to: telegram:-1001234567890     # optional, for sessions without a chat
```

When a decision is in `on` (before or after h-guard adjusted it to what Hermes
can do, so a prompt `deny` that became a warning counts as `deny`), the plugin
runs `hermes send --to <target>` in the background with h-guard's localized,
masked reason, never the command, output or prompt itself. The target is the
chat the session came from (a messaging session, or a cron job's delivery
target); for CLI, TUI and Desktop sessions it is `to`, written as for
`hermes send`: `telegram` (the platform's home channel, set with `/sethome` or
`TELEGRAM_HOME_CHANNEL`), `telegram:<chat_id>`,
`telegram:<chat_id>:<thread_id>` or `discord:#ops`. Without either, nothing is
sent. A chat that already shows the decision (an approval card, a dropped
message's reply) gets no second message. `hermes send` uses the credentials
Hermes is configured with and needs no running gateway for Telegram, Discord,
Slack, Signal, SMS and WhatsApp Cloud. Sending is best effort: it never changes
or delays the decision, a failure is logged in Hermes's log, and the health log
still counts undelivered warnings.

```yaml
# Only blocked actions, to a Slack channel, for every session
harnesses:
  hermes:
    notify: {enabled: true, on: [deny], to: 'slack:#security'}
```

## Tools h-guard does not know

For pi, oh-my-pi, DeepSeek Harness and Hermes Agent, h-guard knows every tool
the harness ships:

- tools that run commands or change files are checked as actions;
- tools that only read, search, plan or coordinate pass;
- MCP tools (`mcp__…`) pass, as on Claude Code and Codex;
- anything else asks, with the reason `tool_unknown`. That covers the
  harness's remaining tools, which can run code, install plugins, schedule
  runs or change remote repositories, and tools added by extensions or
  plugins.

List the tools you know to be read-only in the configuration; `*` and `?`
match any characters:

```yaml
harnesses:
  pi: {read_only_tools: [web_*]}
  omp: {read_only_tools: [my_search, docs_*]}
  dsh: {read_only_tools: [plugin_market]}
  hermes: {read_only_tools: [my_plugin_search]}
```

The list only applies to tools h-guard does not know: a shell or file tool
named there is still checked.

For opencode, h-guard knows opencode's own tools; custom tools and tools added
by plugins pass, and MCP tools count as tools it does not know. opencode
cannot ask, so an MCP tool is blocked (`policy.when_ask_unsupported`) until
you list it:

```yaml
harnesses:
  opencode: {read_only_tools: [docs_search, context7_*]}
```

## What each harness can do

| Event | Claude Code | Codex | opencode | pi, oh-my-pi | DeepSeek Harness | Hermes Agent | Generic |
|---|---|---|---|---|---|---|---|
| Action: deny | yes | yes | yes | yes | yes | yes | caller applies it |
| Action: ask | yes (permission prompt) | no, becomes `deny` | no, becomes `deny` | yes (dialog) | yes (approval service) | yes (Hermes approval); `deny` when Hermes would approve without asking | caller applies it |
| Action: warn | yes (shown to you) | no | yes (toast) | yes (notification) | no | no (log; channel notification if configured) | caller applies it |
| Prompt: block | yes | yes | yes | yes | yes | messaging platforms only; elsewhere becomes a warning | caller applies it |
| Prompt: warn | yes (added as context for Claude) | no | yes (toast) | yes (notification) | no | yes (added as context for the model) | caller applies it |
| Tool output: replace | yes (result withheld) | yes (result replaced) | yes | yes | yes (result replaced) | yes (result replaced) | caller applies it |
| Tool output: warn | yes (shown to you) | no | yes (toast) | yes (notification) | no | no (log; channel notification if configured) | caller applies it |
| Prompt origin | labeled by Claude Code | inferred from known formats | sub-agent sessions | `source` of the prompt | `source.kind` of each message | platform and parent session | `requests[].source` |

How h-guard adjusts a decision a harness cannot carry out:

| Decision | When the harness cannot | Recorded as |
|---|---|---|
| `ask` | becomes `policy.when_ask_unsupported` (default `deny`) | `ask_unsupported` |
| `deny` on tool output | if the output cannot be replaced, becomes `warn` saying the content has already reached the model | `output_not_replaced` |
| `deny` on a prompt | if the prompt cannot be held back (Hermes Agent outside messaging platforms), becomes `warn` saying the prompt has already reached the model | `prompt_not_blocked` |
| `warn` | counted in the health log | `warn_undelivered` |

A tool's side effects cannot be undone; withholding or replacing its output
only changes what the model sees. Prompts and tool outputs that h-guard blocks
may still remain in the harness's own local history.

## Failure behavior

h-guard never answers `allow`; a failure never produces a pass that the local
rules would not have given.

| Situation | Action | Prompt and tool output |
|---|---|---|
| Configuration or rules invalid | asks | passes, recorded in the health log |
| Input too large, or time running out | asks (a deny already reached stays) | passes (a deny already reached stays), recorded |
| Judge on but unavailable (no consent, error, timeout) | local matches ask; otherwise `policy.on_unavailable` | local rules only |
| h-guard itself cannot run | Claude Code wrapper asks; Codex follows its own hook-failure handling; opencode blocks; pi, oh-my-pi, DeepSeek Harness and Hermes Agent ask (Hermes: blocks when it would approve without asking) | the extension passes and tells you (DeepSeek Harness, Hermes Agent: in its log) |

`h-guard status` summarizes degradations of the last 7 days from the health
log.

## Other agent harnesses

Any agent harness that can run a command per event and read its output can use
the [generic contract](protocols.md#generic-harness-contract-v1). Harnesses that
deliver events only to in-process extensions can use the
[extension protocol](protocols.md#extension-protocol-v1), which needs an adapter
for that harness compiled into h-guard. The harnesses above are supported out
of the box.
