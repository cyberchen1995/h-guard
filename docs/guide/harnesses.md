# Harnesses

h-guard connects to Claude Code, Codex, opencode, pi, oh-my-pi, DeepSeek
Harness and OpenClaw with `h-guard install`, and to any other agent harness through the
[generic contract](protocols.md#generic-harness-contract-v1).
For what h-guard intercepts, see
[What it checks](../../README.md#what-it-checks).
This guide describes how each connection works, what each harness can do with
h-guard's decisions, and what happens when it cannot.

## Installing and removing

```sh
h-guard install claudecode|codex|opencode|pi|omp|dsh|openclaw [--write] [--remove] [--timeout <seconds>] [--shell posix|powershell]
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

## OpenClaw

Supported: OpenClaw (`openclaw`), written against and smoke-tested with
2026.10.4 (the npm release, on Linux, through the Gateway with a simulated
model server); no recorded sessions yet.

`install openclaw --write`:

1. writes h-guard's native plugin (`openclaw.plugin.json`, `package.json` and
   `index.mjs`; plain JavaScript without dependencies) to `extensions/openclaw`
   in h-guard's configuration directory, with the h-guard path and timeout in
   it;
2. in `openclaw.json`, adds that directory to `plugins.load.paths` and sets
   `plugins.entries.h-guard`: `enabled: true`,
   `hooks.allowConversationAccess: true` (OpenClaw only gives prompts to a
   plugin that has it) and `hooks.timeouts` for `before_tool_call`,
   `before_agent_run` and `after_tool_call` (the timeout plus 5 seconds; the
   tool result middleware runs on the `after_tool_call` budget; OpenClaw allows
   at most 600 seconds, so `--timeout` can be at most 595). When
   `plugins.allow` is not empty, `h-guard` is added to it. The rest of the file
   is kept, and so are other keys of the entry, such as the notification
   settings below.

`openclaw.json` is `$OPENCLAW_CONFIG_PATH`, or `openclaw.json` in
`$OPENCLAW_STATE_DIR` (default `~/.openclaw`; `$OPENCLAW_HOME` replaces `~`;
as in OpenClaw, a blank `OPENCLAW_HOME` or the literal `undefined` or `null`
counts as unset).
Restart the Gateway afterwards (`openclaw gateway restart`). Removing deletes
the load path and the entry (and `h-guard` from `plugins.allow` when other
plugins remain listed there), then the plugin.

OpenClaw reads `openclaw.json` as JSON5 and can split it with `$include`, but
it writes plain JSON itself. `install` only edits plain JSON: when the file has
comments, trailing commas, unquoted keys or `$include`, it changes nothing and
prints the settings to add yourself. It also refuses while `plugins.deny`
lists `h-guard`. A named profile (`--profile`, `OPENCLAW_PROFILE`) has its own
state directory; set `OPENCLAW_STATE_DIR` or `OPENCLAW_CONFIG_PATH` to install
there.

The plugin runs in the Gateway process and starts h-guard through OpenClaw's
`runtime.system.runCommandWithTimeout`, without a shell. Because it was not
installed with `openclaw plugins install`, the Gateway logs at startup that it
"can't verify where this plugin came from"; the plugin loads anyway.

`h-guard status` lists OpenClaw in its protection summary with the
configuration layer only: as for the other extension harnesses, whether the
plugin really runs is not tracked, and `h-guard selftest` does not cover it.
OpenClaw can ask, so `h-guard allow` one-time approvals are not offered there;
you approve in OpenClaw's own plugin approval instead.

| Plugin hook | What h-guard does |
|---|---|
| `before_tool_call` | checks the actions (`exec` commands; `read`, `grep`, `view_image`; `write`, `edit`; the files in an `apply_patch`; text written to a running `process`); `deny` blocks the call and the model reads h-guard's reason; `ask` becomes a plugin approval |
| tool result middleware | scans the output before the model sees it; `deny` replaces it with h-guard's reason |
| `before_agent_run` | scans the prompt of each run; `deny` blocks the run, and the reply is OpenClaw's "Your message could not be sent: …" with h-guard's reason |

OpenClaw differences:

- **Ask is a plugin approval.** It offers "allow once" and "deny" only
  (OpenClaw does not remember "allow always" for a plugin hook), and its
  description holds h-guard's reason and a summary of the command or files
  in which the credentials h-guard recognizes are masked; it never holds the
  raw arguments (approvals can appear in chats). When h-guard cannot run, the
  description names only the tool. OpenClaw
  delivers it like its other plugin approvals: to the chat the run came from
  (buttons or `/approve`) and to connected approval clients, and it waits up
  to 2 minutes. A run with nobody to answer blocks the call, which is the safe
  direction: the smoke test saw this for `openclaw agent` run from a script,
  and OpenClaw rejects approvals for unattended runs such as scheduled ones. To send
  approvals to a fixed chat, see `approvals.plugin` below.
- **No warnings in the conversation.** A plugin cannot show you a message, so
  `warn` is recorded as `warn_undelivered` and goes to the Gateway log, and the
  judge's outbound findings are not requested, as on Codex. Channel
  notifications (below) can send warnings to a chat.
- **Prompt origin.** A run triggered by a user (OpenClaw's `user` and `manual`
  triggers) whose message came from an external user counts as yours.
  Scheduled, heartbeat, webhook and memory runs, messages handed over from
  another session (sub-agent results, `sessions_send`) or by the system, and
  every run in a sub-agent session count as automated.
- **Shell.** `exec` runs commands with `$SHELL` on macOS and Linux, where
  h-guard checks them as POSIX, in the sandbox as well. On Windows the Gateway
  uses PowerShell and the sandbox a POSIX shell, and which of the two a command
  gets is only settled when it runs (`auto` picks the sandbox when the session
  has one, a session that requires a sandbox overrides a configured
  `gateway`, and elevated mode moves sandbox commands to the Gateway), so
  h-guard checks it under both shells and the stricter result wins; only a
  call that asks for `host: "gateway"` or `elevated` itself is checked as
  PowerShell alone. A command
  for a paired node runs on another device whose shell and files h-guard
  cannot see: it is checked as POSIX and always asks. Where a command runs is
  taken from the call (`host`, `node`), else from the session's `/exec`
  setting, else from the agent's or the global `tools.exec.host`; when the
  plugin cannot read these settings, the command asks. A scheduled job's own
  exec target is not visible to the plugin.
- **Working directory.** Relative paths are resolved against the workspace
  OpenClaw reports for the run (or the agent's configured workspace), or the
  command's `workdir`. A session that works somewhere else (a configured
  `cwd`, a project worktree) can have its relative paths resolved against the
  wrong directory.
- **Code Mode.** A Code Mode `exec` cell is JavaScript; it is not checked
  itself, but each tool call it makes is. Its output is scanned as file
  content.
- **Tools with read-only actions.** `browser` drives a real, possibly
  signed-in browser: only observing it passes (`status`, `profiles`, `tabs`,
  `snapshot`, `console`, `requests`, `errors`, `text`, and `screenshot` and
  `pdf`, whose `path` is checked as a file write); opening, navigating,
  clicking and typing (`act`), uploads, downloads, dialogs and the other
  actions ask. `message` passes reading and sending, replying, reacting and
  polls, with local attachments (`media`, `path`, `filePath`, `attachments`,
  `file:` URLs) checked as file reads because they leave for the channel;
  editing, deleting and pinning messages and managing groups, channels,
  members, roles, profiles and events ask. `sessions` asks to reset or delete
  a session, delete a group or hand a session to another owner, and
  `transcripts` asks to start recording a meeting. An action h-guard does not
  know asks.
- **Processes.** Text written or pasted into a running process (`process`
  with `write` or `paste`) is checked as a POSIX command and always asks;
  submitting pending input (`submit`), closing a process's input (`write`
  with `eof`), sending keys, killing or removing a process asks.

### Channel notifications

h-guard can tell a chat when it blocks something. This is off by default and
lives in OpenClaw's configuration, under the plugin's entry:

```json
{
  "plugins": {
    "entries": {
      "h-guard": {
        "config": {
          "notify": {
            "on": ["deny", "warn"],
            "targets": [
              {"channel": "telegram", "to": "123456789"},
              {"channel": "slack", "to": "channel:C0123456", "account": "work", "thread": "1712345678.000100"}
            ]
          }
        }
      }
    }
  }
}
```

| Field | Meaning |
|---|---|
| `on` | Which decisions to report: `deny` (blocked tool calls, withheld tool output, blocked prompts), `warn`, `ask`. Default `["deny", "warn"]`. |
| `targets` | Where to send: `channel` and `to` as for `openclaw message send --channel … --target …`, optional `account` and `thread` (`--thread-id`). |
| `command` | How to run the OpenClaw command line. Default: the Gateway's own `node` and `openclaw.mjs`, otherwise `openclaw` from `PATH`. |

For each decision and target the plugin runs
`openclaw message send --channel <channel> --target <to> --message <text>` in
the background, with a 60-second limit. Sending never delays or changes the
decision; failures go to the Gateway log, and when 20 messages are pending the
next ones are dropped. The text is h-guard's reason (credentials h-guard
recognizes are masked) with the tool name and the agent, for example
`h-guard blocked a tool call (exec) (agent main): Blocked: …`; it never
contains the command, the tool's arguments or the prompt. OpenClaw checks these
settings against the plugin's schema and reloads the plugin when they change;
`install` keeps them. The smoke test checked that the Gateway runs the command
with these arguments; delivery to a real channel has not been tested.

Approvals already reach the chat a run came from. For runs that did not come
from a chat, OpenClaw can forward plugin approvals to fixed targets
(`approvals.plugin`, separate from `approvals.exec`):

```json
{
  "approvals": {
    "plugin": {
      "enabled": true,
      "mode": "targets",
      "targets": [{"channel": "telegram", "to": "123456789"}]
    }
  }
}
```

`install` does not write either setting: it cannot know your chats.

**Not covered:**

- Runs outside the Gateway: in the smoke test `openclaw agent exec` loaded the
  plugin only for discovery, so its tool calls, tool output and prompts were
  not checked.
- The Codex and Copilot agent runtimes: OpenClaw does not promise
  `before_agent_run` there, and the plugin's tool result middleware is
  registered for OpenClaw's own runtime only. Tool calls those runtimes relay
  to `before_tool_call` have not been tested.
- A parameter rewrite returned by another plugin's `before_tool_call`: every
  plugin sees the original parameters, so h-guard checks the call as the model
  made it.
- Tools of other plugins and of channels ask (`tool_unknown`, see
  [Tools h-guard does not know](#tools-h-guard-does-not-know)); MCP tools
  (`<server>__<tool>`) pass.
- Gateway's `/tools/invoke` HTTP endpoint goes through `before_tool_call` but
  not through the tool result middleware.

When h-guard cannot run, the plugin asks before a tool call (blocked when
nobody can answer) and lets tool output and prompts through with a line in the
Gateway log.

## Tools h-guard does not know

For pi, oh-my-pi, DeepSeek Harness and OpenClaw, h-guard knows every tool the harness ships:

- tools that run commands or change files are checked as actions;
- tools that only read, search, plan or coordinate pass;
- MCP tools (`mcp__…`, on OpenClaw `<server>__<tool>`) pass, as on the other harnesses;
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
  openclaw: {read_only_tools: [my_lookup, docs_*]}
```

The list only applies to tools h-guard does not know: a shell or file tool
named there is still checked. For opencode, h-guard cannot tell the
harness's own tools from MCP and plugin tools, so tools it does not know pass
there.

## What each harness can do

| Event | Claude Code | Codex | opencode | pi, oh-my-pi | DeepSeek Harness | OpenClaw | Generic |
|---|---|---|---|---|---|---|---|
| Action: deny | yes | yes | yes | yes | yes | yes | caller applies it |
| Action: ask | yes (permission prompt) | no, becomes `deny` | no, becomes `deny` | yes (dialog) | yes (approval service) | yes (plugin approval) | caller applies it |
| Action: warn | yes (shown to you) | no | yes (toast) | yes (notification) | no | no (channel notification if configured) | caller applies it |
| Prompt: block | yes | yes | yes | yes | yes | yes | caller applies it |
| Prompt: warn | yes (added as context for Claude) | no | yes (toast) | yes (notification) | no | no (channel notification if configured) | caller applies it |
| Tool output: replace | yes (result withheld) | yes (result replaced) | yes | yes | yes (result replaced) | yes (result replaced) | caller applies it |
| Tool output: warn | yes (shown to you) | no | yes (toast) | yes (notification) | no | no (channel notification if configured) | caller applies it |
| Prompt origin | labeled by Claude Code | inferred from known formats | sub-agent sessions | `source` of the prompt | `source.kind` of each message | the run's trigger and input provenance | `requests[].source` |

How h-guard adjusts a decision a harness cannot carry out:

| Decision | When the harness cannot | Recorded as |
|---|---|---|
| `ask` | becomes `policy.when_ask_unsupported` (default `deny`) | `ask_unsupported` |
| `deny` on tool output | if the output cannot be replaced, becomes `warn` saying the content has already reached the model | `output_not_replaced` |
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
| h-guard itself cannot run | Claude Code wrapper asks; Codex follows its own hook-failure handling; opencode blocks; pi, oh-my-pi, DeepSeek Harness and OpenClaw ask | the extension passes and tells you (DeepSeek Harness and OpenClaw: in their logs) |

`h-guard status` summarizes degradations of the last 7 days from the health
log.

## Other agent harnesses

Any agent harness that can run a command per event and read its output can use
the [generic contract](protocols.md#generic-harness-contract-v1). Harnesses that
deliver events only to in-process extensions can use the
[extension protocol](protocols.md#extension-protocol-v1), which needs an adapter
for that harness compiled into h-guard. The harnesses above are supported out
of the box.
