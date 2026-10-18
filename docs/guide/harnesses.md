# Harnesses

h-guard connects to Claude Code and Codex with `h-guard install`, and to any
other agent harness through the [generic contract](protocols.md#generic-harness-contract-v1).
This guide describes how each connection works, what each harness can do with
h-guard's decisions, and what happens when it cannot.

## Installing and removing

```sh
h-guard install claudecode|codex [--write] [--remove] [--timeout <seconds>] [--shell posix|powershell]
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

## What each harness can do

| Event | Claude Code | Codex | Generic |
|---|---|---|---|
| Action: deny | yes | yes | caller applies it |
| Action: ask | yes (permission prompt) | no, becomes `deny` | caller applies it |
| Action: warn | yes (shown to you) | no | caller applies it |
| Prompt: block | yes | yes | caller applies it |
| Prompt: warn | yes (added as context for Claude) | no | caller applies it |
| Tool output: replace | yes (result withheld) | yes (result replaced) | caller applies it |
| Tool output: warn | yes (shown to you) | no | caller applies it |
| Prompt origin | labeled by Claude Code | inferred from known formats | `requests[].source` |

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
| h-guard itself cannot run | Claude Code wrapper asks; Codex follows its own hook-failure handling | Claude Code mod passes and tells you |

`h-guard status` summarizes degradations of the last 7 days from the health
log.

## Other agent harnesses

Any agent harness that can run a command per event and read its output can use
the [generic contract](protocols.md#generic-harness-contract-v1). Harnesses that
deliver events only to in-process extensions can use the
[extension protocol](protocols.md#extension-protocol-v1), which needs an adapter
for that harness compiled into h-guard. Only Claude Code and Codex are
supported out of the box.
