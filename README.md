# h-guard

[简体中文](README.zh-CN.md)

**Harnesses:** Claude Code · Codex · opencode · pi · oh-my-pi · DeepSeek Harness ·
OpenClaw · Hermes Agent, and any other agent harness through the
[generic JSON contract](docs/guide/protocols.md#generic-harness-contract-v1).<br>
**Intercepts:** catastrophic commands and fork bombs, recursive deletes,
destructive git and branch operations, publishing, bypassed checks, encoded
execution, tampering with the guard and reads of secret files, plus credentials,
private keys and (opt-in) personal data in prompts and tool output, using local
rules and a judge model for the cases that depend on what you asked for
([details](#what-it-checks)).

h-guard is a safety guardrail for agent harnesses. It checks what an agent is
about to do (shell commands and file operations) and what passes through it
(your prompts and tool output), and denies, asks for confirmation or warns
before something destructive runs or a secret leaks.

<p align="center"><img src=".github/assets/how-it-works.svg" alt="How h-guard works" width="720"></p>

**Use it with a judge model.** Local rules handle the clear-cut cases only. For
the common dangerous operations (recursive deletes, destructive git, publishing
and the like), a model decides whether you asked for the operation and how much
it would destroy, so h-guard interrupts only when it matters. Run `h-guard init`
and choose `claude-haiku` (recommended: fast and calibrated) or `gemma4-local`
(runs on your machine and sends nothing out, but is slower).

> **The model is off by default.** When the model is off, h-guard runs its
> local rules only, sends nothing anywhere and needs no API key. These still
> work with the model off:
>
> - catastrophic commands (deleting `/` or the home directory, overwriting a
>   block device, formatting a file system) and fork bombs are denied;
> - changes to h-guard's own configuration or the harness's hook settings ask
>   for confirmation (guard self-protection);
> - running encoded content (for example `base64 -d | sh`) asks;
> - reading files that usually hold secrets (`.env`, private keys, `~/.ssh`,
>   cloud credentials) asks, with the harness's file tools and with common
>   shell reads (`cat`, `grep`, `head`, `< file`);
> - the high-impact forms of losing work and publishing ask: `git reset
>   --hard`, `git clean`, `git checkout .`, a force push without lease,
>   `git filter-repo`, recursive deletes under `~`, `..` or of `.git`,
>   `npm`/`cargo` publish, `twine upload`, `docker push`, `gh release create`;
> - credentials and private keys in your prompts are blocked.
>
> Everything else those rules match is **not judged** with the model off:
> without the model h-guard cannot tell whether you asked for the operation or
> how much it would destroy, so other recursive deletes, `git push`, a rebase
> and `verify_bypass` are only logged. `guard_tampering` still asks on every
> local match, but nothing looks for tampering that its patterns miss. Run
> `h-guard init` to choose a backend and turn the model on.

## Install

**Homebrew** (macOS):

```sh
brew install cyberchen1995/tap/h-guard
```

**GitHub Releases.** Each release has archives for macOS, Linux and Windows
(amd64 and arm64), a `checksums.txt` and its Sigstore bundle
`checksums.txt.sigstore.json`. Verify the checksums file with
[cosign](https://docs.sigstore.dev/cosign/system_config/installation/), then the
archive against it:

```sh
VERSION=0.1.0
BASE=https://github.com/cyberchen1995/h-guard/releases/download/v$VERSION
ARCHIVE=h-guard_${VERSION}_linux_amd64.tar.gz      # or darwin_arm64, windows_amd64.zip, ...
curl -L -O "$BASE/$ARCHIVE" -O "$BASE/checksums.txt" -O "$BASE/checksums.txt.sigstore.json"
cosign verify-blob checksums.txt \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp '^https://github\.com/cyberchen1995/h-guard/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
sha256sum --check --ignore-missing checksums.txt    # macOS: shasum -a 256 --check --ignore-missing checksums.txt
tar -xzf "$ARCHIVE" h-guard                        # Windows archives are zip: unzip or Expand-Archive
```

Put `h-guard` somewhere on your `PATH`.

**From source** (Go toolchain as in `go.mod`):

```sh
go install github.com/cyberchen1995/h-guard/cmd/h-guard@latest
```

`h-guard version` prints the installed version.

## Quick start

Connect h-guard to your harness. Without `--write`, `install` only shows what
it would change; with `--write` it makes a backup of each file it changes, then
writes.

```sh
h-guard install claudecode            # preview
h-guard install claudecode --write    # Claude Code: installs the h-guard plugin
h-guard install codex --write         # Codex: registers hooks in ~/.codex/hooks.json
h-guard install opencode --write      # opencode 1.x: writes a plugin to ~/.config/opencode/plugins
h-guard install pi --write            # pi: writes an extension to ~/.pi/agent/extensions
h-guard install omp --write           # oh-my-pi: writes an extension to ~/.omp/agent/extensions
h-guard install dsh --write           # DeepSeek Harness: mounts a plugin in ~/.dsh/cordis.patch.yml
h-guard install openclaw --write      # OpenClaw: loads a plugin from ~/.openclaw/openclaw.json
h-guard install hermes --write        # Hermes Agent: writes a plugin to ~/.hermes/plugins and enables it
```

For Codex, open Codex and run `/hooks` to review and trust the h-guard hooks.
Codex does not run new or changed hooks until you trust them.

Check that it protects you. `selftest` runs the entries the harness will run,
with a simulated `false && rm -rf /` (never executed) and a prompt with a made-up API
key, and checks that both are blocked:

```sh
h-guard selftest  # end-to-end check of the installed entries; nothing is executed or sent
h-guard status    # starts with a protection summary
```

`status` starts with what you are actually protected by. For each harness it
shows three separate layers: the configuration is written, the harness has
really run the hook (Codex shows "unverified" until it runs one, since h-guard
cannot read Codex's trust state), and the last self-test passed. Then it lists
which rules interrupt, which only log, which are off, and what is not covered:

```console
protection:
  claudecode: config written: yes | hook running: yes, last 2 min ago (PreToolUse, prompt.submit, tool.result) | self-test: passed 3 min ago
  codex: config written: yes | hook running: unverified (Codex has not run the hooks since they were installed; trust them with /hooks in Codex) | self-test: passed 3 min ago
  interrupts: branch_ops (ask, only its high-impact forms while the judge is off), catastrophic (deny), destructive_git (ask, only its high-impact forms while the judge is off), …
  matched but not interrupting, and not recorded (log.decisions is off) (judge off; h-guard init turns it on): verify_bypass
  prompts and tool output: credentials deny, private_key deny (scans prompts)
  not covered: secret files read in ways h-guard does not recognize as reading (python -c, a script, …) …
```

Turn on the model:

```sh
h-guard init      # pick a backend, see what it receives, consent, turn the judge on
h-guard status    # entry points, judge, consent, rules not in effect, recent degradations
```

Try a command without a harness. `check` runs the same checks as the hook;
`--no-judge` runs the local rules only:

```console
$ h-guard check 'rm -rf /' --no-judge
decision: deny
reason: Blocked: Catastrophic operation: deleting the root or home directory, overwriting a block device, or formatting a file system [rule]. Operation: `rm -rf /`. Impact: It would destroy data that cannot be recovered: a whole file system, the home directory or a device. Safer way: If this is really intended, the user should run it themselves after checking the target.
hint: Ask the user to run it themselves.
finding: catastrophic (local)
finding: recursive_delete (local)
signals: {"action":{"judge":"off"}}
$ h-guard check 'git push origin main' --no-judge
decision: pass
finding: publish (local)
signals: {"action":{"judge":"off","judge_disabled_hits":["publish"]}}
```

The second command matches `publish`, but with the model off only that rule's
high-impact forms interrupt (publishing a package or a release), not a plain
push. With the model on, the same command asks for confirmation unless one of
your recent prompts asked for the push (`--request 'push this to origin'`
simulates that).

## When it interrupts

Every interruption says four things: what the agent was about to do and where
(the command and its working directory, or the file), why h-guard stopped it
(the rule, and with the model on whether you asked for it and the blast
radius), what it would cause, and how to continue. For example, with the model
on:

```text
h-guard: The agent chose a dangerous operation on its own and needs your confirmation:
Git operation that discards uncommitted changes or untracked files [rule+judge 0.97].
Blast radius 2.0/3. The user's recent instructions do not explicitly ask for it (0.03).
Operation: `git reset --hard HEAD~1` in /home/me/proj. Impact: Uncommitted changes or
untracked files in this working tree would be lost; git cannot bring them back.
Safer way: Save them first: commit them, or git stash push --all (which also keeps
ignored files that git clean -x removes); before git stash drop or clear, note their
commit ids (git stash list --format=%H) so they can be restored. Then retry.
```

In Claude Code this is the text of the permission prompt: approve it if you
meant it. Codex cannot ask, so h-guard blocks instead, and for anything except
guard self-protection the reason ends with a one-time approval:

```text
To run exactly this once, ask the user to run `h-guard allow 3f9a2c1d0e` in their own
terminal (the approval is valid for 10 minutes and covers only this command in this
directory), then retry it unchanged; or ask the user to run it themselves.
```

`h-guard allow` lists what was stopped in the last hour; `h-guard allow <id>`
shows the operation and asks you to confirm in your terminal. The approval is
bound to the harness, the working directory and the exact tool input, covers
shell commands only (not file reads or edits), is used up by the first retry and expires after 10 minutes (`--ttl`, at most
1h). There is no "allow everything from now on": you do not have to turn the
guard off to keep working. The agent cannot approve for itself: `allow` needs
an interactive terminal, and running it through a harness asks.

## What it checks

**Actions** are the commands and file operations an agent is about to run. The
built-in rules:

| Rule | What it catches | Verdict | Needs the model |
|---|---|---|---|
| `catastrophic` | deleting `/` or the home directory, overwriting a block device, formatting a file system | deny | no (locked) |
| `fork_bomb` | fork bombs | deny | no (locked) |
| `guard_tampering` | changes to h-guard's configuration, consent, cache or the harness's hook settings | ask | no (locked); the model can add hits |
| `obfuscated_exec` | encoded content handed to an interpreter | ask | no |
| `sensitive_read` | reading `.env`, `*.pem`, `*.key`, `id_rsa*`, `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.netrc` and similar, through the harness's file tools or common shell reads (`cat`, `grep`, `head`, `< file`) | ask | no |
| `recursive_delete` | deleting files or directories recursively | ask | yes, except under `~`, `..` or of `.git` |
| `destructive_git` | git operations that discard uncommitted changes or untracked files | ask | yes, except `reset --hard`, `clean`, `checkout .`, `stash clear` |
| `branch_ops` | rewriting history, force-deleting a branch, changing an upstream | ask | yes, except a force push without lease and `filter-branch`/`filter-repo` |
| `publish` | push, pull/merge requests, releases, package publishing, mutating API calls | ask | yes, except publishing a package, an image or a release |
| `verify_bypass` | bypassing git hooks, checks or signing | ask | yes |

With the model on, a rule that needs the model interrupts only when the agent
chose the operation on its own: the judge is asked whether one of your recent
prompts explicitly requested it and how much it would destroy. Locked rules and
`obfuscated_exec` cannot be released by a request.

**Outbound** checks scan your prompts and tool output:

| Category | Detects | Default |
|---|---|---|
| `credentials` | API tokens with known prefixes, bearer tokens, secret assignments, AWS access key IDs, passwords in URLs (a high-entropy detector is available but off) | deny |
| `private_key` | PEM private key blocks | deny |
| `pii` | email addresses, phone numbers (mainland China and international), Chinese resident ID numbers, US SSNs, public IP addresses | off |

A blocked prompt or tool output is reported by category, count and line
numbers; the matched text is never put in the reason.

**Tiers** decide what is checked (locked rules apply at every tier):

| `action.tier` | Checks | | `outbound.tier` | Scans |
|---|---|---|---|---|
| 1 | shell commands | | 1 (default) | prompts |
| 2 (default) | + file reads, writes, deletes, renames | | 2 | + file contents read by tools |
| 3 | + other tool calls (no built-in rules yet) | | 3 | + all tool output |

Verdicts only get stricter: `deny > ask > warn > pass`. h-guard never answers
`allow`, so it never overrides the harness's own permission prompts, and a
failing backend never turns into a pass the local rules would not have given.

## Judge backends and consent

The judge is a model that answers fixed questions about a command. Built-in
backends:

| Backend | Type | Sends to | API key |
|---|---|---|---|
| `claude-haiku` (recommended) | `anthropic` | `https://api.anthropic.com` | `ANTHROPIC_API_KEY` |
| `claude-sonnet` (recommended) | `anthropic` | `https://api.anthropic.com` | `ANTHROPIC_API_KEY` |
| `gemma4-local` (recommended) | `openai` | `http://localhost:11434/v1` (Ollama, model `gemma4:12b-mlx`) | none |
| `jev` | `typesafe` | `https://api.typesafe.ai` | `TYPESAFE_API_KEY` |

Each ships with a calibration profile, so no calibration is needed. `jev` is
the backend named in the default configuration (`judge.backend: jev`); `init`
offers all four. Put API keys in the environment the harness starts h-guard
with, or in a `.env` file in h-guard's configuration directory (`h-guard
status` shows where that is). The configuration only names the variable.

With the model on, the backend receives, for every shell command the agent runs
(except ones already denied):

- the command, its working directory, the harness and the tool name;
- up to 3 of your most recent prompts in the session (`policy.request_window`).

When outbound judging is also on (the default once the model is on), prompts
and tool output that local rules do not block and that are at least 200
characters long are sent in up to 4 chunks of up to 4000 characters. What the
judge finds there is shown as a warning and never blocks, so nothing is sent
for prompts and tool output on a harness that cannot show warnings (Codex).
Credentials, private keys and personal data that h-guard recognizes are masked
before sending; anything it does not recognize is sent as is. Set
`outbound.judge: false` to stop sending prompts and tool output.

**Nothing is sent before you consent.** `h-guard init` and `h-guard backend
enable <name>` show what will be sent and where, and ask in your terminal.
Consent is tied to the backend's name, type and destination (scheme, host and
port; for an `exec` backend, the program and its arguments); changing any of
them withdraws it. Local backends need consent too. `h-guard backend disable
<name>` withdraws consent; `h-guard backend list` shows the state of each
backend. An agent cannot give consent for you: running `init` or `backend
enable` through a harness asks for confirmation (`backend disable` only
withdraws consent and passes).

## Configuration

```sh
h-guard config init       # writes a commented config.yaml (never overwrites)
h-guard config show       # the merged configuration
h-guard config validate   # checks the configuration and runs your rules' examples
```

The configuration lives in `config.yaml` in h-guard's configuration directory
(`$XDG_CONFIG_HOME/h-guard` when set, otherwise `~/Library/Application
Support/h-guard` on macOS, `~/.config/h-guard` on Linux and `%AppData%\h-guard`
on Windows). Its first line points editors with YAML language support at
[`schema/config.schema.json`](schema/config.schema.json) for completion and
checking. Your own rules go in the `rules/` directory next to it.

```yaml
version: 1
judge: {enabled: true, backend: claude-haiku}
action: {tier: 2}
outbound:
  categories:
    pii: {enabled: true, action: warn}
rules:
  publish: {enabled: false}
```

See the [configuration guide](docs/guide/configuration.md) for every field and
the [rule pack guide](docs/guide/rules.md) for writing rules.

## Supported versions

| Harness | Supported | Verified with |
|---|---|---|
| Claude Code | 2.1.290 or later (needs mods for tool output and prompts) | 2.1.296 |
| Codex | the version verified, or later | 0.162.1 |
| opencode | 1.x (opencode 2.x has a different plugin API and is not supported) | 1.19.3 (smoke test) |
| pi | the version tested, or later | 1.3.0 (smoke test) |
| oh-my-pi | the version tested, or later | 18.11.3 (smoke test) |
| DeepSeek Harness | the version tested, or later | 0.2.1-rc.2 (smoke test) |
| OpenClaw | the version tested, or later | 2026.10.4 (smoke test) |
| Hermes Agent | the version tested, or later | 2026.9.24 (plugin hooks driven directly) |

The opencode, pi, oh-my-pi, DeepSeek Harness and OpenClaw extensions were written against
each harness's source code, are tested in CI against simulated harness APIs,
and were smoke-tested in the real harnesses with a simulated model server
(blocking, asking, replacing tool output, blocking prompts). There are no
recorded sessions of them yet. The Hermes Agent plugin was written against
Hermes's source, is tested in CI against a simulated plugin context, and was
loaded by Hermes's own plugin manager with its hooks driven directly; it has
not yet been run with a model or a messaging gateway.

`install` and `status` say when a harness version has not been verified; they
do not refuse it. Other agent harnesses can call h-guard through the
[generic contract](docs/guide/protocols.md#generic-harness-contract-v1). How
each harness is connected and what it can and cannot do is in the
[harness guide](docs/guide/harnesses.md).

Platforms: macOS and Linux. Windows builds are published and the Windows code
paths are tested in CI, but h-guard has not been verified with a real harness
on Windows.

## Known limitations

- **Codex cannot ask.** Codex does not support asking for confirmation from a
  hook, so every `ask` becomes `deny` there (`policy.when_ask_unsupported`).
- **opencode cannot ask either.** opencode's plugin API has no way to ask the
  user, so every `ask` becomes `deny` there as well; warnings are shown as TUI
  toasts and are not visible in `opencode run`.
- **DeepSeek Harness cannot show warnings.** Warnings go to its log only, and a
  blocked prompt is dropped without a message in the conversation.
- **OpenClaw cannot show warnings in the conversation.** Warnings go to the
  Gateway log, or to a chat when you turn on the plugin's channel
  notifications. Runs outside the Gateway (`openclaw agent exec`) are not
  checked, and `openclaw.json` must be plain JSON for `install` to edit it.
- **oh-my-pi's `eval` tool asks.** h-guard cannot read Python or JavaScript
  code, so every `eval` call needs your confirmation.
- **Hermes Agent cannot block prompts outside messaging platforms.** A prompt
  typed into the CLI, TUI or Desktop that h-guard would block has already
  reached the model; h-guard adds a warning to the turn instead
  (`prompt_not_blocked`). Under `--yolo` or `approvals.mode: off`, h-guard's
  confirmations become denials, and Hermes cannot show you warnings except
  through the optional channel notifications.
- **Hermes Agent's `execute_code` asks.** The script can start processes and
  change files directly, so every call needs your confirmation.
- **Unknown tools ask on pi, oh-my-pi, DeepSeek Harness, OpenClaw and Hermes Agent.** Tools that are not on
  h-guard's list of the harness's own tools (for example ones added by an
  extension) need your confirmation until you list them in
  `harnesses.<name>.read_only_tools`.
- **MCP tools are blocked on opencode.** opencode cannot ask, so MCP tools are
  blocked until you list them in `harnesses.opencode.read_only_tools`; custom
  tools and plugin tools pass.
- **Codex hooks must be trusted.** After `install codex --write` you have to
  trust the hooks with `/hooks` in Codex; until then they do not run. h-guard
  cannot read Codex's trust state: `h-guard status` shows the hooks as
  unverified until Codex runs one.
- **One-time approvals are as strong as the agent's file access.** An approval
  is a record in h-guard's cache, signed with a key in its configuration
  directory (`grant.key`, created the first time an operation is stopped with
  an approval offer); so is the stopped operation that `h-guard allow` shows
  you. The agent runs
  as your user: one that reads the key and writes a signed record with a tool
  `guard_tampering` does not recognize could approve its own operation. The
  key keeps a write to the cache alone from being enough; it is not a boundary
  against an agent that sets out to defeat h-guard. The same goes for the
  terminal check in `h-guard allow`: an agent can run a copy of the binary
  under another name inside a pseudo-terminal (`script -c …`) and answer the
  prompt itself. The instruction cache that
  the judge reads as your recent prompts has the same exposure. An approval
  binds the session, the exact tool input and the real working directory (path and file identity), not what the
  paths named in the command point to when it runs, nor the files and settings
  it reads (a `git push origin` goes wherever `.git/config` says `origin` is
  at that moment). It also binds only the working directory Codex reports to
  the hook: if Codex runs a command in a directory it leaves out of the hook
  input, or the directory is created only after the hook ran, the approval
  cannot tell. Check the paths and targets before you approve.
- **Who wrote a prompt is inferred.** Claude Code labels automated messages
  (scheduled tasks, sub-agent reports); Codex does not, so h-guard recognizes
  its automated messages by their known formats. An automated message it does
  not recognize counts as yours, and with the model on can count as your
  request for an operation.
- **Windows is not verified on real hardware.** Path handling, the PowerShell
  hook wrapper and Codex's command forms on Windows are tested only in CI and
  by cross-compilation.
- **Shell reads are recognized, not isolated.** `sensitive_read` checks the
  harness's file tools and the files that common shell reads name (`cat`,
  `grep`, `head`, `base64`, `< file`, PowerShell's `Get-Content`). Other ways
  of reading a file, such as `python -c`, a script, or names passed through
  `xargs` or to a remote host, are not caught before they run. At
  `outbound.tier: 2` (default 1) the output of shell commands recognized as
  reading files is scanned for credentials and keys after the read.
- **Personal-data detection has false positives.** Email addresses and public
  IP addresses are common in development work, which is why `pii` is off by
  default. Use a category's `ignore` list or turn off single rules.
- **Blocked content may stay in the harness's own records.** A blocked prompt
  can remain in the harness's local history, and Codex writes the original tool
  output to its transcript even when h-guard replaces it for the model. h-guard
  cannot remove these.
- **Effects already happened.** Checking tool output happens after the tool ran;
  replacing the output only changes what the model sees.
- **The model's answers are calibrated, not guaranteed.** Judgments can miss
  or interrupt more than needed; `h-guard status` shows whether the backend's
  thresholds are calibrated.

## Uninstall

```sh
h-guard install claudecode --remove --write
h-guard install codex --remove --write
h-guard install opencode --remove --write   # likewise pi, omp, dsh, openclaw, hermes
```

`--remove` deletes only h-guard's own entries and keeps everything else in the
harness configuration. Then remove the binary (`brew uninstall h-guard`, or
delete the file) and, if you like, h-guard's configuration directory.

## Documentation

- [Configuration](docs/guide/configuration.md): every field, merge order,
  backends and calibration profiles.
- [Protection scenarios](docs/guide/scenarios.md): keeping your work, stopping
  unasked publishing and keeping credentials in, with a demo for each.
- [Rule packs](docs/guide/rules.md): writing action and outbound rules.
- [Protocols](docs/guide/protocols.md): the judge exec protocol, the generic
  harness contract and the extension protocol.
- [Harnesses](docs/guide/harnesses.md): how each harness is connected, and
  what each can do.
- [Changelog](CHANGELOG.md), [security policy](SECURITY.md),
  [contributing](CONTRIBUTING.md).

## License

Apache License 2.0; see [LICENSE](LICENSE) and [NOTICE](NOTICE).
