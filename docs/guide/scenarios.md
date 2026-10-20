# Protection scenarios

h-guard is built around three things an agent can do to you without meaning
to: throw away your work, publish something you did not ask for, and leak a
secret. This guide shows, for each one, what h-guard recognizes, what it tells
you, what happens next, and how to check that it is working. All of it works
with the model off; with the model on, the same rules also catch the forms
their patterns miss and stop asking when you requested the operation.

Native permission prompts work by tool or by command prefix. Once a prefix
such as `git` or `npm` is allowed, or the harness runs without prompts, they
no longer tell `git reset --hard` from `git status`, or `npm publish` from
`npm test`. Codex hooks cannot ask at all. h-guard looks at the operation
itself, and explains why it stopped it.

Every demo below is `h-guard check` with `--no-judge`, which runs the same
checks as the hook with the local rules only. The same cases run through the
real hook entry points in `TestScenarioKeepWork`,
`TestScenarioNoUnauthorizedPublish` and `TestScenarioCredentials`
(`internal/app/scenario_test.go`).

## 1. Keep your work

**Recognizes.** With the model off, these forms ask:

- `git reset --hard`, `git clean`, `git checkout .` / `git checkout -- .`,
  `git stash clear` (`destructive_git`);
- a force push without a lease (`git push --force`, `-f`, `+branch`), and
  `git filter-branch` / `git filter-repo` (`branch_ops`);
- recursive deletes under `~`, under `..`, or of `.git`, with `rm` or
  PowerShell's `Remove-Item -Recurse` (`recursive_delete`);
- deleting `/` or the home directory is denied outright (`catastrophic`).

Everyday forms run: `git reset --soft`, `git push --force-with-lease`,
`rm -rf build`, `git stash`. With the model on, the rest of these rules (any
recursive delete, `git restore`, a rebase, `git branch -D`) asks too when the
agent chose it on its own.

**Explains.**

```console
$ h-guard check 'git reset --hard origin/main' --no-judge --cwd ~/proj
decision: ask
reason: This operation is dangerous and needs your confirmation: Git operation that discards uncommitted changes or untracked files [rule]. Operation: `git reset --hard origin/main` in /home/me/proj. Impact: Uncommitted changes or untracked files in this working tree would be lost; git cannot bring them back. Safer way: Save them first: commit them, or git stash push --all (which also keeps ignored files that git clean -x removes); before git stash drop or clear, note their commit ids (git stash list --format=%H) so they can be restored. Then retry.
hint: Ask the user to run it themselves.
finding: destructive_git (local)
$ h-guard check 'git push --force-with-lease' --no-judge --cwd ~/proj
decision: pass
finding: branch_ops (local)
finding: publish (local)
```

**Acts.** Claude Code shows the reason in its permission prompt: approve it if
you meant it. Codex cannot ask, so h-guard blocks and gives an id; run
`h-guard allow <id>` in your own terminal and the agent's unchanged retry runs
once.

## 2. Stop unasked publishing

**Recognizes.** With the model off, publishing something others will see and
that is hard to take back asks: `npm`, `pnpm` and `yarn publish`,
`cargo publish`, `twine upload`, `uv publish`, `gem push`, `docker push`,
`podman push`, `gh release create`/`upload`/`delete`, PowerShell's
`Publish-Module` and `nuget push` (`publish`). Dry runs and read-only
commands (`npm publish --dry-run`, `gh release view`, `npm pack`) run.

A plain `git push`, pull requests and mutating API calls need the model: they
are routine when you asked for them, so h-guard asks only when the judge finds
that you did not. With the model off they are logged, and `h-guard status`
says so.

**Explains.**

```console
$ h-guard check 'npm publish' --no-judge --cwd ~/proj
decision: ask
reason: This operation is dangerous and needs your confirmation: Publishes to or changes state on a remote (push, PR/MR, release, registry, mutating API call) [rule]. Operation: `npm publish` in /home/me/proj. Impact: Others can see the result (a pushed branch, a pull request, a release or a package), and it is hard to take back. Safer way: Check the target and the content first (git log @{u}.., the package version), and publish only when you mean to.
hint: Ask the user to run it themselves.
finding: publish (local)
$ h-guard check 'npm publish --dry-run' --no-judge --cwd ~/proj
decision: pass
finding: publish (local)
```

**Acts.** As in scenario 1: a permission prompt in Claude Code, a block with a
one-time approval on Codex.

## 3. Keep credentials in

**Recognizes.**

- Reading files that usually hold secrets (`.env`, `*.pem`, `*.key`,
  `id_rsa*`, `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.netrc` and similar) asks,
  through the harness's file tools and through common shell reads: `cat`,
  `head`, `grep`, `sed`, `base64`, `< file` and PowerShell's `Get-Content`
  name the file they read (`sensitive_read`). A wildcard (`cat .env*`) counts
  for the files it matches in the working directory; one that matches more
  than 1024 files asks, since they are not all checked. Example files (`.env.example`)
  and public keys (`*.pub`) are read normally.
- Credentials and private keys in your prompts are blocked, and with
  `outbound.tier: 2` also in the output of tools that read files.

**Explains.**

```console
$ h-guard check 'cat .env' --no-judge --cwd ~/proj
decision: ask
reason: This file operation touches .env, which a path rule covers, so it needs your confirmation: Reads a file that usually holds secrets (.env, private keys, cloud or SSH credentials) [rule]. Operation: `cat .env` in /home/me/proj. Impact: Its contents (keys, tokens, passwords) would enter the agent's context and may be sent to the model provider. Safer way: Let the agent use the value without reading the file (an environment variable), or read it yourself.
hint: Ask the user to run it themselves.
finding: sensitive_read (local)
$ h-guard check 'cat .env.example' --no-judge --cwd ~/proj
decision: pass
```

**Acts.** A read asks (Claude Code) or blocks with a one-time approval
(Codex). A blocked prompt is not sent to the model.

**Not isolation.** Shell reads are recognized by command, not sandboxed.
`python -c`, a script, or a file name that reaches the command through
`xargs`, a variable or a remote host is not caught before it runs; only the
output scan at `outbound.tier: 2` or 3 can catch what such a read prints.

## Check that it is working

```sh
h-guard selftest   # runs the installed entries the way the harness does
h-guard status     # what interrupts, what only logs, and what is not covered
```

The protection summary lists each rule with its condition, for example
`destructive_git (ask, only its high-impact forms while the judge is off)`,
and a `not covered:` line for each gap above.
