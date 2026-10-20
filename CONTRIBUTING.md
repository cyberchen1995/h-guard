# Contributing

Thanks for helping. h-guard is a Go module (`github.com/cyberchen1995/h-guard`);
the toolchain version is in `go.mod`.

## Build and test

```sh
go build ./...
go vet ./...
GOOS=windows go vet ./...
gofmt -l $(git ls-files '*.go')      # must print nothing
go test ./...                        # the full suite
go test -short ./...                 # skips the slow tests (e.g. the separate-module build)
go test -race ./...
```

The golden test replays the action corpus against the built-in rules and pins
the corpus bytes by hash. Run it in required mode so a missing file fails
instead of skipping:

```sh
HG_GOLDEN_REQUIRED=1 go test -count=1 -run '^TestGolden$' ./internal/check/action/
```

Fuzz targets live next to the code they cover (`pkg/detect/...`,
`pkg/harness/codex`, `internal/check/outbound`). Run one for a short while:

```sh
go test -run '^$' -fuzz '^FuzzFind$' -fuzztime 30s ./pkg/detect/pii/
```

The opencode, pi/oh-my-pi, DeepSeek Harness and OpenClaw extensions have JavaScript tests
under `extensions/*/tests`. They run against simulated harness APIs and a
freshly built h-guard; `go test ./extensions/` runs them when `node` is on
`PATH` (CI runners have it), and skips them otherwise or with `-short`.
The Hermes Agent plugin has Python tests (standard library `unittest`) under
`extensions/hermes/tests`, run the same way when `python3` or `python` (3.9 or
later) is on `PATH`.

The Claude Code plugin has its own tests; they need the `claude` CLI and are not
part of CI:

```sh
claude plugin test extensions/claudecode
```

To check every commit of a branch the way CI does (commit message, gofmt, vet,
Windows vet; tests run only on the branch head):

```sh
.github/scripts/each-commit.sh <base> <head>
```

Tests must not touch the real network, a real model API, or real harness
configuration (`~/.claude`, `~/.codex`). Use a temporary `HOME` and
`XDG_CONFIG_HOME` when running the binary.

## Rules and corpora

- Built-in rules live in `rules/` (see `schema/` for the file formats). A rule
  needs examples that run in `config validate`.
- The labeled corpora under `corpus/` are written by the maintainers. We do not
  accept samples copied from public datasets. Labels are decided by the
  maintainers; new samples are held out of threshold sweeps until they are
  folded in. If you find a missed or wrongly blocked case, open an issue with
  the (made-up) input and the expected verdict instead of a corpus patch.
- Verdicts only get stricter: `deny > ask > warn > pass`, never `allow`. Changes
  that loosen a policy or a threshold need a stated reason and calibration data.
- Do not publish new `pkg/` API without discussing it first. Before v1.0 `pkg/`
  may change incompatibly; such changes are listed in `CHANGELOG.md`.

## Commits and pull requests

- Use conventional commits: `feat:`, `fix:`, `docs:`, `test:`, `perf:`,
  `chore:`. Keep each commit buildable, since CI vets every commit in a pull
  request; the full test suite runs on the branch head.
- Pull requests are squash-merged. The commit that lands on `main` takes its
  message from the pull request title and description, so write them the way
  you would write a commit message; CI checks them the same way.
- Do not put review ids, internal planning terms or private paths in commit
  messages, code or docs. A repository test rejects them.
- Do not commit real credentials or personal data. Fixtures use made-up values.
- Contributions are licensed under the Apache License 2.0, as section 5 of the
  license describes.

## Comments and language

Existing code comments are in Simplified Chinese. New comments may be in
Chinese or English; keep them consistent within a file. Identifiers and CLI
output are English. User-facing documentation is English.

## Dependencies

h-guard keeps its dependency list short because it reads commands and keys.
A new dependency needs a justification in the pull request: what it does that
the standard library does not, its maintenance state, and its transitive
footprint. Judge backends deliberately use plain `net/http` rather than vendor
SDKs (see [ADR 0002](docs/adr/0002-judge-backends-use-plain-http.md)).
