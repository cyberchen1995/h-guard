# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub: open the repository's
**Security** tab and choose **Report a vulnerability**. Do not open a public
issue or pull request for a suspected vulnerability.

Include the h-guard version (`h-guard version`), the harness and its version,
the relevant configuration, and a minimal input that reproduces the problem. If
the input contains real credentials or personal data, replace them with
made-up values of the same shape.

## Supported versions

Only the latest minor release receives security fixes. Before v1.0 that means
the most recent `0.x` release.

## What counts as a vulnerability

h-guard is a guardrail for agent harnesses, so these are in scope:

- **Detection bypass.** An operation or text that a rule, a tier or a built-in
  detector is documented to catch, and that passes without a verdict. Bypasses
  of the limits listed under "Known limitations" in the README are not
  vulnerabilities, but are welcome as ordinary issues.
- **Raw content leaking.** A credential, a personal-data value or the text of a
  blocked prompt or command appearing in a log, a health record, an error
  message, CLI output or a verdict's reason text. Reasons are meant to contain
  only a category, a hit count and line numbers.
- **Sending without consent.** Any request to a judge backend, or any other
  network call, made for a backend, endpoint or scope the user has not
  consented to.
- **Consent bypass.** Consent recorded, kept or reused when the backend
  identity (name, type, endpoint) or the scope has changed, or an agent
  granting consent on the user's behalf.
- **A verdict that is weaker than it should be.** Any path where a failure
  (backend error, timeout, unparsable input) produces a pass that a healthy run
  would not have produced.

Out of scope: findings that need write access to the user's own configuration
or home directory, and false positives or false negatives of the optional
model-based judgments (report those as issues; they are calibrated, not
guaranteed).

## What to expect

We aim to acknowledge a report within a few days and to agree on a fix and a
disclosure date with you before anything is made public. Reporters are credited
in the release notes unless they prefer otherwise.
