# HOL Guard `before_tool` adapter packet

Status (updated October 28, 2026): HOL-authored adapter proposed for independent review in [Klaat Code PR #68](https://github.com/KlaatAI/klaatcode/pull/68). The PR is open, not merged or released. This document corrects the earlier pre-submission status; it does not claim third-party approval or adoption.

## Why this maps cleanly

Klaat Code sends a JSON object to `before_tool` hooks. For a `run_command` call, the relevant fields are:

- `event`: `before_tool`
- `project_root`: current project root
- `tool_name`: `run_command`
- `tool_args`: the raw JSON argument string passed to the tool

Klaat Code blocks a tool call when the hook exits with status `2` or writes a JSON object such as:

```json
{"decision":"block","reason":"..."}
```

HOL Guard already has native pre-tool authority for command decisions. The supported native request is a versioned `PreToolUse` envelope whose `tool_input.command` contains the command string. The Rust runtime owns the security decision. The adapter transports and renders that result rather than reimplementing Guard policy in Klaat Code.

## Proposed adapter behavior

The proposed PR branch contains the JavaScript adapter `scripts/hol-guard-before-tool.mjs` and a POSIX fail-closed launcher `scripts/hol-guard-before-tool.sh`. For `tool_name == "run_command"` it:

1. Parses `tool_args` as JSON.
2. Extracts the non-empty `command` string. Missing or malformed command input fails closed.
3. Constructs a Guard `PreToolUse` request with the current project as `cwd`.
4. Sends the complete request through `hol-guard hook --harness codex --json`, with the workspace when available, so Guard's native hook authority remains the decision owner.
5. Requires `hookSpecificOutput.hookEventName` to be `PreToolUse`, then allows an authoritative native `allow` decision or the explicit `native_policy_warning` allow-with-warning result. Missing or mismatched event binding fails closed.
6. Fails closed when native review is unavailable or not ready, including `native_pre_tool_unavailable`, `native_policy_not_ready`, worker/daemon availability failures, unmanaged-harness passthrough, unknown warning results, malformed output, timeout, missing Guard, review, reapproval, sandbox-required, or block.

The adapter does not use `hol-guard command explain` as enforcement authority. The `--json` response must be one complete JSON object on stdout; a diagnostic prefix, suffix, or multiple verdicts fails closed instead of letting the adapter extract a possibly misleading allow result.

## Validation completed

The exact owned branch was downloaded into an independent Linux sandbox and validated with Node 20 and Bun 1.4.2.

The following checks pass:

- `node --check scripts/hol-guard-before-tool.mjs`
- `node --test scripts/hol-guard-before-tool.test.mjs`, 7/7 focused tests
- `node --test scripts/hol-guard-before-tool-wrapper.test.mjs`, 4/4 isolated POSIX launcher tests (October 28; not upstream CI)
- `bun install --frozen-lockfile`
- `bun run typecheck`
- `bun run build`

The focused tests cover command extraction, unrelated hook pass-through, malformed `tool_args`, complete `PreToolUse` envelope construction, authoritative allow and policy-warning handling, unavailable native review, unknown warnings, review/block responses, and malformed/missing-reason responses.

## Real HOL Guard 3.4.2 availability test

A clean isolated Python environment installed the published `hol-guard==3.4.2` package successfully.

With no resident native policy authority initialized, `hol-guard hook --harness codex --json` returned `policy_action: warn`, `permissionDecision: allow`, and `reason_code: native_pre_tool_unavailable` for both a benign command and a destructive command. That response means Guard could not complete the native decision. It is not execution proof.

The first adapter version treated a generic `warn` plus `permissionDecision: allow` as sufficient and therefore would have allowed that unavailable state. The owned-fork adapter now rejects Guard availability and not-ready reason codes and rejects unknown warning results. Re-running the adapter against the same real 3.4.2 runtime now emits Klaat's block result for both test commands while Guard authority is unavailable.

This closes the unavailable-runtime fail-open defect seen in the initial test. The [PR description](https://github.com/KlaatAI/klaatcode/pull/68) additionally reports a later isolated HOL Guard 3.4.2 native-runtime test with benign allows and a destructive-command block. That later assertion is a contributor report, not an independent maintainer acceptance or a raw test log reproduced in this document.

## Independent review and real-runtime validation

The implementation has already been submitted for independent upstream review in PR #68. A reviewer should reproduce these cases with an isolated managed Guard runtime rather than relying only on contributor-reported results:

| Case | Expected result |
| --- | --- |
| `pwd` | Klaat Code command proceeds after authoritative Guard allow |
| `git status --short` | Klaat Code command proceeds after authoritative Guard allow |
| `rm -rf /` | Klaat Code command is blocked |
| `shred ~/.ssh/id_ed25519` | Klaat Code command is blocked |
| malformed `tool_args` | fail closed |
| Guard runtime unavailable | fail closed |

The denial test must verify that the target command was not executed. The PR description reports a sentinel test; the exact runtime transcript is not reproduced in this document.

An earlier isolated `hol-guard install codex` attempt did not establish authority because Guard rejected the sandbox interpreter as writable by another user. No real user installation was modified. The PR description reports a later successful managed-runtime test; that proof should be independently replayed before merge.

## Candidate hook configuration

This is an **unreleased, project-local proposal**, not a component shipped by Klaat Code or HOL Guard. Copy **both** `scripts/hol-guard-before-tool.sh` and `scripts/hol-guard-before-tool.mjs` from the reviewed PR branch into your project's `scripts/` directory. Do not assume these scripts are included in the npm package: Klaat's current `package.json` publishes only its built CLI, README, and license.

```json
{
  "before_tool": [
    {
      "matcher": "run_command",
      "command": "sh ./scripts/hol-guard-before-tool.sh",
      "timeout": 12
    }
  ]
}
```

Klaat's current hook runner treats exit status **2** or an explicit JSON block as denial, but ignores other failed shell exits and timeouts. The POSIX launcher therefore converts missing Node, missing adapter, and unexpected adapter failures to exit **2** rather than silently allowing the command. The host timeout is set above the adapter's 9-second Guard deadline so the adapter can return its own block verdict first.

**Limit:** This does not fix a missing `sh` interpreter, a missing *launcher itself*, or a host timeout before the launcher can report a verdict. Klaat currently fails open in those cases. A separate upstream hook-runner change to fail closed on every nonzero exit, start failure, and timeout would be needed before treating this as a general enforcement boundary. Do not represent the PR as a shipped security guarantee.

The current upstream README example points at `./scripts/guard-shell.sh`, but that helper is not present in the repository. This PR supplies an opt-in adapter, not a replacement for Klaat's global hook-failure semantics.

## Acceptance and release gates

Before merge or release:

- revalidate the current Klaat Code upstream head, hook payload, block semantics, contribution guidance, and queue ownership;
- revalidate HOL Guard's current native hook entry point;
- keep Klaat Code typecheck/build plus focused adapter tests green;
- prove one authoritative allow path and one authoritative deny path with the real Guard runtime, including target command non-execution on deny;
- get independent Klaat maintainer review and check the current PR branch against the upstream contribution rules.

Until independent upstream approval/merge and a separate usable release, PR #68 remains a HOL-authored proposal. It is not an externally authored PR, a tagged extension release, or independently measured nonauthor adoption.
