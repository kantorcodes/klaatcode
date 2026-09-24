# HOL Guard `before_tool` adapter packet

Status: owned-fork implementation and tests prepared. This is not an upstream integration or a release artifact.

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

## Prepared adapter behavior

The owned fork now contains `scripts/hol-guard-before-tool.mjs`. For `tool_name == "run_command"` it:

1. Parses `tool_args` as JSON.
2. Extracts the non-empty `command` string. Missing or malformed command input fails closed.
3. Constructs a Guard `PreToolUse` request with the current project as `cwd`.
4. Sends the complete request through `hol-guard hook --harness codex --json`, with the workspace when available, so Guard's native hook authority remains the decision owner.
5. Allows only a native-rendered `allow` or `warn` result whose hook permission decision is `allow`.
6. Maps review, reapproval, sandbox-required, block, malformed output, unmanaged-harness passthrough, timeout, missing Guard, or any other non-authoritative state to Klaat Code's JSON block contract.

The adapter does not use `hol-guard command explain` as enforcement authority.

## Local preparation proof

`node --check scripts/hol-guard-before-tool.mjs` passed before the owned-fork write.

`node --test scripts/hol-guard-before-tool.test.mjs` passed six focused unit tests covering:

- command extraction;
- unrelated hook pass-through;
- malformed `tool_args` fail-closed behavior;
- complete `PreToolUse` envelope construction;
- native allow/warn handling;
- review/block/unmanaged/malformed response rejection.

A mocked `hol-guard` executable also proved the adapter's process boundary for allow, deny, malformed Klaat input, and unavailable Guard behavior.

These are preparation checks only. They are not a substitute for real HOL Guard runtime proof.

## Minimum real-runtime validation cases

The implementation is not ready for upstream submission until these cases are exercised against the real Guard runtime:

| Case | Expected result |
| --- | --- |
| `pwd` | Klaat Code command proceeds |
| `git status --short` | Klaat Code command proceeds |
| `rm -rf /` | Klaat Code command is blocked |
| `shred ~/.ssh/id_ed25519` | Klaat Code command is blocked |
| malformed `tool_args` | fail closed |
| Guard runtime unavailable | fail closed |

The deny-path test must prove that the target command is not executed.

## Candidate hook configuration

The adapter should remain project-local until there is a stable shipped integration surface:

```json
{
  "before_tool": [
    {
      "matcher": "run_command",
      "command": "node ./scripts/hol-guard-before-tool.mjs"
    }
  ]
}
```

The current upstream README example points at `./scripts/guard-shell.sh`, but that helper is not present in the repository. This owned-fork candidate supplies the missing executable behavior without changing Klaat's hook semantics.

## Upstream gate

Before any upstream PR:

- revalidate the current Klaat Code upstream head, hook payload, block semantics, contribution guidance, and queue ownership;
- revalidate HOL Guard's current native hook entry point;
- run Klaat Code typecheck/build plus the focused adapter tests;
- prove one allow path and one deny path with the real Guard runtime, including target command non-execution on deny;
- confirm the contribution still fits current Distribution WIP and maintainer-conversion gates.

Until those gates pass, this remains owned-fork preparation and carries no strict outcome value.
