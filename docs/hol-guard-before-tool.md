# HOL Guard `before_tool` adapter packet

Status: owned-fork preparation only. This is not an upstream integration or a release artifact.

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

HOL Guard already has native pre-tool authority for command decisions. The supported native request is a versioned `PreToolUse` envelope whose `payload.tool_input.command` contains the command string. The Rust runtime owns the security decision. An adapter must transport and render that result, not reimplement Guard policy from Klaat Code.

## Required adapter behavior

For `tool_name == "run_command"`:

1. Parse `tool_args` as JSON.
2. Extract the `command` string. If it is absent or malformed, fail closed for this matched hook rather than guessing.
3. Construct a Guard `PreToolUse` request using the current project as `cwd`.
4. Send the request through HOL Guard's native hook authority.
5. If Guard returns a deny/block/review/reapproval/sandbox-required floor that prevents execution, translate it to Klaat Code's block contract.
6. If Guard returns an allow result, exit successfully without a block response.
7. If Guard cannot produce an authoritative decision, fail closed. Do not silently allow a command because Guard is unavailable.

Do not use `hol-guard command explain` as the enforcement authority. It is useful for stateless inspection and test assertions, but the live hook decision must remain native-authoritative.

## Minimum validation cases

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

The adapter should be project-local until there is a stable shipped integration surface:

```json
{
  "before_tool": [
    {
      "matcher": "run_command",
      "command": "./scripts/hol-guard-before-tool"
    }
  ]
}
```

The current README example points at `./scripts/guard-shell.sh`, but that helper is not present in the repository. A real contribution should either ship the referenced helper or replace the example with an existing supported command.

## Upstream gate

Before any upstream PR:

- revalidate the current Klaat Code hook payload and block semantics;
- revalidate HOL Guard's current native hook entry point;
- implement the smallest portable adapter with no duplicated policy logic;
- run Klaat Code typecheck/build plus focused adapter tests;
- prove one allow path and one deny path with the real Guard runtime;
- confirm the contribution still fits current maintainer guidance and Distribution WIP limits.

Until those gates pass, this packet is preparation only and carries no strict outcome value.
