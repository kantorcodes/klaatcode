import assert from 'node:assert/strict';
import test from 'node:test';
import { resolve } from 'node:path';
import {
  buildGuardPayload,
  resolveKlaatCommandCwd,
  decisionFromGuardResponse,
  extractKlaatCommand,
  parseGuardJson,
} from './hol-guard-before-tool.mjs';

test('extracts run_command command from Klaat tool_args', () => {
  assert.equal(extractKlaatCommand({
    event: 'before_tool',
    tool_name: 'run_command',
    tool_args: JSON.stringify({ command: 'git status --short' }),
  }), 'git status --short');
});

test('ignores unrelated hook events defensively', () => {
  assert.equal(extractKlaatCommand({ event: 'after_tool', tool_name: 'run_command', tool_args: '{}' }), null);
});

test('fails closed on malformed run_command input', () => {
  assert.throws(() => extractKlaatCommand({
    event: 'before_tool',
    tool_name: 'run_command',
    tool_args: '{',
  }));
});

test('builds complete PreToolUse command envelope', () => {
  assert.deepEqual(
    buildGuardPayload({ session_id: 's1', project_root: '/repo' }, 'pwd'),
    {
      hook_event_name: 'PreToolUse',
      tool_name: 'Bash',
      tool_input: { command: 'pwd' },
      session_id: 's1',
      cwd: '/repo',
    },
  );
});

test('allows authoritative native allow and policy warning decisions', () => {
  assert.equal(decisionFromGuardResponse({
    policy_action: 'allow',
    reason_code: 'native_exact_safe_command',
    hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'allow' },
  }).allow, true);
  assert.equal(decisionFromGuardResponse({
    policy_action: 'warn',
    reason_code: 'native_policy_warning',
    hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'allow' },
  }).allow, true);
});

test('rejects absent, malformed, and mismatched event envelopes', () => {
  for (const hookSpecificOutput of [
    { permissionDecision: 'allow' },
    { hookEventName: 'PostToolUse', permissionDecision: 'allow' },
    null,
    [],
  ]) {
    assert.equal(decisionFromGuardResponse({
      policy_action: 'allow',
      reason_code: 'native_policy_allow',
      hookSpecificOutput,
    }).allow, false);
  }
});

test('fails closed on unavailable and non-authoritative warn decisions', () => {
  for (const reason_code of [
    'native_pre_tool_unavailable',
    'native_policy_not_ready',
    'native_hook_worker_unavailable',
    'harness_not_managed',
    'future_unknown_warning',
  ]) {
    assert.equal(decisionFromGuardResponse({
      policy_action: 'warn',
      reason_code,
      reason: 'Guard did not complete an authoritative review.',
      hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'allow' },
    }).allow, false, reason_code);
  }
});

test('blocks review, block, malformed, and missing-reason responses', () => {
  for (const response of [
    { policy_action: 'review', reason_code: 'native_command_review_required', hookSpecificOutput: { permissionDecision: 'deny' } },
    { policy_action: 'block', reason_code: 'native_destructive_command', hookSpecificOutput: { permissionDecision: 'deny' } },
    { policy_action: 'allow', hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'allow' } },
    {},
  ]) {
    assert.equal(decisionFromGuardResponse(response).allow, false);
  }
});

test('accepts one complete verdict, but never extracts an allow from mixed stdout', () => {
  const allowed = '{"policy_action":"allow","reason_code":"native_policy_allow","hookSpecificOutput":{"permissionDecision":"allow"}}';
  const denied = '{"policy_action":"block","reason_code":"policy_block","hookSpecificOutput":{"permissionDecision":"deny"}}';
  assert.equal(parseGuardJson(`  \n${allowed}\n  `)?.policy_action, 'allow');
  for (const output of [
    `diagnostic\n${allowed}`,
    `${allowed}\ndiagnostic`,
    `${denied}\n${allowed}`,
    `${allowed}\n${denied}`,
    `${allowed}\n${allowed}`,
  ]) {
    assert.equal(parseGuardJson(output), null);
  }
});

test('rejects repeated authoritative Guard keys, including escaped duplicates', () => {
  const contradictory = [
    '{"policy_action":"block","policy_action":"allow","reason_code":"native_policy_allow","hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"}}',
    '{"policy_action":"allow","reason_code":"native_policy_allow","hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecision":"allow"}}',
    '{"policy_action":"allow","reason_code":"native_policy_allow","hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"},"metadata":{"note":"deny","note":"allow"}}',
    '{"policy_\\u0061ction":"block","policy_action":"allow","reason_code":"native_policy_allow","hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"}}',
  ];
  for (const output of contradictory) {
    assert.equal(parseGuardJson(output), null);
    assert.equal(decisionFromGuardResponse(parseGuardJson(output)).allow, false);
  }
  const valid = '{"notes":["repeated","repeated"],"policy_action":"allow","reason_code":"native_policy_allow","hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"}}';
  assert.deepEqual(parseGuardJson(valid), JSON.parse(valid));
});

test('explicit stop fields override otherwise authoritative allows', () => {
  const allowed = {
    policy_action: 'allow',
    reason_code: 'native_policy_allow',
    hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'allow' },
  };
  for (const stopped of [
    { continue: false },
    { continue: 'false' },
    { continue: 0 },
    { decision: 'deny' },
    { decision: 'review' },
    { decision: 'block' },
    { decision: 0 },
  ]) {
    assert.equal(decisionFromGuardResponse({ ...allowed, ...stopped }).allow, false);
  }
});


test('matches the effective run_command workdir for Guard inspection', () => {
  const root = '/repo';
  for (const [workdir, expected] of [
    ['nested', resolve(root, 'nested')],
    ['/tmp/other-worktree', '/tmp/other-worktree'],
    ['', root],
  ]) {
    const payload = {
      session_id: 's1',
      project_root: root,
      tool_args: JSON.stringify({ command: 'git status', workdir }),
    };
    assert.equal(resolveKlaatCommandCwd(payload), expected);
    assert.equal(buildGuardPayload(payload, 'git status').cwd, expected);
  }
});

test('denies an unknown execution directory instead of inspecting the wrong tree', () => {
  assert.throws(
    () => resolveKlaatCommandCwd({ tool_args: JSON.stringify({ command: 'git status' }) }),
    /project_root/,
  );
  assert.throws(
    () => resolveKlaatCommandCwd({
      project_root: '/repo',
      tool_args: JSON.stringify({ command: 'git status', workdir: ['elsewhere'] }),
    }),
    /workdir must be a string/,
  );
});

test('rejects relative project roots before choosing the Guard workspace', () => {
  for (const project_root of ['.', 'relative/repo', '']) {
    assert.throws(
      () => resolveKlaatCommandCwd({
        project_root,
        tool_args: JSON.stringify({ command: 'git status' }),
      }),
      /project_root must be an absolute path/,
    );
  }
});
