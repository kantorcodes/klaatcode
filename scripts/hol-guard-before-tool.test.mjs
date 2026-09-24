import assert from 'node:assert/strict';
import test from 'node:test';
import {
  buildGuardPayload,
  decisionFromGuardResponse,
  extractKlaatCommand,
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

test('allows only native allow or warn decisions rendered as allow', () => {
  assert.equal(decisionFromGuardResponse({
    policy_action: 'allow',
    reason_code: 'native_pre_tool_allow',
    hookSpecificOutput: { permissionDecision: 'allow' },
  }).allow, true);
  assert.equal(decisionFromGuardResponse({
    policy_action: 'warn',
    reason_code: 'native_policy_warning',
    hookSpecificOutput: { permissionDecision: 'allow' },
  }).allow, true);
});

test('blocks review, block, malformed, and unmanaged passthrough responses', () => {
  for (const response of [
    { policy_action: 'review', hookSpecificOutput: { permissionDecision: 'deny' } },
    { policy_action: 'block', hookSpecificOutput: { permissionDecision: 'deny' } },
    { policy_action: 'allow', reason_code: 'harness_not_managed', hookSpecificOutput: { permissionDecision: 'allow' } },
    {},
  ]) {
    assert.equal(decisionFromGuardResponse(response).allow, false);
  }
});
