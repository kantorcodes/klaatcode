import assert from 'node:assert/strict';
import test from 'node:test';
import { delimiter, join, resolve } from 'node:path';
import { mkdtempSync, mkdirSync, realpathSync, rmSync, symlinkSync, writeFileSync, chmodSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import {
  buildGuardPayload,
  resolveKlaatCommandCwd,
  decisionFromGuardResponse,
  extractKlaatCommand,
  parseGuardJson,
  parseGuardBytes,
  trustedGuardPath,
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

test('denies missing event and pre-tool identity instead of bypassing Guard', () => {
  for (const payload of [
    null,
    [],
    {},
    { event: null, tool_name: 'run_command' },
    { event: '', tool_name: 'run_command' },
    { event: 'before_tool' },
    { event: 'before_tool', tool_name: null },
    { event: 'before_tool', tool_name: '' },
    { event: 'before_tool', tool_name: 42 },
  ]) {
    assert.throws(() => extractKlaatCommand(payload));
  }
  assert.equal(extractKlaatCommand({
    event: 'before_tool',
    tool_name: 'read_file',
    tool_args: '{}',
  }), null);
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

test('rejects invalid UTF-8 native Guard bytes even when decoding would look like allow', () => {
  const allowed = JSON.stringify({
    policy_action: 'allow',
    reason_code: 'native_policy_allow',
    hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'allow' },
    diagnostic: 'ok',
  });
  const valid = Buffer.from(allowed, 'utf8');
  assert.equal(parseGuardBytes(valid)?.policy_action, 'allow');

  const marker = allowed.lastIndexOf('ok');
  assert.ok(marker > 0);
  const invalid = Buffer.concat([
    Buffer.from(allowed.slice(0, marker), 'utf8'),
    Buffer.from([0xff]),
    Buffer.from(allowed.slice(marker + 2), 'utf8'),
  ]);
  // Default Node decoding would replace the invalid byte and still parse an allow.
  assert.equal(JSON.parse(invalid.toString('utf8')).policy_action, 'allow');
  assert.equal(parseGuardBytes(invalid), null);
  assert.equal(parseGuardBytes(allowed), null);
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

test('rejects falsey non-string workdirs before Guard inspects a different directory', () => {
  for (const workdir of [false, 0]) {
    const payload = {
      project_root: '/repo',
      tool_args: JSON.stringify({ command: 'git status', workdir }),
    };
    assert.throws(() => resolveKlaatCommandCwd(payload), /workdir must be a string/);
    assert.throws(() => buildGuardPayload(payload, 'git status'), /workdir must be a string/);
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


test('Guard executable search excludes relative and empty PATH entries', () => {
  const trustedA = resolve('/usr/local/bin');
  const trustedB = resolve('/opt/guard/bin');
  const original = ['.', trustedA, '', './node_modules/.bin', '../other', trustedB].join(delimiter);
  assert.equal(trustedGuardPath(original), [trustedA, trustedB].join(delimiter));
  assert.equal(trustedGuardPath('.'), '');
  assert.equal(trustedGuardPath(undefined), '');
});

test('rejects absolute project PATH entries and symlinks into the project', {
  skip: process.platform === 'win32',
}, () => {
  const root = mkdtempSync(join(tmpdir(), 'klaat-guard-absolute-path-'));
  const project = join(root, 'project');
  const projectBin = join(project, 'bin');
  const trustedBin = join(root, 'trusted-bin');
  const linkedProjectBin = join(root, 'linked-project-bin');
  mkdirSync(projectBin, { recursive: true });
  mkdirSync(trustedBin);
  symlinkSync(projectBin, linkedProjectBin, 'dir');
  try {
    const options = [projectBin, linkedProjectBin, trustedBin].join(delimiter);
    assert.equal(trustedGuardPath(options, [project]), realpathSync(trustedBin));
    assert.equal(trustedGuardPath(projectBin, [project]), '');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('rejects executable symlinks that point into a project', { skip: process.platform === 'win32' }, () => {
  const temp = mkdtempSync(join(tmpdir(), 'klaat-guard-executable-link-'));
  try {
    const project = join(temp, 'project');
    const externalBin = join(temp, 'external-bin');
    mkdirSync(project);
    mkdirSync(externalBin);
    const projectShim = join(project, 'hol-guard');
    writeFileSync(projectShim, '#!/bin/sh\nexit 0\n');
    chmodSync(projectShim, 0o755);
    // Directory is outside the repo, but its executable points into it.
    symlinkSync(projectShim, join(externalBin, 'hol-guard'));
    assert.equal(trustedGuardPath(externalBin, [project]), '');
    // An actual executable outside the project remains eligible.
    rmSync(join(externalBin, 'hol-guard'));
    writeFileSync(join(externalBin, 'hol-guard'), '#!/bin/sh\nexit 0\n');
    chmodSync(join(externalBin, 'hol-guard'), 0o755);
    assert.equal(trustedGuardPath(externalBin, [project]), realpathSync(externalBin));
  } finally {
    rmSync(temp, { recursive: true, force: true });
  }
});

test('project-local fake hol-guard cannot shadow a trusted PATH executable', {
  skip: process.platform === 'win32',
}, () => {
  const root = mkdtempSync(join(tmpdir(), 'klaat-hol-guard-path-'));
  const toolDirectory = join(root, 'tool-workspace');
  const trustedDirectory = join(root, 'trusted-bin');
  mkdirSync(toolDirectory);
  mkdirSync(trustedDirectory);
  try {
    const fakeAllow = JSON.stringify({
      policy_action: 'allow',
      reason_code: 'native_policy_allow',
      hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'allow' },
    });
    const realBlock = JSON.stringify({
      policy_action: 'block',
      reason_code: 'native_policy_block',
      hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'deny' },
    });
    const fakePath = join(toolDirectory, 'hol-guard');
    const trustedPath = join(trustedDirectory, 'hol-guard');
    writeFileSync(fakePath, "#!/bin/sh\nprintf '%s\\n' '" + fakeAllow + "'\n");
    writeFileSync(trustedPath, "#!/bin/sh\nprintf '%s\\n' '" + realBlock + "'\n");
    chmodSync(fakePath, 0o755);
    chmodSync(trustedPath, 0o755);
    const scriptPath = fileURLToPath(new URL('./hol-guard-before-tool.mjs', import.meta.url));
    const result = spawnSync(process.execPath, [scriptPath], {
      cwd: root,
      env: { ...process.env, PATH: ['.', trustedDirectory, process.env.PATH ?? ''].join(delimiter) },
      input: JSON.stringify({
        event: 'before_tool',
        tool_name: 'run_command',
        project_root: toolDirectory,
        tool_args: JSON.stringify({ command: 'git status' }),
      }),
      encoding: 'utf8',
      timeout: 10_000,
    });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(JSON.parse(result.stdout.trim()).decision, 'block');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('rejects project-controlled PATH link to trusted Guard directory', {
  skip: process.platform === 'win32',
}, () => {
  const root = mkdtempSync(join(tmpdir(), 'klaat-guard-link-spoof-'));
  const project = join(root, 'project');
  const trusted = join(root, 'trusted-bin');
  const outsideAlias = join(root, 'trusted-alias');
  const worktreeAlias = join(project, 'guard-bin-alias');
  mkdirSync(project);
  mkdirSync(trusted);
  symlinkSync(trusted, outsideAlias, 'dir');
  symlinkSync(trusted, worktreeAlias, 'dir');
  try {
    assert.equal(trustedGuardPath(worktreeAlias, [project]), '');
    const sanitized = trustedGuardPath([worktreeAlias, outsideAlias].join(delimiter), [project]);
    // The project can retarget its own link, while trusted aliases resolve to
    // fixed canonical directories before spawn.
    assert.equal(sanitized, realpathSync(trusted));
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
