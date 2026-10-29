#!/usr/bin/env node
import { spawnSync } from 'node:child_process';
import { delimiter, isAbsolute, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import process from 'node:process';

const MAX_STDIN_BYTES = 1_000_000;
const GUARD_TIMEOUT_MS = 9_000;

// The hook switches cwd to the tool directory. Relative PATH entries would
// then resolve there and could select a different, project-local hol-guard.
// Only absolute search directories may be used for Guard's executable lookup.
export function trustedGuardPath(pathValue) {
  if (typeof pathValue !== 'string') return '';
  return pathValue.split(delimiter)
    .filter((entry) => entry && isAbsolute(entry))
    .join(delimiter);
}

const NON_AUTHORITATIVE_REASON_CODES = new Set([
  'native_hook_disabled',
  'native_shadow_diagnostic_disabled',
  'native_policy_not_ready',
  'native_hook_event_unavailable',
  'native_pre_tool_unavailable',
  'native_post_tool_unavailable',
  'native_overloaded',
  'native_hook_worker_unavailable',
  'native_hook_worker_unavailable_before_compatibility',
  'native_hook_worker_unsupported',
  'native_hook_worker_exception',
  'native_hook_compatibility_disabled',
  'native_hook_edge_invalid_response',
  'native_hook_edge_unavailable',
  'python_hook_oracle_unavailable',
  'python_oracle_exception',
  'watch_recording_only',
  'daemon_hook_queue_capacity',
  'daemon_hook_deadline_exhausted',
  'daemon_hook_process_deadline_exhausted',
  'daemon_hook_process_not_ready',
  'daemon_hook_process_failed',
  'daemon_hook_process_invalid_request',
  'daemon_hook_process_guard_home_mismatch',
  'daemon_worker_exception',
  'harness_not_managed',
  'native_degraded_emergency_safe',
]);

function block(reason) {
  const message = typeof reason === 'string' && reason.trim()
    ? reason.trim()
    : 'HOL Guard did not return an authoritative allow decision.';
  process.stdout.write(`${JSON.stringify({ decision: 'block', reason: message })}\n`);
}

export function extractKlaatCommand(payload) {
  if (!payload || typeof payload !== 'object') {
    throw new Error('invalid Klaat hook payload');
  }
  if (payload.event !== 'before_tool' || payload.tool_name !== 'run_command') {
    return null;
  }
  if (typeof payload.tool_args !== 'string') {
    throw new Error('run_command tool_args must be a JSON string');
  }
  let args;
  try {
    args = JSON.parse(payload.tool_args);
  } catch {
    throw new Error('run_command tool_args is not valid JSON');
  }
  if (!args || typeof args !== 'object' || typeof args.command !== 'string' || !args.command.trim()) {
    throw new Error('run_command command is missing');
  }
  return args.command;
}

export function resolveKlaatCommandCwd(payload) {
  const root = payload?.project_root;
  if (typeof root !== 'string' || !root.trim() || !isAbsolute(root)) {
    throw new Error('run_command project_root must be an absolute path');
  }
  let workdir;
  if (typeof payload.tool_args === 'string') {
    const parsed = JSON.parse(payload.tool_args);
    workdir = parsed?.workdir;
  }
  if (!workdir) return root;
  if (typeof workdir !== 'string') {
    throw new Error('run_command workdir must be a string');
  }
  // Match Klaat's runCommand/safeResolve logic, including tilde paths.
  if (workdir.startsWith('/') || workdir.startsWith('~')) {
    const expanded = workdir.replace(/^~/, process.env.HOME ?? '~');
    if (!isAbsolute(expanded)) {
      throw new Error('run_command effective workdir must be an absolute path');
    }
    return expanded;
  }
  return resolve(root, workdir);
}

export function buildGuardPayload(payload, command) {
  const guardPayload = {
    hook_event_name: 'PreToolUse',
    tool_name: 'Bash',
    tool_input: { command },
    // Guard must inspect from the same directory as run_command executes.
    cwd: resolveKlaatCommandCwd(payload),
  };
  if (typeof payload.session_id === 'string' && payload.session_id) {
    guardPayload.session_id = payload.session_id;
  }
  return guardPayload;
}

// Standard JSON.parse keeps the last repeated field. Refuse duplicate keys
// before an allow-shaped response can erase an earlier deny or review.
function containsDuplicateGuardKeys(raw) {
  const frames = [];
  for (let i = 0; i < raw.length;) {
    const char = raw[i];
    if (char === '"') {
      const start = i++;
      while (i < raw.length) {
        if (raw[i] === "\\") {
          i += 2;
          continue;
        }
        if (raw[i++] === '"') break;
      }
      const frame = frames[frames.length - 1];
      if (frame?.isObject && frame.expectKey) {
        const key = JSON.parse(raw.slice(start, i));
        if (frame.keys.has(key)) return true;
        frame.keys.add(key);
        frame.expectKey = false;
      }
      continue;
    }
    if (char === '{') frames.push({ isObject: true, expectKey: true, keys: new Set() });
    else if (char === '[') frames.push({ isObject: false });
    else if (char === '}' || char === ']') frames.pop();
    else if (char === ',' && frames[frames.length - 1]?.isObject) {
      frames[frames.length - 1].expectKey = true;
    }
    i++;
  }
  return false;
}

export function parseGuardJson(stdout) {
  const text = typeof stdout === 'string' ? stdout.trim() : '';
  if (!text) return null;
  try {
    if (containsDuplicateGuardKeys(text)) return null;
    const parsed = JSON.parse(text);
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : null;
  } catch {
    // A diagnostic line or second verdict cannot authorize execution.
    return null;
  }
}

export function decisionFromGuardResponse(response) {
  if (!response || typeof response !== 'object' || Array.isArray(response)) {
    return { allow: false, reason: 'HOL Guard returned an invalid response.' };
  }
  const hookSpecific = response.hookSpecificOutput;
  // Only a concrete PreToolUse verdict is an authorization for this hook.
  // A missing event name must fail closed just like a mismatched event.
  if (!hookSpecific || typeof hookSpecific !== 'object' ||
      Array.isArray(hookSpecific) || hookSpecific.hookEventName !== 'PreToolUse') {
    return { allow: false, reason: 'HOL Guard returned no matching PreToolUse event.' };
  }
  const permissionDecision = hookSpecific.permissionDecision;
  if (('continue' in response && response.continue !== true) ||
      ('decision' in response && response.decision !== 'allow')) {
    return { allow: false, reason: 'HOL Guard refused tool continuation.' };
  }
  const policyAction = response.policy_action;
  const reasonCode = typeof response.reason_code === 'string'
    ? response.reason_code.trim()
    : '';
  const reason =
    (typeof response.reason === 'string' && response.reason) ||
    (hookSpecific && typeof hookSpecific === 'object' &&
      typeof hookSpecific.permissionDecisionReason === 'string' &&
      hookSpecific.permissionDecisionReason) ||
    (reasonCode && `HOL Guard blocked this command (${reasonCode}).`) ||
    'HOL Guard did not return an authoritative allow decision.';

  if (permissionDecision !== 'allow' || !reasonCode) {
    return { allow: false, reason };
  }

  if (NON_AUTHORITATIVE_REASON_CODES.has(reasonCode)) {
    return { allow: false, reason };
  }

  // A superficially allow-shaped response with a destructive/review reason
  // must not bypass Guard's native classifier. Unknown reasons fail closed.
  const provenAllowReason = reasonCode.startsWith('native_exact_safe_') ||
    reasonCode === 'native_exact_introspection_command' ||
    reasonCode === 'native_policy_allow' || reasonCode === 'native_custom_mcp_tool_allow';
  if (policyAction === 'allow' && provenAllowReason) {
    return { allow: true, reason: '' };
  }

  if (policyAction === 'warn' && reasonCode === 'native_policy_warning') {
    return { allow: true, reason: '' };
  }

  return { allow: false, reason };
}

async function readStdin() {
  const chunks = [];
  let size = 0;
  for await (const chunk of process.stdin) {
    size += chunk.length;
    if (size > MAX_STDIN_BYTES) throw new Error('Klaat hook payload exceeds the size limit');
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString('utf8');
}

export async function main() {
  let payload;
  try {
    const input = await readStdin();
    payload = JSON.parse(input);
  } catch (error) {
    block(error instanceof Error ? error.message : 'invalid Klaat hook payload');
    return;
  }

  let command;
  let guardPayload;
  try {
    command = extractKlaatCommand(payload);
    if (command !== null) guardPayload = buildGuardPayload(payload, command);
  } catch (error) {
    block(error instanceof Error ? error.message : 'invalid run_command payload');
    return;
  }
  if (command === null) return;

  const args = ['hook', '--harness', 'codex'];
  if (typeof payload.project_root === 'string' && payload.project_root) {
    args.push('--workspace', payload.project_root);
  }
  args.push('--json');

  const guardPathKey = Object.keys(process.env).find((key) => key.toUpperCase() === 'PATH');
  const guardPath = trustedGuardPath(guardPathKey ? process.env[guardPathKey] : '');
  if (!guardPath) {
    block('HOL Guard needs an absolute trusted executable search path.');
    return;
  }
  const guardEnv = { ...process.env };
  for (const key of Object.keys(guardEnv)) {
    if (key.toUpperCase() === 'PATH') delete guardEnv[key];
  }
  guardEnv.PATH = guardPath;

  const result = spawnSync('hol-guard', args, {
    input: `${JSON.stringify(guardPayload)}\n`,
    encoding: 'utf8',
    timeout: GUARD_TIMEOUT_MS,
    maxBuffer: MAX_STDIN_BYTES,
    cwd: guardPayload.cwd,
    env: guardEnv,
    windowsHide: true,
  });

  if (result.error || result.status !== 0) {
    block('HOL Guard could not complete an authoritative command review.');
    return;
  }

  const response = parseGuardJson(result.stdout);
  const decision = decisionFromGuardResponse(response);
  if (!decision.allow) block(decision.reason);
}

const invokedPath = process.argv[1] ? pathToFileURL(process.argv[1]).href : '';
if (import.meta.url === invokedPath) {
  await main();
}
