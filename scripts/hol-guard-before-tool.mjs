#!/usr/bin/env node
import { spawnSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';
import process from 'node:process';

const MAX_STDIN_BYTES = 1_000_000;
const GUARD_TIMEOUT_MS = 9_000;

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

export function buildGuardPayload(payload, command) {
  const guardPayload = {
    hook_event_name: 'PreToolUse',
    tool_name: 'Bash',
    tool_input: { command },
  };
  if (typeof payload.session_id === 'string' && payload.session_id) {
    guardPayload.session_id = payload.session_id;
  }
  if (typeof payload.project_root === 'string' && payload.project_root) {
    guardPayload.cwd = payload.project_root;
  }
  return guardPayload;
}

function parseGuardJson(stdout) {
  const text = typeof stdout === 'string' ? stdout.trim() : '';
  if (!text) return null;
  try {
    return JSON.parse(text);
  } catch {
    for (const line of text.split(/\r?\n/).reverse()) {
      const candidate = line.trim();
      if (!candidate) continue;
      try {
        const parsed = JSON.parse(candidate);
        if (parsed && typeof parsed === 'object') return parsed;
      } catch {
        // Keep looking for the final JSON response line.
      }
    }
    return null;
  }
}

export function decisionFromGuardResponse(response) {
  if (!response || typeof response !== 'object') {
    return { allow: false, reason: 'HOL Guard returned an invalid response.' };
  }
  const hookSpecific = response.hookSpecificOutput;
  const permissionDecision = hookSpecific && typeof hookSpecific === 'object'
    ? hookSpecific.permissionDecision
    : undefined;
  const policyAction = response.policy_action;
  const reasonCode = response.reason_code;

  if (
    permissionDecision === 'allow' &&
    (policyAction === 'allow' || policyAction === 'warn') &&
    reasonCode !== 'harness_not_managed'
  ) {
    return { allow: true, reason: '' };
  }

  const reason =
    (typeof response.reason === 'string' && response.reason) ||
    (hookSpecific && typeof hookSpecific === 'object' &&
      typeof hookSpecific.permissionDecisionReason === 'string' &&
      hookSpecific.permissionDecisionReason) ||
    (typeof reasonCode === 'string' && `HOL Guard blocked this command (${reasonCode}).`) ||
    'HOL Guard did not return an authoritative allow decision.';
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
  try {
    command = extractKlaatCommand(payload);
  } catch (error) {
    block(error instanceof Error ? error.message : 'invalid run_command payload');
    return;
  }
  if (command === null) return;

  const guardPayload = buildGuardPayload(payload, command);
  const args = ['hook', '--harness', 'codex'];
  if (typeof payload.project_root === 'string' && payload.project_root) {
    args.push('--workspace', payload.project_root);
  }
  args.push('--json');

  const result = spawnSync('hol-guard', args, {
    input: `${JSON.stringify(guardPayload)}\n`,
    encoding: 'utf8',
    timeout: GUARD_TIMEOUT_MS,
    maxBuffer: MAX_STDIN_BYTES,
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
