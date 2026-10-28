import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { copyFileSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const wrapperPath = join(dirname(fileURLToPath(import.meta.url)), 'hol-guard-before-tool.sh');

function runWrapper(fakeAdapter) {
  const directory = mkdtempSync(join(tmpdir(), 'klaat-guard-wrapper-'));
  try {
    const wrapper = join(directory, 'hol-guard-before-tool.sh');
    copyFileSync(wrapperPath, wrapper);
    if (fakeAdapter !== null) {
      writeFileSync(join(directory, 'hol-guard-before-tool.mjs'), fakeAdapter);
    }
    return spawnSync('sh', [wrapper], {
      encoding: 'utf8',
      input: JSON.stringify({ event: 'before_tool', tool_name: 'run_command' }),
      timeout: 3000,
    });
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

const posix = process.platform !== 'win32';

test('wrapper preserves authoritative allow with exit 0', { skip: !posix }, () => {
  const result = runWrapper('process.exit(0);');
  assert.equal(result.status, 0);
  assert.equal(result.stdout.trim(), '');
});

test('wrapper preserves JSON block sent on stdout', { skip: !posix }, () => {
  const result = runWrapper('console.log(JSON.stringify({ decision: "block", reason: "denied" }));');
  assert.equal(result.status, 0);
  assert.deepEqual(JSON.parse(result.stdout), { decision: 'block', reason: 'denied' });
});

test('wrapper converts adapter runtime failure into Klaat blocking exit 2', { skip: !posix }, () => {
  const result = runWrapper('process.exit(7);');
  assert.equal(result.status, 2);
  assert.match(result.stderr, /failed \(exit 7\)/);
});

test('wrapper converts absent adapter into Klaat blocking exit 2', { skip: !posix }, () => {
  const result = runWrapper(null);
  assert.equal(result.status, 2);
  assert.match(result.stderr, /failed \(exit /);
});

// The host's hook timeout must exceed the adapter's own 9-second deadline.
// These tests cover shell exit behavior, not integration with a managed Guard runtime.
