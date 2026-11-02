import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';

const minimatch = {
  name: 'minimatch',
  severity: 'moderate',
  via: [{ name: 'minimatch', dependency: 'minimatch', url: 'https://github.com/advisories/GHSA-g3hv-75wg-m249' }],
};
const vsce = { name: '@vscode/vsce', severity: 'moderate', via: ['minimatch'] };

function run(vulnerabilities: object, status = 1, raw?: string) {
  const dir = mkdtempSync(join(tmpdir(), 'audit-test-'));
  try {
    writeFileSync(join(dir, 'npm'), '#!/bin/sh\nprintf "%s" "$AUDIT_REPORT"\nexit "$AUDIT_STATUS"\n', { mode: 0o755 });
    const report = raw
      ?? JSON.stringify({
        auditReportVersion: 2,
        vulnerabilities,
        metadata: {
          vulnerabilities: {
            total: Object.keys(vulnerabilities).length,
            ...Object.fromEntries(['info', 'low', 'moderate', 'high', 'critical'].map((level) => [
              level,
              Object.values(vulnerabilities).filter((value) => value?.severity === level).length,
            ])),
          },
        },
      });
    return spawnSync(process.execPath, ['scripts/audit.mts'], {
      encoding: 'utf8',
      env: { ...process.env, PATH: `${dir}:${process.env.PATH}`, AUDIT_REPORT: report, AUDIT_STATUS: String(status) },
    });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

test('audit permits clean reports and the specific minimatch advisory with vsce propagation', () => {
  assert.equal(run({}, 0).status, 0);
  assert.equal(run({ minimatch }).status, 0);
  assert.equal(run({ minimatch, '@vscode/vsce': vsce }).status, 0);
  for (const severity of ['info', 'low']) {
    const result = run({ other: { name: 'other', severity, via: ['example'] } }, 0);
    assert.equal(result.status, 0);
    assert.match(result.stdout, /example/);
  }
});

test('audit rejects other advisories, broken propagation and npm failures', () => {
  for (const severity of ['moderate', 'high', 'critical']) {
    assert.equal(run({ minimatch, other: { name: 'other', severity, via: ['minimatch'] } }).status, 1);
  }
  assert.equal(run({ minimatch: { ...minimatch, via: [...minimatch.via, { url: 'other' }] } }).status, 1);
  assert.equal(run({ '@vscode/vsce': vsce }).status, 1);
  assert.equal(run({ minimatch: { ...minimatch, via: [{ ...minimatch.via[0], url: 'other' }] } }).status, 1);
  assert.equal(run({}, 2).status, 1);
  assert.equal(run({}, 1, '{invalid').status, 1);
  assert.equal(run({}, 1).status, 1);
  assert.equal(run({ minimatch }, 0).status, 1);
  assert.equal(run({}, 1, JSON.stringify({ error: { code: 'ENETWORK' } })).status, 1);
  assert.equal(run({ minimatch: null }).status, 1);
  assert.equal(run({}, 0, '{}').status, 1);
});
