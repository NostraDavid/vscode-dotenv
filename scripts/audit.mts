import { spawnSync } from 'node:child_process';

const audit = spawnSync('npm', ['audit', '--json', '--audit-level=moderate'], { encoding: 'utf8' });
if (audit.stderr) process.stderr.write(audit.stderr);

try {
  if (audit.error || (audit.status !== 0 && audit.status !== 1)) throw new Error('npm audit failed');
  const report = JSON.parse(audit.stdout);
  if (
    report.auditReportVersion !== 2 || report.error || !report.vulnerabilities
    || typeof report.vulnerabilities !== 'object' || Array.isArray(report.vulnerabilities)
  ) {
    throw new Error('Invalid npm audit report');
  }
  const entries = Object.entries(report.vulnerabilities);
  const levels = ['info', 'low', 'moderate', 'high', 'critical'];
  const counts = report.metadata?.vulnerabilities;
  if (
    !counts || counts.total !== entries.length || levels.some((level) =>
      !Number.isInteger(counts[level])
      || counts[level]
        !== entries.filter(([, value]) => (value as { severity?: string } | null)?.severity === level).length
    ) || (audit.status === 0) !== (counts.moderate + counts.high + counts.critical === 0)
  ) {
    throw new Error('Inconsistent npm audit report');
  }
  for (const [name, value] of entries) {
    const vulnerability = value as { name?: string; severity?: string; via?: unknown[] } | null;
    if (
      !vulnerability || vulnerability.name !== name || !levels.includes(vulnerability.severity ?? '')
      || !Array.isArray(vulnerability.via) || vulnerability.via.length === 0
    ) {
      throw new Error(`Unexpected vulnerability: ${name}`);
    }
    if (
      vulnerability.via.some((item) => {
        if (typeof item === 'string') return !item;
        if (!item || typeof item !== 'object') return true;
        return !('name' in item) || typeof item.name !== 'string' || !('dependency' in item)
          || typeof item.dependency !== 'string' || !('url' in item) || typeof item.url !== 'string';
      })
    ) throw new Error(`Invalid advisory: ${name}`);
    if (vulnerability.severity === 'info' || vulnerability.severity === 'low') {
      console.log(JSON.stringify(value));
      continue;
    }
    const via = vulnerability.via[0] as { name?: unknown; dependency?: unknown; url?: unknown } | string | null;
    const allowed = vulnerability.severity === 'moderate' && vulnerability.via.length === 1
      && name === 'minimatch' && typeof via === 'object' && via !== null
      && via.name === 'minimatch' && via.dependency === 'minimatch'
      && via.url === 'https://github.com/advisories/GHSA-g3hv-75wg-m249';
    const root = report.vulnerabilities.minimatch;
    const propagated = vulnerability.severity === 'moderate' && vulnerability.via.length === 1
      && name === '@vscode/vsce' && via === 'minimatch' && root?.name === 'minimatch'
      && root.severity === 'moderate' && Array.isArray(root.via) && root.via.length === 1
      && root.via[0]?.name === 'minimatch' && root.via[0]?.dependency === 'minimatch'
      && root.via[0]?.url === 'https://github.com/advisories/GHSA-g3hv-75wg-m249';
    if (!allowed && !propagated) throw new Error(`Unexpected vulnerability: ${name}`);
  }
  console.log(
    entries.length
      ? 'npm audit: no blocking vulnerabilities beyond the permitted advisory.'
      : 'npm audit: no vulnerabilities.',
  );
} catch (error) {
  console.error('npm audit check failed:', error instanceof Error ? error.message : error);
  if (audit.stdout) process.stderr.write(audit.stdout);
  process.exitCode = 1;
}
