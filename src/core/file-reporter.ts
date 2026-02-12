import { FileScanReport, RiskLevel } from '../types/index.js';

// ─── Color Helpers ──────────────────────────────────────────────

const RESET = '\x1b[0m';
const BOLD = '\x1b[1m';
const DIM = '\x1b[2m';

const RISK_COLOR: Record<RiskLevel, string> = {
  HIGH: '\x1b[31m',
  MEDIUM: '\x1b[33m',
  LOW: '\x1b[36m',
  SAFE: '\x1b[32m',
};

const RISK_LABEL: Record<RiskLevel, string> = {
  HIGH: '\u274c HIGH',
  MEDIUM: '\u26a0\ufe0f  MEDIUM',
  LOW: '\u2139\ufe0f  LOW',
  SAFE: '\u2705 SAFE',
};

// ─── CLI Report ─────────────────────────────────────────────────

export function formatFileCLIReport(report: FileScanReport, verbose = false): string {
  const lines: string[] = [];
  const hr = '\u2500'.repeat(60);

  lines.push('');
  lines.push(`${BOLD}\ud83d\udee1\ufe0f  AgentShield File Scan Report${RESET}`);
  lines.push(`${DIM}${hr}${RESET}`);
  lines.push(`  Target:     ${report.targetPath}`);
  lines.push(`  Files:      ${report.scannedFiles} scanned`);
  lines.push(`  Findings:   ${report.findings.length} total`);
  lines.push(`  Scanned at: ${report.scannedAt}`);
  lines.push('');

  // Summary bar
  const { safe, low, medium, high } = report.summary;
  lines.push(`${BOLD}  Summary${RESET}`);
  lines.push(`  ${RISK_COLOR.SAFE}\u2588 SAFE: ${safe}${RESET}  ${RISK_COLOR.LOW}\u2588 LOW: ${low}${RESET}  ${RISK_COLOR.MEDIUM}\u2588 MEDIUM: ${medium}${RESET}  ${RISK_COLOR.HIGH}\u2588 HIGH: ${high}${RESET}`);
  lines.push('');

  // Risk files table
  if (report.riskFiles.length > 0) {
    lines.push(`${BOLD}  Files with Threats${RESET}`);
    lines.push(`${DIM}  ${'File'.padEnd(50)} ${'Risk'.padEnd(8)} Findings${RESET}`);
    lines.push(`${DIM}  ${'\u2500'.repeat(50)} ${'\u2500'.repeat(8)} ${'\u2500'.repeat(8)}${RESET}`);

    const maxFiles = verbose ? report.riskFiles.length : Math.min(report.riskFiles.length, 15);
    for (let i = 0; i < maxFiles; i++) {
      const f = report.riskFiles[i];
      const color = RISK_COLOR[f.risk];
      const truncPath = f.path.length > 48 ? '...' + f.path.slice(-45) : f.path;
      lines.push(`  ${truncPath.padEnd(50)} ${color}${f.risk.padEnd(8)}${RESET} ${f.findingCount}`);
    }
    if (!verbose && report.riskFiles.length > 15) {
      lines.push(`${DIM}  ... and ${report.riskFiles.length - 15} more files (use -v for all)${RESET}`);
    }
    lines.push('');
  }

  // Detailed findings
  if (verbose && report.findings.length > 0) {
    lines.push(`${BOLD}  Detailed Findings${RESET}`);
    lines.push(`${DIM}${hr}${RESET}`);

    for (const f of report.findings) {
      const color = RISK_COLOR[f.severity as RiskLevel] || RESET;
      const loc = f.line > 0 ? `${f.filePath}:${f.line}` : f.filePath;
      lines.push(`  ${color}[${f.severity}]${RESET} ${f.description}`);
      lines.push(`${DIM}    ${loc}${RESET}`);
      lines.push(`${DIM}    Matched: ${f.matchedText}${RESET}`);
      if (f.context && f.context !== '(full file scan)') {
        lines.push(`${DIM}    Context: ${f.context}${RESET}`);
      }
      lines.push('');
    }
  } else if (!verbose && report.findings.length > 0) {
    lines.push(`${DIM}  Use -v for detailed findings with file:line references${RESET}`);
    lines.push('');
  }

  // Footer
  if (high > 0) {
    lines.push(`${RISK_COLOR.HIGH}${BOLD}  \u26a0  ${high} HIGH-risk file(s) detected. Review immediately.${RESET}`);
  } else if (medium > 0) {
    lines.push(`${RISK_COLOR.MEDIUM}  ${medium} MEDIUM-risk file(s) found. Review recommended.${RESET}`);
  } else if (low > 0) {
    lines.push(`${RISK_COLOR.LOW}  ${low} LOW-risk file(s) found. Minor concerns.${RESET}`);
  } else {
    lines.push(`${RISK_COLOR.SAFE}  All files appear safe. No threats detected.${RESET}`);
  }
  lines.push('');

  return lines.join('\n');
}

// ─── JSON Report ────────────────────────────────────────────────

export function formatFileJSONReport(report: FileScanReport): string {
  return JSON.stringify(report, null, 2);
}

// ─── HTML Report ────────────────────────────────────────────────

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

export function formatFileHTMLReport(report: FileScanReport): string {
  const { safe, low, medium, high } = report.summary;
  const total = safe + low + medium + high;

  const riskColor: Record<string, string> = {
    HIGH: '#FF3B30',
    MEDIUM: '#FF9F0A',
    LOW: '#64D2FF',
    SAFE: '#34C759',
  };

  const overallRisk: RiskLevel = high > 0 ? 'HIGH' : medium > 0 ? 'MEDIUM' : low > 0 ? 'LOW' : 'SAFE';

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AgentShield File Scan Report</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, 'SF Pro Display', 'SF Pro Text', 'Helvetica Neue', sans-serif;
    background: #1C1C1E;
    color: #F2F2F7;
    min-height: 100vh;
    padding: 40px 20px;
    -webkit-font-smoothing: antialiased;
  }
  .container { max-width: 800px; margin: 0 auto; }
  .card {
    background: #2C2C2E;
    border-radius: 16px;
    padding: 28px;
    margin-bottom: 16px;
    border: 1px solid #3A3A3C;
  }
  .header { text-align: center; margin-bottom: 32px; }
  .header h1 { font-size: 28px; font-weight: 700; letter-spacing: -0.5px; margin-bottom: 4px; }
  .header .subtitle { color: #8E8E93; font-size: 15px; }
  .summary-grid {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 12px;
    margin: 20px 0;
  }
  .summary-item {
    background: #3A3A3C;
    border-radius: 12px;
    padding: 16px;
    text-align: center;
  }
  .summary-item .count {
    font-size: 32px;
    font-weight: 700;
    font-variant-numeric: tabular-nums;
  }
  .summary-item .label {
    font-size: 12px;
    color: #8E8E93;
    font-weight: 500;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    margin-top: 4px;
  }
  .section-title {
    font-size: 13px;
    font-weight: 600;
    color: #8E8E93;
    text-transform: uppercase;
    letter-spacing: 0.8px;
    margin-bottom: 12px;
  }
  .meta-row {
    display: flex;
    justify-content: space-between;
    padding: 8px 0;
    border-bottom: 1px solid #3A3A3C;
    font-size: 14px;
  }
  .meta-row:last-child { border-bottom: none; }
  .meta-row .key { color: #8E8E93; }
  table {
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
  }
  th {
    text-align: left;
    padding: 10px 8px;
    border-bottom: 2px solid #3A3A3C;
    color: #8E8E93;
    font-weight: 600;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }
  td {
    padding: 8px;
    border-bottom: 1px solid #3A3A3C;
    vertical-align: top;
  }
  tr:last-child td { border-bottom: none; }
  .badge {
    display: inline-block;
    font-size: 11px;
    font-weight: 600;
    padding: 3px 8px;
    border-radius: 6px;
    white-space: nowrap;
  }
  .badge-high { background: rgba(255,59,48,0.2); color: #FF453A; }
  .badge-medium { background: rgba(255,159,10,0.2); color: #FF9F0A; }
  .badge-low { background: rgba(100,210,255,0.2); color: #64D2FF; }
  .badge-safe { background: rgba(52,199,89,0.2); color: #34C759; }
  .mono { font-family: 'SF Mono', 'Menlo', monospace; font-size: 12px; }
  .context { color: #8E8E93; font-size: 12px; margin-top: 2px; }
  .footer {
    text-align: center;
    margin-top: 24px;
    font-size: 12px;
    color: #48484A;
  }
</style>
</head>
<body>
<div class="container">

  <div class="header">
    <h1>\ud83d\udee1\ufe0f AgentShield File Scan</h1>
    <div class="subtitle">Scanned ${report.scannedFiles} files &bull; ${report.findings.length} findings</div>
  </div>

  <div class="card">
    <div class="section-title">Overview</div>
    <div class="meta-row"><span class="key">Target</span><span class="mono">${escapeHtml(report.targetPath)}</span></div>
    <div class="meta-row"><span class="key">Files Scanned</span><span>${report.scannedFiles}</span></div>
    <div class="meta-row"><span class="key">Overall Risk</span><span class="badge badge-${overallRisk.toLowerCase()}">${overallRisk}</span></div>
    <div class="meta-row"><span class="key">Scanned At</span><span>${report.scannedAt}</span></div>
  </div>

  <div class="summary-grid">
    <div class="summary-item"><div class="count" style="color:${riskColor.SAFE}">${safe}</div><div class="label">Safe</div></div>
    <div class="summary-item"><div class="count" style="color:${riskColor.LOW}">${low}</div><div class="label">Low</div></div>
    <div class="summary-item"><div class="count" style="color:${riskColor.MEDIUM}">${medium}</div><div class="label">Medium</div></div>
    <div class="summary-item"><div class="count" style="color:${riskColor.HIGH}">${high}</div><div class="label">High</div></div>
  </div>

  ${report.riskFiles.length > 0 ? `
  <div class="card">
    <div class="section-title">Risk Files (${report.riskFiles.length})</div>
    <table>
      <thead><tr><th>File</th><th>Risk</th><th>Findings</th></tr></thead>
      <tbody>
        ${report.riskFiles.map(f => `
        <tr>
          <td class="mono">${escapeHtml(f.path)}</td>
          <td><span class="badge badge-${f.risk.toLowerCase()}">${f.risk}</span></td>
          <td>${f.findingCount}</td>
        </tr>`).join('')}
      </tbody>
    </table>
  </div>` : ''}

  ${report.findings.length > 0 ? `
  <div class="card">
    <div class="section-title">All Findings (${report.findings.length})</div>
    <table>
      <thead><tr><th>Location</th><th>Severity</th><th>Category</th><th>Description</th></tr></thead>
      <tbody>
        ${report.findings.map(f => {
          const loc = f.line > 0 ? `${escapeHtml(f.filePath)}:${f.line}` : escapeHtml(f.filePath);
          return `
        <tr>
          <td class="mono">${loc}</td>
          <td><span class="badge badge-${f.severity.toLowerCase()}">${f.severity}</span></td>
          <td>${escapeHtml(f.category)}</td>
          <td>
            ${escapeHtml(f.description)}
            ${f.context && f.context !== '(full file scan)' ? `<div class="context">${escapeHtml(f.context)}</div>` : ''}
          </td>
        </tr>`;
        }).join('')}
      </tbody>
    </table>
  </div>` : `
  <div class="card" style="text-align:center; padding:40px;">
    <div style="font-size:48px; margin-bottom:12px;">\u2705</div>
    <div style="font-size:18px; font-weight:600;">All Clear</div>
    <div style="color:#8E8E93; margin-top:4px;">No threats detected in ${total} files</div>
  </div>`}

  <div class="footer">
    AgentShield v0.1.0 &bull; ${report.scannedAt}
  </div>

</div>
</body>
</html>`;
}
