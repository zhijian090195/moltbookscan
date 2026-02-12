import { readFileSync, readdirSync, statSync } from 'fs';
import { join, relative, extname } from 'path';
import {
  FileFinding,
  FileScanReport,
  FileScanOptions,
  RiskLevel,
} from '../types/index.js';
import {
  ALL_PATTERNS,
  URL_PATTERN,
  isSuspiciousUrl,
  containsBase64Hidden,
} from '../analysis/patterns.js';
import { ContentScanner } from '../sdk/scanner.js';

const DEFAULT_EXTENSIONS = new Set([
  '.md', '.txt', '.ts', '.js', '.py', '.yaml', '.yml', '.json', '.sh',
]);

const DEFAULT_EXCLUDE_DIRS = new Set([
  'node_modules', '.git', 'dist', '__pycache__', '.next', '.venv', 'vendor',
]);

export class FileScanner {
  private contentScanner: ContentScanner;

  constructor() {
    this.contentScanner = new ContentScanner();
  }

  async scan(targetPath: string, options: FileScanOptions): Promise<FileScanReport> {
    const stat = statSync(targetPath);
    const files = stat.isDirectory()
      ? this.walkDirectory(targetPath, options)
      : [targetPath];

    const findings: FileFinding[] = [];
    const riskFiles: { path: string; risk: RiskLevel; findingCount: number }[] = [];
    const summary = { safe: 0, low: 0, medium: 0, high: 0 };

    for (const filePath of files) {
      let content: string;
      try {
        content = readFileSync(filePath, 'utf-8');
      } catch {
        continue;
      }

      const fileFindings = this.scanFileContent(filePath, content);
      findings.push(...fileFindings);

      const scanResult = this.contentScanner.scanSync(content);
      const risk = scanResult.risk;

      const key = risk.toLowerCase() as 'safe' | 'low' | 'medium' | 'high';
      summary[key]++;

      if (risk !== 'SAFE') {
        riskFiles.push({
          path: relative(targetPath, filePath) || filePath,
          risk,
          findingCount: fileFindings.length,
        });
      }
    }

    riskFiles.sort((a, b) => {
      const order: Record<RiskLevel, number> = { HIGH: 0, MEDIUM: 1, LOW: 2, SAFE: 3 };
      return order[a.risk] - order[b.risk];
    });

    return {
      targetPath,
      totalFiles: files.length,
      scannedFiles: files.length,
      findings,
      summary,
      riskFiles,
      scannedAt: new Date().toISOString(),
    };
  }

  private scanFileContent(filePath: string, content: string): FileFinding[] {
    const findings: FileFinding[] = [];
    const lines = content.split('\n');

    // Line-by-line pattern matching
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      for (const rule of ALL_PATTERNS) {
        const match = line.match(rule.pattern);
        if (match) {
          findings.push({
            filePath,
            line: i + 1,
            severity: rule.severity,
            category: rule.category,
            description: rule.description,
            matchedText: match[0],
            context: line.trim().slice(0, 120),
          });
        }
      }

      // Suspicious URL detection per line
      const urlMatches = line.match(URL_PATTERN);
      if (urlMatches) {
        for (const url of urlMatches) {
          if (isSuspiciousUrl(url)) {
            findings.push({
              filePath,
              line: i + 1,
              severity: 'LOW',
              category: 'suspicious_link',
              description: 'Suspicious or unknown URL detected',
              matchedText: url,
              context: line.trim().slice(0, 120),
            });
          }
        }
      }
    }

    // Base64 hidden content on full content
    if (containsBase64Hidden(content)) {
      findings.push({
        filePath,
        line: 0,
        severity: 'HIGH',
        category: 'base64_hidden',
        description: 'Hidden base64-encoded executable content detected',
        matchedText: '(base64 payload)',
        context: '(full file scan)',
      });
    }

    return findings;
  }

  private walkDirectory(dirPath: string, options: FileScanOptions): string[] {
    const files: string[] = [];
    const includeExts = options.include
      ? new Set(options.include.map(g => g.startsWith('.') ? g : `.${g}`))
      : DEFAULT_EXTENSIONS;
    const excludeDirs = options.exclude
      ? new Set([...DEFAULT_EXCLUDE_DIRS, ...options.exclude])
      : DEFAULT_EXCLUDE_DIRS;

    const walk = (dir: string) => {
      let entries: string[];
      try {
        entries = readdirSync(dir);
      } catch {
        return;
      }

      for (const entry of entries) {
        const fullPath = join(dir, entry);
        let stat;
        try {
          stat = statSync(fullPath);
        } catch {
          continue;
        }

        if (stat.isDirectory()) {
          if (!excludeDirs.has(entry) && options.recursive) {
            walk(fullPath);
          }
        } else if (stat.isFile()) {
          const ext = extname(entry).toLowerCase();
          if (includeExts.has(ext)) {
            files.push(fullPath);
          }
        }
      }
    };

    walk(dirPath);
    return files;
  }
}
