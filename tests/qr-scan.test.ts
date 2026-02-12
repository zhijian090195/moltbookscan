import path from 'path';
import { FileScanner } from '../src/core/file-scanner';

const FIXTURES = path.join(__dirname, 'fixtures');
const scanner = new FileScanner();

const defaultOpts = {
  verbose: false,
  output: 'cli' as const,
  skipLLM: true,
  recursive: false,
};

describe('QR Code Injection Scanning', () => {
  it('detects prompt injection in QR code', async () => {
    const report = await scanner.scan(
      path.join(FIXTURES, 'qr-prompt-injection.png'),
      defaultOpts
    );
    expect(report.findings.length).toBeGreaterThan(0);
    expect(report.findings[0].category).toBe('qr_code_injection');
    expect(report.findings.some((f) =>
      f.description.toLowerCase().includes('override previous instructions')
    )).toBe(true);
  });

  it('detects javascript: URI in QR code', async () => {
    const report = await scanner.scan(
      path.join(FIXTURES, 'qr-javascript-uri.png'),
      defaultOpts
    );
    expect(report.findings.length).toBeGreaterThan(0);
    expect(report.findings.some((f) =>
      f.description.toLowerCase().includes('malicious uri')
    )).toBe(true);
  });

  it('detects credential theft in QR code', async () => {
    const report = await scanner.scan(
      path.join(FIXTURES, 'qr-credential-theft.png'),
      defaultOpts
    );
    expect(report.findings.length).toBeGreaterThan(0);
    expect(report.findings.some((f) =>
      f.description.toLowerCase().includes('api keys') ||
      f.description.toLowerCase().includes('credential')
    )).toBe(true);
  });

  it('detects curl|bash covert execution in QR code', async () => {
    const report = await scanner.scan(
      path.join(FIXTURES, 'qr-curl-payload.png'),
      defaultOpts
    );
    expect(report.findings.length).toBeGreaterThan(0);
    expect(report.findings.some((f) =>
      f.description.toLowerCase().includes('shell execution') ||
      f.description.toLowerCase().includes('remote content')
    )).toBe(true);
  });

  it('detects short URL in QR code', async () => {
    const report = await scanner.scan(
      path.join(FIXTURES, 'qr-short-url.png'),
      defaultOpts
    );
    expect(report.findings.length).toBeGreaterThan(0);
    expect(report.findings.some((f) =>
      f.description.includes('Short URL') || f.description.includes('suspicious')
    )).toBe(true);
  });

  it('does NOT flag safe URL in QR code', async () => {
    const report = await scanner.scan(
      path.join(FIXTURES, 'qr-safe-url.png'),
      defaultOpts
    );
    expect(report.findings.length).toBe(0);
  });

  it('does NOT flag benign text in QR code', async () => {
    const report = await scanner.scan(
      path.join(FIXTURES, 'qr-benign-text.png'),
      defaultOpts
    );
    expect(report.findings.length).toBe(0);
  });

  it('scans directory with mixed QR images', async () => {
    const report = await scanner.scan(FIXTURES, {
      ...defaultOpts,
      include: ['.png'],
      recursive: false,
    });
    // Should find threats in 5 malicious QR images, 2 safe ones
    expect(report.totalFiles).toBe(7);
    expect(report.riskFiles.length).toBeGreaterThanOrEqual(4);
    expect(report.summary.safe).toBeGreaterThanOrEqual(2);

    // Print summary for visibility
    console.log('\n  QR Scan Summary:');
    console.log(`    Total images: ${report.totalFiles}`);
    console.log(`    HIGH: ${report.summary.high}, MEDIUM: ${report.summary.medium}, LOW: ${report.summary.low}, SAFE: ${report.summary.safe}`);
    for (const f of report.riskFiles) {
      console.log(`    ${f.risk.padEnd(6)} ${f.path} (${f.findingCount} findings)`);
    }
  });
});
