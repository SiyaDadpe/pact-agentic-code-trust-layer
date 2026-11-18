import fs from 'node:fs';
import path from 'node:path';

function pdfEscape(value) {
  return String(value ?? '')
    .replace(/\\/g, '\\\\')
    .replace(/\(/g, '\\(')
    .replace(/\)/g, '\\)');
}

function buildPdfDocument(entries) {
  const lines = entries.map((entry, index) => {
    const packageName = entry?.requested_package?.name ?? 'unknown';
    const version = entry?.requested_package?.version ? `@${entry.requested_package.version}` : '';
    const decision = entry?.decision ?? 'UNKNOWN';
    const reason = entry?.reason ?? 'no reason recorded';
    const risk = entry?.risk_score ?? 0;
    const confidence = entry?.confidence ?? 0;
    return `${index + 1}. ${packageName}${version} | ${decision} | risk=${risk} | confidence=${confidence} | ${reason}`;
  });

  const content = lines.join('\n');
  const escaped = pdfEscape(content);
  const objects = [
    '<< /Type /Catalog /Pages 2 0 R >>',
    '<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
    '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>',
    `<< /Length ${escaped.length + 100} >>\nstream\nBT\n/F1 11 Tf\n50 760 Td\n${escaped.split('\n').map((line, index) => `(${pdfEscape(line)}) Tj\n0 -16 Td`).join('\n')}ET\nendstream`,
    '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>'
  ];

  let pdf = '%PDF-1.4\n';
  const offsets = [0];
  for (const object of objects) {
    offsets.push(pdf.length);
    pdf += `${objects.indexOf(object) + 1} 0 obj\n${object}\nendobj\n`;
  }
  const xrefPosition = pdf.length;
  pdf += `xref\n0 ${objects.length + 1}\n`;
  pdf += '0000000000 65535 f \n';
  for (let index = 1; index <= objects.length; index += 1) {
    pdf += `${String(offsets[index]).padStart(10, '0')} 00000 n \n`;
  }
  pdf += `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${xrefPosition}\n%%EOF\n`;

  return pdf;
}

export async function generatePdfReport(entries, outputPath = 'pact-report.pdf') {
  const resolvedOutputPath = path.isAbsolute(outputPath) ? outputPath : path.join(process.cwd(), outputPath);
  const directory = path.dirname(resolvedOutputPath);
  fs.mkdirSync(directory, { recursive: true });

  const content = buildPdfDocument(entries);
  fs.writeFileSync(resolvedOutputPath, content, 'binary');

  return {
    outputPath: resolvedOutputPath,
    bytes: Buffer.byteLength(content, 'binary'),
    ok: true
  };
}
