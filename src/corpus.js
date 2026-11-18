import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const currentDir = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(currentDir, '..');

function loadList(fileName) {
  const filePath = path.join(rootDir, 'data', fileName);
  const raw = fs.readFileSync(filePath, 'utf8');
  return JSON.parse(raw);
}

export const popularPackages = loadList('popular-packages.json');
export const hallucinationCorpus = loadList('hallucination-corpus.json');