import fs from 'node:fs';
import path from 'node:path';
import { DEFAULT_LOG_FILE } from './constants.js';

export function createDecisionLogger(logFilePath = DEFAULT_LOG_FILE) {
  const absolutePath = path.isAbsolute(logFilePath) ? logFilePath : path.join(process.cwd(), logFilePath);
  fs.mkdirSync(path.dirname(absolutePath), { recursive: true });

  return {
    path: absolutePath,
    write(entry) {
      fs.appendFileSync(absolutePath, `${JSON.stringify(entry)}\n`, 'utf8');
    }
  };
}