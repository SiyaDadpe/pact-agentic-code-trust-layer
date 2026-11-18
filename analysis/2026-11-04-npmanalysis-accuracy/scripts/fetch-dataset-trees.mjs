#!/usr/bin/env node
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO = process.env.NPMANALYSIS_REPO || 'lxyeternal/NPMAnalysis';
const REF = process.env.NPMANALYSIS_REF || 'main';
const DATA_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', 'data');
const offline = process.argv.includes('--offline');

const apiBase = `https://api.github.com/repos/${REPO}`;

function requestHeaders() {
  const headers = {
    accept: 'application/vnd.github+json',
    'user-agent': 'pact-npmanalysis-verifier'
  };
  if (process.env.GITHUB_TOKEN) {
    headers.authorization = `Bearer ${process.env.GITHUB_TOKEN}`;
  }
  return headers;
}

async function getJson(url) {
  const response = await fetch(url, { headers: requestHeaders() });
  const text = await response.text();
  if (!response.ok) {
    const reset = response.headers.get('x-ratelimit-reset');
    throw new Error(`GitHub API ${response.status} for ${url}${reset ? ` (rate limit reset ${reset})` : ''}: ${text.slice(0, 300)}`);
  }
  return JSON.parse(text);
}

async function getTree(sha, recursive = false) {
  return getJson(`${apiBase}/git/trees/${sha}${recursive ? '?recursive=1' : ''}`);
}

async function collectBlobs(sha, seen = new Set()) {
  if (seen.has(sha)) {
    return [];
  }
  seen.add(sha);

  const recursiveTree = await getTree(sha, true);
  if (!recursiveTree.truncated) {
    return {
      mode: 'recursive',
      entries: recursiveTree.tree
    };
  }

  const shallowTree = await getTree(sha, false);
  const entries = [];
  for (const entry of shallowTree.tree) {
    if (entry.type === 'blob') {
      entries.push(entry);
      continue;
    }
    if (entry.type === 'tree') {
      const child = await collectBlobs(entry.sha, seen);
      entries.push(...child.entries.map((childEntry) => ({
        ...childEntry,
        path: `${entry.path}/${childEntry.path}`
      })));
    }
  }

  return {
    mode: 'enumerated',
    entries
  };
}

async function saveJson(fileName, value) {
  const target = path.join(DATA_DIR, fileName);
  await fs.writeFile(target, `${JSON.stringify(value, null, 2)}\n`);
  return target;
}

async function main() {
  await fs.mkdir(DATA_DIR, { recursive: true });

  if (offline) {
    for (const fileName of ['root-tree.json', 'dataset-tree.json', 'zip-benign-tree.json', 'zip-malware-tree.json']) {
      const value = JSON.parse(await fs.readFile(path.join(DATA_DIR, fileName), 'utf8'));
      const blobs = (value.tree ?? []).filter((entry) => entry.type === 'blob');
      console.log(`${fileName}: sha=${value.sha} truncated=${Boolean(value.truncated)} entries=${(value.tree ?? []).length} blobs=${blobs.length}`);
    }
    return;
  }

  const rootTree = await getTree(REF, false);
  await saveJson('root-tree.json', rootTree);

  const datasetEntry = rootTree.tree.find((entry) => entry.path === 'Dataset' && entry.type === 'tree');
  if (!datasetEntry) {
    throw new Error('Dataset folder not found in root tree');
  }

  const datasetTree = await getTree(datasetEntry.sha, false);
  await saveJson('dataset-tree.json', datasetTree);

  for (const [folderName, fileName] of [['zip_benign', 'zip-benign-tree.json'], ['zip_malware', 'zip-malware-tree.json']]) {
    const folderEntry = datasetTree.tree.find((entry) => entry.path === folderName && entry.type === 'tree');
    if (!folderEntry) {
      throw new Error(`${folderName} folder not found in Dataset tree`);
    }

    const collected = await collectBlobs(folderEntry.sha);
    const output = {
      repo: REPO,
      ref: REF,
      folder: folderName,
      sha: folderEntry.sha,
      truncation_fallback: collected.mode === 'enumerated',
      truncated: false,
      fetched_at: new Date().toISOString(),
      tree: collected.entries
    };
    await saveJson(fileName, output);

    const blobCount = output.tree.filter((entry) => entry.type === 'blob').length;
    console.log(`${folderName}: sha=${folderEntry.sha} entries=${output.tree.length} blobs=${blobCount} mode=${collected.mode}`);
  }
}

main().catch((error) => {
  console.error(error.stack ?? error.message);
  process.exitCode = 1;
});
