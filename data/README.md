# Data files

- `popular-packages.json`: popular npm package names used for typosquat (name-similarity) detection. The first 91 entries are the original hand-picked list. The rest are filled, up to 5,000 names, from the ranked `top` list in [`npm-high-impact`](https://github.com/wooorm/npm-high-impact) v1.13.0 (most downloaded and most depended-on packages, published 2026-06-08). The list was read as data; the package was not installed.
- `hallucination-corpus.json`: package names associated with AI-hallucinated or fake-package patterns (slopsquatting).
