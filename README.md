# seed-hunter

**Find the tokens that shouldn't exist.** Rarity × recurrence mining for security
research, OSINT, and corpus forensics.

[![Python 3.11+](https://img.shields.io/badge/python-3.11%20%7C%203.12-3776AB?logo=python&logoColor=white)](pyproject.toml)
[![3.8 fallback](https://img.shields.io/badge/AST%20fallback-3.8%2B-informational)](docs/COMPAT.md)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

A nonsense word that appears **once** is a typo. A nonsense word that appears in
**fourteen independent files** is a codename — an internal service, a proprietary
brand, a zombie endpoint, a leaked credential fragment, a handle someone forgot
to scrub. seed-hunter scores every token in a corpus by

```
seed_score = rarity_z × log(1 + count) × log(1 + spread)
```

where **rarity** is character-trigram perplexity measured against *reference*
language (never the corpus being scored — in-corpus training normalizes the very
jargon you're hunting), **count** is case-insensitive recurrence capped per file
(so one-line JSON blobs can't fake popularity), and **spread** is the number of
distinct artifacts echoing it.

## Why not just grep?

Grep finds what you already suspect. seed-hunter finds what you didn't know to
suspect: the internal canary header stamped on every HTTP response, the
third-party marketplace codename hiding in a datasource roster, the access-key
ID recurring across presigned URLs, the unreleased version tag that only exists
in old package metadata.

## Install & run

```bash
git clone https://github.com/toxicwind/seed-hunter && cd seed-hunter
pip install nltk            # only needed for the semantic layer

python3 src/seed_hunter/seed_hunter.py /path/to/corpus --out out/
python3 src/seed_hunter/semantic_weirdness.py /path/to/corpus --out out/

# optional: cluster top seeds semantically with any OpenAI-compatible endpoint
export SEED_EMBED_URL=... SEED_EMBED_KEY=...
python3 src/seed_hunter/nlp_cluster.py 80 out/seeds_v2.json
```

Outputs: `seeds_v2.{json,csv,md}` (ranked, with file:line contexts),
`weird_report.{json,md}`, `clusters.json`.

## The pipeline

```
corpus ──► harvest (case-insensitive, per-file capped)
       ──► rarity model (char 3-gram, trained on reference prose only)
       ──► noise filters (unicode escapes, base64 fragments, hex/uuid,
                          CDN header names, ubiquitous tokens)
       ──► seed_score ranking with contexts
       ──► NLTK layer: PMI jargon collocations, hapax credential-shaped
           singlets, coined identifiers, single-document oddities
       ──► (opt) embedding clustering → seed families
```

## Python compatibility

Primary target **3.11+**, developed and tested on **3.12**. The only
version-sensitive surface is `ast` usage in the semantic layer — a 3.8+
fallback path is included (see `docs/COMPAT.md`). No other 3.10+ syntax
is used anywhere in the codebase.

## Design lessons (v1 → v2)

- Training the rarity model on the scored corpus ranked base64 noise #1 and
  real seeds below #8000. Score rarity against language the token *didn't*
  come from.
- Recurrence must be capped per file; a single minified JSON repeats a token
  hundreds of times and drowns independent sightings.
- Spread beats count: credentials and codenames echo across *independent*
  artifacts, not within one noisy file.

## Use it for

- Post-incident corpus triage (what internal names leaked into this dump?)
- Pre-publication hygiene (what are we about to accidentally disclose?)
- Red-team harvest review (which of these tokens deserve targeted probing?)
- Session-export forensics (agent session dumps are dense with seeds)

## License

MIT. Authorized use only — mine corpora you have the right to read.
