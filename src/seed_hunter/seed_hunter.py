#!/usr/bin/env python3
"""
seed_hunter v2 — rarity x recurrence OSINT seed miner.

v2 lessons from v1 output:
  * n-gram model must NOT train on the same corpus being scored (internal
    jargon normalizes itself). v2 trains on a designated reference subcorpus
    (English advisories/CVE text) + an embedded common-English floor list.
  * one-line JSON bodies repeat a token 100x per file -> count per-file with a
    cap, so recurrence measures independent sightings, not line noise.
  * filter noise shapes: unicode escapes (u0026), base64 fragments (AAC7B),
    sourcemap/bundle dirs, CDN/WAF header names.
  * optional --nlp: embed top seeds via the gateway's nlp_embedding and
    cluster by cosine similarity (semantic seed families).
"""
import json, math, os, re, sys, csv
from collections import Counter, defaultdict
from pathlib import Path

import argparse
_ap = argparse.ArgumentParser(prog="seed-hunter", description="rarity x recurrence OSINT seed miner")
_ap.add_argument("roots", nargs="+", help="corpus directories to mine")
_ap.add_argument("--out", default="./seed_hunter_out", help="output directory")
_args, _unknown = _ap.parse_known_args()
ROOTS = _args.roots
REF_HINTS = ("GHSA", "nvd_", "46680_", "55723_", "61459_", "turing", "README")
EXCLUDE_DIRS = ("npm_audit", "wheel020", "wheel025", "__pycache__")
OUT = Path(_args.out); OUT.mkdir(parents=True, exist_ok=True)
MAXF = 5 * 1024 * 1024
PER_FILE_CAP = 5

TOKEN_RE = re.compile(r"[A-Za-z][A-Za-z0-9_.\-]{3,}")
UESCAPE = re.compile(r"^u00[0-9a-f]{2}$")
B64FRAG = re.compile(r"^[A-Z][A-Z0-9]{2,6}$")          # AAC7B-style bundle fragments
HEX_RE = re.compile(r"^[0-9a-f]{12,}$")
HDR_RE = re.compile(r"^x-(cdn|edge|cache|proxy|waf|internal)-")
COMMON = set("""about after again against agent all also an and any api are as at
back be because been before between body both but by can cannot client code come
content could data date day default did do does don't down each end error example
false fetch file find first for form found from get give given go good had has have
he header her here him his host how http https if image in info input into is it
its json key know last like list look made make many may me method model more most
must name need new no not note now null number object of off on once one only open
option or other our out over own page param part path people post put query read
request required response result return right said same search see server set she
should size so some status string such sure system take text than that the their
them then there these they this those through time to token tool true two type
under up upload url us use used user using value version very video want was way
we web well were what when where which while who will with without work would
write year you your""".split())

def iter_files():
    for root in ROOTS:
        for dirpath, dirs, files in os.walk(root):
            dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
            for fn in files:
                p = Path(dirpath) / fn
                try:
                    if p.stat().st_size > MAXF or p.suffix in ('.whl','.tgz','.png','.zip','.pyc'):
                        continue
                    yield p
                except OSError:
                    pass

counts, spread, variants, contexts = Counter(), defaultdict(set), defaultdict(Counter), defaultdict(list)
trigram = Counter()
prose_re = re.compile(r"[A-Za-z][A-Za-z ,.';:!?()\-]{60,}")

nfiles = 0
for p in iter_files():
    try:
        txt = p.read_text(errors="replace")
    except Exception:
        continue
    if not txt:
        continue
    nfiles += 1
    if any(h in p.name for h in REF_HINTS):          # reference English only
        for m in prose_re.finditer(txt):
            s = "  " + m.group(0).lower() + "  "
            for i in range(len(s) - 2):
                trigram[s[i:i+3]] += 1
    seen = Counter()
    for i, line in enumerate(txt.splitlines(), 1):
        for m in TOKEN_RE.finditer(line):
            raw = m.group(0); tok = raw.lower()
            seen[tok] += 1
            variants[tok][raw] += 1
            if len(contexts[tok]) < 3:
                contexts[tok].append(f"{p}:{i}: {line.strip()[:150]}")
    for tok, c in seen.items():
        counts[tok] += min(c, PER_FILE_CAP)
        spread[tok].add(str(p))

if not trigram:  # fallback: train on everything prose-like (weaker)
    for p in iter_files():
        try: txt = p.read_text(errors="replace")
        except Exception: continue
        for m in prose_re.finditer(txt):
            s = "  " + m.group(0).lower() + "  "
            for i in range(len(s) - 2):
                trigram[s[i:i+3]] += 1

V = 27 ** 3
total_tri = sum(trigram.values())
def rarity(tok):
    s = "  " + tok + "  "
    n = max(1, len(s) - 2)
    lp = sum(math.log10((trigram.get(s[i:i+3], 0) + 0.01) / (total_tri + 0.01 * V))
             for i in range(len(s) - 2))
    r = -lp / n
    if tok in COMMON:                       # common-English floor
        r = min(r, 1.2)
    return r

rows = []
for tok, cnt in counts.items():
    if cnt < 3 or len(tok) < 4 or tok in COMMON:
        continue
    if UESCAPE.match(tok) or B64FRAG.match(tok) or HEX_RE.match(tok) or HDR_RE.match(tok):
        continue
    sp = len(spread[tok])
    if sp < 2 or sp > max(4, nfiles * 0.25):
        continue
    rows.append([tok, cnt, sp, round(rarity(tok), 3)])

zs = [r[3] for r in rows]
if not zs:
    print("no candidates — corpus too small or fully filtered"); raise SystemExit(0)
mu = sum(zs) / len(zs); sd = (sum((x - mu) ** 2 for x in zs) / len(zs)) ** 0.5 or 1.0
out = []
for tok, cnt, sp, r in rows:
    rz = (r - mu) / sd
    seed = rz * math.log1p(cnt) * math.log1p(sp)
    out.append({"token": tok, "top_variant": variants[tok].most_common(1)[0][0],
                "count": cnt, "spread": sp, "rarity": r, "rarity_z": round(rz, 2),
                "seed_score": round(seed, 2), "contexts": contexts[tok]})
out.sort(key=lambda r: -r["seed_score"])

(OUT / "seeds_v2.json").write_text(json.dumps(out, indent=1, ensure_ascii=False))
with open(OUT / "seeds_v2.csv", "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["token","top_variant","count","spread","rarity","rarity_z","seed_score"])
    for r in out:
        w.writerow([r["token"], r["top_variant"], r["count"], r["spread"], r["rarity"], r["rarity_z"], r["seed_score"]])
with open(OUT / "seeds_v2.md", "w") as f:
    f.write(f"# seed_hunter v2\n\ncorpus {nfiles} files | {len(counts)} uniq | {len(out)} candidates\n\n")
    for i, r in enumerate(out[:200], 1):
        f.write(f"## {i}. `{r['top_variant']}` — {r['seed_score']} "
                f"(cnt {r['count']}, spread {r['spread']}, rz {r['rarity_z']})\n")
        for c in r["contexts"]:
            f.write(f"  - {c}\n")
        f.write("\n")

print(f"files={nfiles} uniq={len(counts)} candidates={len(out)} ref_trigrams={total_tri}")
for r in out[:35]:
    print(f"{r['seed_score']:7.2f}  {r['top_variant']:30s} cnt={r['count']:<4d} spread={r['spread']:<3d} rz={r['rarity_z']}")
