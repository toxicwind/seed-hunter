#!/usr/bin/env python3
"""
semantic_weirdness.py — NLTK-driven anomaly mining over recon corpora.

Layers:
 1. PMI collocations (bigram/trigram): fixed phrases = institutional jargon,
    internal product names, error-signature strings.
 2. Hapax-once oddities: tokens appearing exactly once corpus-wide with
    credential/ID-like shapes (keys, node IDs, session UUIDs) — leaks.
 3. Coinage detector: camelCase / snake_case / mixed tokens that are NOT in
    an English floor set and NOT pure code builtins — coined identifiers.
 4. Per-document semantic outliers: tokens whose zipf-style rarity is high
    AND that appear in only one document (localized weirdness = that doc's
    unique secret).
Outputs: weird_report.{json,md}
"""
import json, math, os, re, sys
sys.path.insert(0, "/tmp/pylibs")
from collections import Counter, defaultdict
from pathlib import Path
import nltk
from nltk.collocations import BigramCollocationFinder, TrigramCollocationFinder
from nltk.metrics import BigramAssocMeasures, TrigramAssocMeasures

import argparse
_ap = argparse.ArgumentParser(prog="semantic-weirdness", description="NLTK corpus anomaly miner")
_ap.add_argument("roots", nargs="+", help="corpus directories to mine")
_ap.add_argument("--out", default="./seed_hunter_out")
_args, _unknown = _ap.parse_known_args()
ROOTS = _args.roots
OUT = Path(_args.out); OUT.mkdir(parents=True, exist_ok=True)
MAXF = 8 * 1024 * 1024
TOKEN_RE = re.compile(r"[A-Za-z][A-Za-z0-9_.\-:/]{2,}")
ENG_FLOOR = set(json.load(open(OUT/"eng_floor.json"))) if (OUT/"eng_floor.json").exists() else set("""the of and to in is was he for it with as his on be at by i this had not are but from or have an they which one you were her all she there would their we him been has when who will more no if out so said what up its about into than them can only other new some could time these two may then do first any my now such like our over man me even most made after also did many before must through back years where much your way well down should because each just those people mr how too little state good very make world still own see men work long get here between both life being under never day same another know while last might us off great come since against go came right used take three""".split())

docs = {}   # path -> token list
for root in ROOTS:
    for dp, _, fns in os.walk(root):
        for fn in fns:
            p = Path(dp)/fn
            try:
                if p.stat().st_size > MAXF or p.suffix in ('.whl','.tgz','.png','.zip','.pyc'):
                    continue
                txt = p.read_text(errors="replace")
            except Exception:
                continue
            docs[str(p)] = [t.lower() for t in TOKEN_RE.findall(txt)]

all_tokens = [t for toks in docs.values() for t in toks]
N = len(all_tokens)
freq = Counter(all_tokens)
print(f"docs={len(docs)} tokens={N} uniq={len(freq)}")

# ---- 1. PMI collocations ----
bgf = BigramCollocationFinder.from_words(all_tokens, window_size=2)
bgf.apply_freq_filter(5)
bigrams = bgf.score_ngrams(BigramAssocMeasures.pmi)[:120]
tgf = TrigramCollocationFinder.from_words(all_tokens, window_size=3)
tgf.apply_freq_filter(4)
trigrams = tgf.score_ngrams(TrigramAssocMeasures.pmi)[:80]

def jargonish(pair):
    a, b = pair
    if a in ENG_FLOOR and b in ENG_FLOOR: return False
    if re.fullmatch(r"[0-9a-f]{8,}", a) or re.fullmatch(r"[0-9a-f]{8,}", b): return False
    return True
jbig = [((a,b),s) for (a,b),s in bigrams if jargonish((a,b))][:50]
jtri = [(t,s) for t,s in trigrams if sum(w in ENG_FLOOR for w in t) < 2][:40]

# ---- 2. hapax oddities (credential-shaped singlets) ----
KEYISH = re.compile(r"^(sk-[a-z0-9-]{10,}|ltai[a-z0-9]{10,}|aklt[a-z0-9]{8,}|[a-z0-9]{20,}|[a-z]+[0-9]{3,}[a-z0-9]*|[a-z0-9+/]{20,}={0,2})$", re.I)
hapax = []
doc_of = {}
for d, toks in docs.items():
    for t in set(toks):
        doc_of.setdefault(t, d)
for t, c in freq.items():
    if c == 1 and len(t) >= 8 and t not in ENG_FLOOR and KEYISH.match(t):
        hapax.append((t, doc_of.get(t, "?")))

# ---- 3. coinage detector ----
COIN = re.compile(r"^([a-z]+[A-Z][a-zA-Z]+|[a-z]+_[a-z_]+|[a-z]+-[a-z-]+)$")
coin = []
for t, c in freq.items():
    if c >= 3 and t not in ENG_FLOOR and COIN.match(t) and len(t) >= 5:
        if re.match(r"^(get|set|is_|to_|no_|un|re)([a-z_]+)$", t):  # boring code verbs
            pass
        coin.append((t, c))
coin.sort(key=lambda x: -x[1])

# ---- 4. per-document outliers ----
doc_uniq = defaultdict(set)
for d, toks in docs.items():
    for t in set(toks):
        doc_uniq[t].add(d)
localized = []
for t, ds in doc_uniq.items():
    if len(ds) == 1 and freq[t] >= 2 and len(t) >= 6 and t not in ENG_FLOOR:
        d = next(iter(ds))
        localized.append((t, freq[t], d))
localized.sort(key=lambda x: -x[1])

report = {
    "stats": {"docs": len(docs), "tokens": N, "uniq": len(freq)},
    "pmi_bigrams": [{"phrase": " ".join(p), "pmi": round(s,2), "count": freq[p[0]] and None} for p, s in jbig],
    "pmi_trigrams": [{"phrase": " ".join(t), "pmi": round(s,2)} for t, s in jtri],
    "hapax_keyish": [{"token": t, "doc": d} for t, d in hapax[:120]],
    "coined_terms": [{"token": t, "count": c} for t, c in coin[:150]],
    "localized_oddities": [{"token": t, "count": c, "doc": d} for t, c, d in localized[:150]],
}
(OUT/"weird_report.json").write_text(json.dumps(report, indent=1, ensure_ascii=False))

with open(OUT/"weird_report.md","w") as f:
    f.write(f"# semantic weirdness report\n\ncorpus: {len(docs)} docs, {N} tokens, {len(freq)} unique\n\n")
    f.write("## 1. High-PMI bigrams (institutional jargon / fixed phrases)\n\n")
    for (a,b),s in jbig[:35]:
        f.write(f"- `{a} {b}` — PMI {s:.1f} (x{bgf.ngram_fd[(a,b)]})\n")
    f.write("\n## 2. High-PMI trigrams\n\n")
    for t,s in jtri[:25]:
        f.write(f"- `{' '.join(t)}` — PMI {s:.1f}\n")
    f.write("\n## 3. Hapax credential-shaped tokens (appear exactly ONCE corpus-wide)\n\n")
    for t,d in hapax[:40]:
        f.write(f"- `{t[:60]}` — in {d}\n")
    f.write("\n## 4. Coined identifiers (recurrent, non-English)\n\n")
    for t,c in coin[:50]:
        f.write(f"- `{t}` x{c}\n")
    f.write("\n## 5. Localized oddities (recurrent but confined to ONE document)\n\n")
    for t,c,d in localized[:40]:
        f.write(f"- `{t[:60]}` x{c} — only in {os.path.basename(d)}\n")
print("== TOP PMI BIGRAMS ==")
for (a,b),s in jbig[:20]: print(f"{s:6.1f}  {a} {b}")
print("== HAPAX KEYISH (top) ==")
for t,d in hapax[:15]: print(f"  {t[:50]:52s} {os.path.basename(d)}")
print("== LOCALIZED (top) ==")
for t,c,d in localized[:15]: print(f"  {t[:44]:46s} x{c:<3d} {os.path.basename(d)}")
