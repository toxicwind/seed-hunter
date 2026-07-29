#!/usr/bin/env python3
"""
nlp_cluster.py — semantic clustering of top seeds via any OpenAI-compatible
embeddings endpoint. Configure with env:
  SEED_EMBED_URL   e.g. https://api.openai.com/v1/embeddings
  SEED_EMBED_KEY   bearer token
  SEED_EMBED_MODEL default: text-embedding-3-small
Usage: python3 nlp_cluster.py [TOPN] [seeds_json] [threshold]
"""
import json, math, os, subprocess, sys
from pathlib import Path

TOPN = int(sys.argv[1]) if len(sys.argv) > 1 else 80
SEEDS = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("seed_hunter_out/seeds_v2.json")
THRESH = float(sys.argv[3]) if len(sys.argv) > 3 else 0.82
URL = os.environ.get("SEED_EMBED_URL", "https://api.openai.com/v1/embeddings")
KEY = os.environ.get("SEED_EMBED_KEY", "")
MODEL = os.environ.get("SEED_EMBED_MODEL", "text-embedding-3-small")

seeds = json.load(open(SEEDS))[:TOPN]
tokens = [s["token"] for s in seeds]
body = {"model": MODEL, "input": tokens}
r = subprocess.run(["curl", "-sS", "--max-time", "60", "-X", "POST",
                    "-H", f"Authorization: Bearer {KEY}",
                    "-H", "Content-Type: application/json",
                    "-d", json.dumps(body), URL], capture_output=True)
resp = json.loads(r.stdout)
emb = [d["embedding"] for d in sorted(resp["data"], key=lambda d: d["index"])]

def cos(a, b):
    dot = sum(x*y for x, y in zip(a, b))
    na = math.sqrt(sum(x*x for x in a)); nb = math.sqrt(sum(x*x for x in b))
    return dot / (na * nb) if na and nb else 0.0

assigned = [False] * len(tokens)
clusters = []
order = sorted(range(len(tokens)), key=lambda i: -seeds[i].get("seed_score", 0))
for i in order:
    if assigned[i]: continue
    members = [i]; assigned[i] = True
    for j in order:
        if not assigned[j] and cos(emb[i], emb[j]) >= THRESH:
            members.append(j); assigned[j] = True
    clusters.append(members)

out = [[seeds[m]["token"] for m in mem] for mem in clusters]
json.dump(out, open("clusters.json", "w"), indent=1)
print(f"embedded {len(tokens)} seeds -> {len(clusters)} clusters -> clusters.json")
