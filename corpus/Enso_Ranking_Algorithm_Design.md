# Enso Ranking Algorithm — Design Overview

Classification: Confidential
Department: Engineering

> Fabricated content for the AICompliance data-classification and risk-rating lab. Enso is a
> fictional product; this is not a real algorithm. Retained as a realistic example of trade-secret /
> competitive-IP material.

## Summary

The Enso relevance ranker blends lexical matching with a proprietary recency-weighted authority
score and a learned semantic-similarity component. The exact feature weights, the source-trust
methodology, and the reranker training data are trade secrets and are not published outside
Engineering.

## Pipeline

1. **Candidate generation** — BM25 lexical retrieval over the inverted index returns the top 200
   candidates per query.
2. **Embedding recall** — an approximate-nearest-neighbor lookup (HNSW, cosine) over document
   embeddings adds up to 100 semantically similar candidates the lexical pass missed.
3. **Feature scoring** — each candidate is scored with the blend below.
4. **Cross-encoder rerank** — the top 50 by blended score are rescored by a fine-tuned
   cross-encoder; the top 8 are returned to the answer synthesizer.

## Scoring blend

```
final_score = 0.42 * lexical_match       # BM25, length-normalized
            + 0.24 * semantic_similarity # cross-encoder logit, min-max scaled
            + 0.22 * source_authority    # from the internal source-trust table
            + 0.12 * recency             # exp decay, 90-day half-life
```

`source_authority` is derived from an internal source-trust table maintained by the platform team.
Each source is assigned a base trust tier (0–4) and adjusted by signals such as edit provenance,
resolution rate of linked support tickets, and manual demotion of sources flagged during incident
review. The table and its update rules are the primary competitive differentiator.

## Source-trust tiers (illustrative)

| Tier | Example source class | Base weight |
|------|----------------------|-------------|
| 4 | Verified runbooks, signed-off policy docs | 1.00 |
| 3 | Product/engineering wiki, reviewed | 0.80 |
| 2 | Support macros, KB drafts | 0.55 |
| 1 | User-contributed notes | 0.30 |
| 0 | Unverified / flagged sources | 0.05 |

## Tuning notes

- Weights were fit by grid search against an internal relevance-judgment set (~4,800 query/document
  pairs) and validated on held-out click-through data.
- The recency half-life is deliberately short for the support corpus (docs go stale fast) and longer
  for policy content, configured per-namespace.
- The cross-encoder is retrained monthly; drift is monitored via nDCG@8 on the judgment set.

## Why this is Confidential

The weighting scheme, source-trust methodology, and reranker training pipeline are what make Enso's
answers better than a naive keyword search. Public disclosure would let a competitor replicate the
ranking quality and erode the product's market position. This is **trade-secret** / competitive-IP
sensitivity — not personal-data sensitivity.
