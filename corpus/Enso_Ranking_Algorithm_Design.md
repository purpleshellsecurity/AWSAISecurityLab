# Enso Ranking Algorithm — Design Overview
Classification: Confidential
Department: Engineering

> ILLUSTRATIVE / SYNTHETIC: fictional content created for the AICompliance data-
> classification and risk-rating exercise. Not a real algorithm; not in the lab corpus.

## Summary
The Enso relevance ranker blends lexical matching with a proprietary recency-weighted
authority score. The exact feature weights and the source-trust methodology are a trade
secret and are not published outside Engineering.

## Scoring (illustrative)
```
final_score = 0.55 * lexical_match + 0.30 * source_authority + 0.15 * recency
```
`source_authority` is derived from an internal source-trust table maintained by the
platform team; the table and its update rules are the competitive differentiator.

## Why this is Confidential
The weighting scheme and source-trust methodology are what make Enso's answers better
than a naive keyword search. Public disclosure would let a competitor replicate the
ranking quality and erode the product's market position. This is **trade-secret** /
competitive-IP sensitivity — not personal-data sensitivity.
