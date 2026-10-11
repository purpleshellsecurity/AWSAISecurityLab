# Documentation index

> [!TIP]
> **New here?** Read [overview.md](overview.md) (the whole project in plain AWS terms), then the root
> [TUTORIAL.md](../TUTORIAL.md). Then, by goal:

### Understand
| Doc | What it answers |
|---|---|
| [overview.md](overview.md) | The whole project in plain AWS terms — **start here**. |
| [architecture.md](architecture.md) | The components, the request flow, the data flow, and the production upgrade path. |
| [../TUTORIAL.md](../TUTORIAL.md) | How it's wired on AWS and where each control lives (file + mechanism). |

### Operate
| Doc | What it answers |
|---|---|
| [../TESTING.md](../TESTING.md) | A step-by-step runbook — deploy, attack, and prove each control. |
| [tuning.md](tuning.md) | Issues found in testing, the knobs to turn, diagnostics, and AWS doc links. |
| [../demo/scenarios/README.md](../demo/scenarios/README.md) | How to write and replay your own attack scenarios. |

### Frameworks
| Doc | What it answers |
|---|---|
| [controls-matrix.md](controls-matrix.md) | Each control ← the incident finding that motivates it, and the demo that proves it. |
| [atlas-mapping.md](atlas-mapping.md) | Each control → the MITRE ATLAS attacker technique it defends against. |
| [owasp-mapping.md](owasp-mapping.md) | Each control → the OWASP LLM Top 10 (2025) prevention strategy it implements. |
| [end-to-end-logging.md](end-to-end-logging.md) | How one `request_id` correlates every layer's logs, with the join queries. |

**The three-way traceability:** every control maps to an *incident finding* (controls-matrix), an
*attacker technique* (atlas-mapping), and a *prevention standard* (owasp-mapping).
