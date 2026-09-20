# Wallet-migration research archive (not production code)

This repository is an **archive**: the complete tree of the TollGate
wallet-migration research programme, taken out of
`OpenTollGate/tollgate-module-basic-go` so the research survives without living
in the module's tree.

**Nothing here is production code, nothing here is built or shipped, and no pull
request should be opened against this repository.** The production-worthy parts
of this programme were promoted into the module as documentation instead:

| Promoted to the module (`docs/architecture/`) | What it is |
|---|---|
| `walletport-contract.md` | the acceptance contract a replacement Cashu wallet backend must satisfy |
| `wallet-integration-decision.md` | in-process wallet vs CDK sidecar, per target tier |
| `wallet-measurement-protocol.md` | metric catalogue, proposed blocker thresholds, mandatory fault-injection set, plus two current-wallet audit findings |

(Module PR: <https://github.com/OpenTollGate/tollgate-module-basic-go/pull/431>.
The programme's own pull request, #397, is closed — see below.)

## 1. What is in here

The tree of `research/wallet-migration/` from the module repository as of
2026-09-20 (285 files), with the history rewritten so the research directory is
the repository root (the 60 commits that touched these paths are preserved; the
programme's own task list and status files, `TASKS.md` and `STATUS.md`, are kept
for provenance).

- `00-context/` — how the module consumes `gonuts` today, and the coupling surface
- `01-candidates/` — per-candidate capability, licence, portability, footprint
- `02-method/` — the measurement protocol and metric set
- `03-baseline/` — measured baselines (gonuts and the candidates)
- `04-reports/` — the recommendation and the dissent kept alongside it
- `05-architecture/` — the integration decision
- `experiments/` — harnesses, sources and raw lab output behind every number
- `patches/` — patch bundles produced for the code changes the programme proposed

Treat everything here as unvetted research notes. Harnesses ran on lab hardware;
some raw logs are from throwaway mints and devices. Do not redistribute any of
this as part of the product, and do not assume a claim here has been reviewed.

## 2. Provenance, and the redaction you must know about

The module branch `research/wallet-migration` originally shipped **secret
material**: a generated BIP-39 seed and Cashu bearer tokens, inside the raw lab
logs under `experiments/`. That material was removed by a history rewrite and the
branch force-pushed.

- Redacted (current) branch head:
  `855355c130004cbc91682f5f77354e059aaf3faf`
- Pre-rewrite tip: `5ae015edb5` — **unreachable and must be treated as
  compromised.** A copy of that tip still contains a live seed and bearer tokens.

**Any key or token that ever appeared in this material is burned. Rotate it; do
not reuse it.** The redaction removed the literals, and the scans below confirm
that, but a secret that reached a public branch is a secret no longer.

## 3. Pre-publication secret scan (2026-09-20, before the first push)

Performed over *this* repository, in this order, before its first push. Every
step is a gate: a finding in any of them would have stopped the push. Raw reports
are committed here under `report/`.

| Check | Scope | Result |
|---|---|---|
| fleet wallet-material detector (`detect_wallet_secrets.py`: BIP-39 mnemonics validated by checksum + Cashu bearer tokens) | working tree, 284 files | **clean** — 0 findings; 1 advisory: the canonical all-zero BIP-39 test vector in a `local-mint` README (public example data, not a secret) |
| fleet wallet-material detector | **every blob in the object store, 357 blobs** | **clean** — 0 findings |
| gitleaks 8.21.2 | working tree | 18 findings — **all 18 are the `generic-api-key` entropy rule firing on public, non-secret values**: this wallet's own advertised Nostr **pubkey** (7), public Cashu **keyset IDs** (6), a **truncated** `cashuB…` token prefix of 8 base64 chars in the fault logs (4), and the secp256k1 **generator point G** used deliberately in a P2PK test (1). Classification per finding in `report/SCAN-REPORT.md` §2 |
| gitleaks 8.21.2 | full history, 61 commits | 18 findings, the same set, the same classification |
| conservative needles over the tree **and** every blob: `cashu[AB]…` (≥40 chars), `nsec1…`, `-----BEGIN [A-Z ]*PRIVATE KEY`, a ≥12-word run after `generated mnemonic:` | tree + all 357 blobs | **0 hits** — with the positive controls firing (both redaction markers are present — see `report/archive-verify.json` for the counts), so the scan demonstrably reads the regions the rewrite touched |
| pre-rewrite tip reachability | object store | `5ae015edb5` is **not present** in this repository |

> **Corrected 2026-09-20.** The first version of this table said the 18 gitleaks
> findings were "matches on the redaction placeholders themselves … no live
> value". The conclusion was right, the reasoning was not: gitleaks had been run
> with `--redact`, which substitutes `REDACTED` for the matched span **in
> gitleaks' output**, so the report was read back as if the files contained the
> word. Each finding was subsequently read out of its file and classified
> individually (see the row above and `report/SCAN-REPORT.md` §2), and an
> independent second pass re-scanned all objects (blobs 363 / trees 222 /
> commits 63) with zero live secrets of either leaked class. Verdict unchanged:
> `CLEAN`.

Acceptance harness: `report/archive-verify.json`
(`harness_sha256 = ecd0d33fe1cb4db965e9582ba5def9a1d91932e9a3338313934464bec833707c` —
this is the *harness*, not the detector; the detector's own hash is
`fd6f35fd9feb837d272db9385d3c31e3ef85ba316c99a77ebeaf62ee94922fd8`),
verdict `CLEAN`. It is conservative by construction: it fails closed if the
wordlist or the object enumeration is unavailable, asserts the needle set is
non-empty, and requires the object scan to have scanned more than zero objects.

## 4. Relationship to the module repository

- Module: <https://github.com/OpenTollGate/tollgate-module-basic-go>
- The study branch that used to carry this tree is closed; #397 was closed with a
  comment recording what was promoted and where the archive lives.
- No file in this repository is a dependency, package, test target or build input
  of the module. Nothing here should be merged into the module.
