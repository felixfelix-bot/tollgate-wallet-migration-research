# Pre-publication secret scan — archive of the wallet-migration research tree

Run 2026-09-20, over this repository, **before its first push**. Every step is a
gate: any finding would have stopped the push.

Machine-readable result of the acceptance harness: [`archive-verify.json`](archive-verify.json).

## 1. Fleet wallet-material detector

`~/.hermes/scripts/security/detect_wallet_secrets.py` — the detector written for
exactly this leak class (a repo-configured `detect-secrets` gate cannot see a
BIP-39 seed: it has no mnemonic plugin). It flags a mnemonic only when every word
is in the BIP-39 English list **and** the checksum validates, and it exempts the
canonical all-zero test vector.

```
$ detect_wallet_secrets.py --dir .          # working tree
note: experiments/local-mint/README.md:25 is the public BIP-39 test vector — allowed, not a secret
exit=0                                      # 284 files, 0 findings, 1 advisory
```

The same detector was run over **every blob in the object store** (not just the
checked-out tree, so an added-then-removed blob cannot hide):

```
objects scanned: 357   findings: 0   advisory test vectors: 1
```

## 2. gitleaks 8.21.2 (independent second scanner)

18 findings in the tree and the same 18 across the full history (61 commits).
**All 18 are matches on the redaction placeholders themselves**, i.e. on the
literal text the rewrite inserted where the secret used to be:

| Placeholder matched | Files |
|---|---|
| `"pubkey":"REDACTED"` | `experiments/baseline-gonuts/raw/{idle,startup,payments-logread,startup-logread}-*.{log,txt}` |
| `token mint: REDACTED` | `experiments/baseline-gonuts/raw/{faults,superseded-faults}-*.log` |
| `keyset=REDACTED` | `experiments/baseline-gonuts/raw/store-keyset-counters-injected.txt` |
| `g_pubkey = "REDACTED"` | `patches/117-wallet-sidecar-tests.patch` |

Each match is 8 characters long — the word `REDACTED` — and gitleaks' entropy
heuristics classify it as high-entropy noise. No finding carries a live value.
(`--redact` was used, so the raw reports never contain one either.)

## 3. Conservative needles, with positive controls

Over the tree **and** every blob in history, for both encodings of both leaked
classes plus generic key material:

| Needle | Hits |
|---|---|
| `cashu[AB][A-Za-z0-9_+/=-]{40,}` (Cashu bearer token) | **0** |
| `nsec1[02-9ac-hj-np-z]{20,}` (bech32 secret key) | **0** |
| `-----BEGIN[A-Z ]*PRIVATE KEY` | **0** |
| `generated mnemonic:[ \t]*` followed by a ≥12-word run | **0** |
| control: the seed redaction marker | present, both in the tree and in the blobs that carry it (exact counts in `archive-verify.json`) |
| control: the token redaction marker (same) | present, 90+ occurrences |

The controls matter: a needle set that silently matches nothing looks identical
to a clean repository. Both hooks firing proves the redacted regions were read.

## 4. Structural checks

- The pre-rewrite tip `5ae015edb5` is **not present** in this repository's object
  store (`git cat-file -e 5ae015edb5` fails).
- The object enumeration returned 357 blobs (> 0), so the "clean" verdict is not
  an empty-scan artifact.

## Verdict

```
RESULT: CLEAN
script_sha256: ecd0d33fe1cb4db965e9582ba5def9a1d91932e9a3338313934464bec833707c
```

**Standing caveat, unchanged by the scan:** anything that ever appeared in the
pre-redaction material — the generated BIP-39 seed, the Cashu bearer tokens — is
burned. Rotate, never reuse.
