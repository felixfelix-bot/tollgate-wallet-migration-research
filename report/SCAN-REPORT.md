# Pre-publication secret scan — archive of the wallet-migration research tree

Run 2026-09-20, over this repository, **before its first push**. Every step is a
gate: any finding would have stopped the push.

Machine-readable result of the acceptance harness: [`archive-verify.json`](archive-verify.json).

> **Revision note (2026-09-20, same day).** §2 was corrected after review. The
> first version of this report claimed that all 18 gitleaks findings were matches
> on the literal word `REDACTED`. That was wrong: gitleaks was run with
> `--redact`, which replaces the matched span *in gitleaks' own output* with
> `REDACTED`. The findings were real matches on real (non-secret) values in the
> files. §2 now states what each finding actually is, and §5 and §6 add an
> independent second-pass re-verification. **The verdict (`CLEAN`) is unchanged**
> — the correction makes the reasoning match the evidence.

## 0. Identifiers

So this result can be re-checked rather than taken on trust:

| Artifact | `sha256` |
|---|---|
| detector, `~/.hermes/scripts/security/detect_wallet_secrets.py` | `fd6f35fd9feb837d272db9385d3c31e3ef85ba316c99a77ebeaf62ee94922fd8` |
| acceptance harness, `archive_verify.py` (the value recorded as `script_sha256` in `archive-verify.json`) | `ecd0d33fe1cb4db965e9582ba5def9a1d91932e9a3338313934464bec833707c` |
| tree scanned | the commit this report ships in, and its parent (pre-report) tree |

An earlier draft recorded `script_sha256` without saying *which* script; that
hash is the acceptance harness, **not** the detector. Both are given above.

## 1. Fleet wallet-material detector

`~/.hermes/scripts/security/detect_wallet_secrets.py` — the detector written for
exactly this leak class (a repo-configured `detect-secrets` gate cannot see a
BIP-39 seed: it has no mnemonic plugin). It flags a mnemonic only when every word
is in the BIP-39 English list **and** the checksum validates, and it exempts the
canonical all-zero test vector.

```
$ detect_wallet_secrets.py --dir .
note: experiments/local-mint/README.md:25 is the public BIP-39 test vector — allowed, not a secret
exit=0                                      # 0 findings, 1 advisory
```

The same detector was run over **every blob in the object store** (not just the
checked-out tree, so an added-then-removed blob cannot hide):

```
objects scanned: 357   findings: 0   advisory test vectors: 1
```

## 2. gitleaks 8.21.2 (independent second scanner) — all 18 findings classified

18 findings in the tree, and the same 18 across the full history. **None of them
is a secret.** Each was read back out of the file, byte for byte, and classified:

| gitleaks rule | What the match actually is | Why it is not a secret | Hits |
|---|---|---|---|
| `generic-api-key` | the **Nostr pubkey** of this wallet's own advertisement, e.g. `5cf21734cba4…4f7d8b4c7e46`, inside the kind-10021 metrics event the wallet logs | a **public** key, broadcast by design; it is the identity the router advertises, and it carries no signing authority over funds | 7 |
| `generic-api-key` | **Cashu keyset IDs**, e.g. `keyset=01182e5f…dfa40b8591` and `keyset=0184237e…ca4ca5ed96`, in `store-keyset-counters-injected.txt` | keyset IDs are public identifiers returned by a mint's `/v1/keysets`; they identify a keyset, they do not spend from it | 6 |
| `generic-api-key` | a **truncated Cashu token prefix**, `cashuBo2F0gaJh…`, in the `base token mint:` line of the fault logs | the log line itself elides the token: **8 base64 characters of payload** follow `cashuB`, then a literal `…`. A real v4-CBOR token is hundreds of characters; 8 cannot encode one | 4 |
| `generic-api-key` | the **secp256k1 generator point** `0279be66…f81798` (`g_pubkey`), in `patches/117-wallet-sidecar-tests.patch` | a published curve constant, used *deliberately* in that test because nobody holds the private key for G — the test asserts a token locked to G cannot be spent | 1 |

Locations, for re-checking:

- the pubkey: `experiments/baseline-gonuts/raw/{idle-*,startup-*}.log`,
  `{startup,payments}-logread-*.txt`
- the keyset IDs: `experiments/baseline-gonuts/raw/store-keyset-counters-injected.txt`
  (6 of its 18 lines)
- the truncated prefix: `experiments/baseline-gonuts/raw/{faults,superseded-faults}-*.log`
- the curve constant: `patches/117-wallet-sidecar-tests.patch`

All 18 are the generic-api-key entropy rule firing on public, non-secret values.
The word `REDACTED` does appear in `archive-verify.json`'s sibling gitleaks
reports, but only as the `--redact` **masking placeholder substituted into
gitleaks' output** — it is not what the files contain. (`--redact` *was* used, so
the raw reports committed here never contain a live value either way.)

## 3. Conservative needles, with positive controls

Over the tree **and** every blob in history, for both encodings of both leaked
classes plus generic key material:

| Needle | Hits |
|---|---|
| `cashu[AB][A-Za-z0-9_+/=-]{40,}` (Cashu bearer token) | **0** |
| `nsec1[02-9ac-hj-np-z]{20,}` (bech32 secret key) | **0** |
| `-----BEGIN [A-Z ]*PRIVATE KEY` | **0** |
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

## 5. Independent second-pass re-verification (2026-09-20)

A separate scan, written for this review and run over **all** objects including
unreachable ones (`git cat-file --batch-all-objects`), independent of the
harness above:

```
object inventory:  blobs 363   trees 222   commits 63
old tip 5ae015edb5            : absent
redacted head 855355c130…     : absent from this object store (see §6 — the
                                archive is a re-committed snapshot, not a clone)
```

Pattern results over those 363 blobs (`n` = hit count):

| Class | `n` | Reading |
|---|---|---|
| `cashu[AB]…{80,}` (full token) | 0 | — |
| `cashu[AB]…{10,}` (any token fragment ≥10 payload chars) | **0** | the longest fragment anywhere in the object store is the 8-char elision in §2 |
| `nsec1…`, `ncryptsec1…` | 0 | — |
| `xprv…`, `AKIA…`, `gh[pousr]_…`, long `Bearer …` | 0 | — |
| `(priv|secret|seed|mnemonic|nsec)…<64 hex>` | 0 | no hex private key next to a key-material keyword |
| `\b[0-9a-f]{64}\b` (bare) | 165 | sha256 digests: produced-binary hashes, backup `sha:`, Nostr event ids. No key material. |
| `npub1…` | 1 | a **public** key cited in `04-reports/nosigner-setup.md` |
| ≥12-word runs over the BIP-39 wordlist shape | 2 | the canonical public test vector (`abandon ×11 about`, in a `local-mint` README) and one prose false positive in `experiments/nucula-port/incremental/README.md`. No live mnemonic. |

**Result: no live secret of either leaked class, in the tree or anywhere in the
object store.**

## 6. Completeness and fidelity vs the source pull request

The archive exists to preserve the research tree, so the claim worth checking is
not only "clean" but "complete and faithful". Verified against the source:

- PR #397 changes **623** files; **285** of them are under
  `research/wallet-migration/` (the rest is unrelated drift on that branch:
  `packaging/`, `src/*`, `.secrets.baseline`, … — one reason the branch was not
  merged).
- Fetched the redacted branch head `855355c130004cbc91682f5f77354e059aaf3faf`
  into a **`--filter=blob:none` partial clone**, which downloads commits and trees
  only. Confirmed: **0 blobs fetched**, so no historical secret material was
  materialised on the scanning disk to perform this check.
- Comparing blob SHAs (content-addressed, so equality is exact):

| Result | Count |
|---|---|
| research files missing from the archive | **0** |
| research files byte-identical | **284** of 285 |
| research files whose content differs | **1** — `README.md` (the archive banner was prepended; intentional) |
| archive-only files | **3** — `ARCHIVE.md`, `report/SCAN-REPORT.md`, `report/archive-verify.json` |

## Verdict

```
RESULT: CLEAN
detector_sha256:  fd6f35fd9feb837d272db9385d3c31e3ef85ba316c99a77ebeaf62ee94922fd8
harness_sha256:   ecd0d33fe1cb4db965e9582ba5def9a1d91932e9a3338313934464bec833707c
```

**Standing caveat, unchanged by the scan:** anything that ever appeared in the
pre-redaction material — the generated BIP-39 seed, the Cashu bearer tokens — is
burned. Rotate, never reuse.
