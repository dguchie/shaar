# Prior work

Everything on this page was done by [@dguchie](https://github.com/dguchie) before Oct 27, 2026, the start of the hackathon building period. It is background for the event work. None of it is code in this repository, and none of these numbers is presented as an event result unless it is measured again in a recorded event run.

## 1. PostgreSQL default key exchange

Checked on Linux and macOS against PostgreSQL master (20devel):

| Setup | Result |
|---|---|
| Default server configuration; client with OpenSSL 3.5 / 3.6 defaults | Negotiated `X25519` (classical, not post-quantum) |
| Client offering only `X25519MLKEM768` | Handshake failure |
| `ssl_groups = 'X25519MLKEM768:X25519:prime256v1'` | Negotiated `X25519MLKEM768`; a P-256 client was still served (Linux run) |

Source of the default: in PostgreSQL 18 and on master, `ssl_groups` defaults to `"X25519:prime256v1"` (`DEFAULT_SSL_GROUPS` in `src/include/libpq/libpq.h` on master). PostgreSQL 17 pins `prime256v1` through `SSL_CTX_set_tmp_ecdh`.

## 2. OpenSSL 3.0 reproduction

| OpenSSL | Attempt | Result |
|---|---|---|
| 3.0.22 (built from source) | Set the group `X25519MLKEM768` | Rejected ("cannot be set") |
| 3.0.13 | Use the `?` group-name prefix | Rejected |

A group list that names `X25519MLKEM768` therefore cannot be applied as-is on OpenSSL 3.0.

## 3. PostgreSQL regression and reproducible-build measurements

Measured on the PostgreSQL source revision listed in the table:

| Measurement | Result |
|---|---|
| `make check` on the existing build (linked against OpenSSL 3.6.3) | 239/239 tests passed in 31.63 s |
| Two isolated builds | 143.34 s and 142.39 s; 1,337 objects each; identical manifests |
| Backend SHA-256 | `3c12cbf41a0edaef43d509f4fb0aa5c422b5b6c2270130ef8cf27558c6aa0fee` |
| PostgreSQL source revision | `68af68ac691f2b57d29524a191debed9b0bdd558` |

## 4. shaar-lite proof of concept

[github.com/dguchie/shaar-lite](https://github.com/dguchie/shaar-lite), public since Oct 14, 2026, Apache-2.0, cited here at commit `69a3df9fcfb575a1ff0afde0dfecd1467c06710d` (head of `main` when this baseline was written). It is a separate repository; nothing from it is copied here.

Scope: one C file, one rule. A deterministic detector finds a classical-only TLS group list pinned in C code. A model proposes a corrected file. A gate with no model in it decides, using five checks:

| Gate | Check |
|---|---|
| G1 | Patch applies with an exact context match |
| G2 | Compiles with `-Wall -Wextra -Werror` against OpenSSL 3.5 or newer |
| G3 | Two builds from different directories produce the same SHA-256 |
| G4 | A live server built from the patch negotiates `X25519MLKEM768` with a reference OpenSSL client |
| G5 | A re-scan finds no classical-only group pinning left |

Five deliberately wrong ("sabotaged") patches, all rejected:

| Patch | What it does | First failed gate |
|---|---|---|
| `m1_comment_only` | Adds a comment claiming post-quantum readiness; behavior unchanged | G4 |
| `m2_classical_upgrade` | Swaps in X25519 and calls it modern; still not post-quantum | G4 |
| `m3_fake_telemetry` | Server logs claim `X25519MLKEM768`; the reference client observes P-256 | G4 |
| `m4_wrong_api` | Calls a non-existent OpenSSL function | G2 |
| `m5_stale_base` | Written against a different version of the file | G1 |

Other recorded results: the unpatched baseline was rejected at G4; a human-written reference patch was accepted; a patch proposed by Muse Spark 1.3 (`X25519MLKEM768:P-256`) was accepted. Decisions matched on macOS (Intel, Apple clang 17, OpenSSL 3.6.3) and Linux x86_64 (OpenSSL 3.5.9, gcc 13.3 and clang 18.1). Replays matched their recorded verdict hashes with zero model calls. The model's patch left an old comment that is now stale; the gate does not check comments.

## 5. Design and planning

Design and planning notes were prepared before Oct 27 and are not part of this repository.
