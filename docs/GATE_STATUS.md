# Gate status

## What the gate is

`gate/check.py` is a standard-library Python program that decides ACCEPT, REJECT or BLOCKED for one bounded case: the default TLS key-exchange groups that a PostgreSQL server uses (`DEFAULT_SSL_GROUPS` in `src/include/libpq/libpq.h`), checked against two OpenSSL library versions on one macOS machine. The harness applies and validates the patch, runs every check and derives the verdict from receipts, logs and `gate/policy.json`. No model is called, and no model assigns the verdict.

It is not a general patch gate and not a sandbox. It has run only the unmodified baseline and the two reviewed, hand-written fixtures in `gate/fixtures/`. No model-proposed patch has been gated.

## Results

All three cases ran under the same gate identity, `37aaa09d08a842caede30314fb0179f63befcdb1d77aec8bb14e94a2b7eb9b94` (SHA-256 over the hashes of `gate/check.py`, `gate/policy.json` and both fixtures).

| Run | Case | Verdict | Mandatory checks | Deciding observation |
|---|---|---|---|---|
| `baseline-03` | unmodified PostgreSQL | **REJECT** | 21: 19 PASS, 2 FAIL | OpenSSL 3.6.3 arm: the hybrid-first offer negotiated classical X25519, and the hybrid-only offer failed the handshake. The compiled default is `X25519:prime256v1` in both arms. |
| `uncond-03` | `hybrid-unconditional` fixture | **REJECT** | 21: 16 PASS, 1 FAIL, 4 NOT_RUN | OpenSSL 3.0 arm: the server did not start. Its log shows `FATAL: could not set group names specified in ssl_groups: passed invalid argument`. Its four handshake checks were not run. The OpenSSL 3.6.3 arm passed every check. |
| `versioned-03` | `hybrid-versioned` fixture | **ACCEPT** | 21: 21 PASS | Compiled default `X25519MLKEM768:X25519:prime256v1` with OpenSSL 3.6.3 and `X25519:prime256v1` with OpenSSL 3.0. Every handshake matched the policy, including the expected hybrid-only failure on OpenSSL 3.0. |

For these tested configurations, the `versioned-03` run verified hybrid post-quantum key exchange (X25519MLKEM768) on the OpenSSL 3.6.3 arm, with classical fallback, and classical compatibility on the OpenSSL 3.0 arm. Server authentication remains classical (the upstream RSA test certificate).

In every run where they were reached, both arms built, passed `make check` (`All 239 tests passed`) and passed the identity check. The identity check covers the compile-time header, the `otool -L` linkage, the libraries dyld loaded for the built `postgres`, and the libraries mapped into the running server. All six reference controls passed in each of the three runs. The integrity check passed in each run: gate, policy, client, libraries and the read-only PostgreSQL checkout were unchanged, and every process the run started was stopped.

Each verdict was recomputed from its observations and logs with `gate/check.py evaluate`, and the recomputation matched `verdict.json` byte for byte. `gate/check.py negative-control versioned-03` evaluated three in-memory synthetic copies of the ACCEPT run: a removed handshake receipt, an edited receipt group, and an edited log. All three came out BLOCKED, and the original files were unchanged.

Elapsed time per run was 269 s, 235 s and 236 s (`accounting.json`). These are single measurements on one machine, not performance claims.

### Earlier BLOCKED runs

`baseline-01` and `baseline-02` ran under an earlier gate identity (`a6dd9e12…`). Both stopped before any build, with BLOCKED, because two reference controls were unclassifiable. On a failed handshake, OpenSSL 3.6.3's `s_client` prints `Negotiated TLS1.3 group: <NULL>`, and the parser treated `<NULL>` as a group name. The parser now treats `<NULL>` as "no group", and it never counts as an observed group. That change produced the new gate identity, and all three cases were rerun under it. The two earlier runs are kept as recorded.

## Tested matrix

| Item | Tested |
|---|---|
| Machine | one Intel Mac, macOS 26.2 (x86_64), Apple clang 17.0.0, GNU make 3.81, bison 2.3, flex 2.6.4 |
| PostgreSQL | master (20devel) at commit `68af68ac691f2b57d29524a191debed9b0bdd558`, exported fresh with `git archive` for each arm; `configure --with-openssl --without-icu --without-readline` into a private prefix |
| OpenSSL ≥3.5 arm | OpenSSL 3.6.3 (Homebrew installation) |
| OpenSSL 3.0 arm | OpenSSL 3.0.22 (built from source) |
| Reference client | `openssl s_client` from OpenSSL 3.6.3, `-starttls postgres -tls1_3`, with the upstream test CA and peer name `common-name.pg-ssltest.test` |
| Server settings | `ssl=on`, upstream test certificate and key, loopback only; `ssl_groups` left unset so the compiled default is tested |

Exact versions, library hashes and loaded-library paths for each run are in `evidence/event/gate-runs/RUN_ID/environment.json`.

## Invocation

```
python3 gate/check.py selftest --pg-git PG_CHECKOUT
python3 gate/check.py run --case CASE --run-id RUN_ID --pg-git PG_CHECKOUT \
    --protected-pgdata EXISTING_CLUSTER_DIR --newer-prefix OPENSSL_3_5_PLUS_PREFIX \
    --old-prefix OPENSSL_3_0_PREFIX --client OPENSSL_3_5_PLUS_PREFIX/bin/openssl \
    --work-root WORK_DIR [--reference-run BASELINE_RUN_ID]
python3 gate/check.py evaluate RUN_ID
python3 gate/check.py negative-control RUN_ID
```

The cases are `baseline` (run IDs `baseline-NN`), `hybrid-unconditional` (`uncond-NN`) and `hybrid-versioned` (`versioned-NN`). Run IDs cannot be reused. Evidence goes to `evidence/event/gate-runs/RUN_ID/`. Sources, builds, installs, clusters, sockets and full logs go to `WORK_DIR/RUN_ID/` outside the repository. Fixture runs take `--reference-run` naming a baseline run with the same gate identity.

## Prerequisites

- macOS with Apple clang, GNU make, bison, flex, perl, lsof and otool on `/usr/bin:/bin:/usr/sbin:/sbin`
- A git checkout of PostgreSQL that contains the pinned commit. It is only read, with `git show` and `git archive`.
- Two OpenSSL installation prefixes, one 3.0.x and one 3.5 or newer, each with `include/`, `lib/libssl.dylib` and `bin/openssl`
- Free loopback ports: 55401–55402 (servers) and 55411–55416 (reference controls)

## What one run does

1. **Preflight:** checks the pin and the tracked files, both library prefixes (header version, library hashes, which libraries the prefix's own `openssl` actually loads), the reference client, the ports and the tools.
2. **Reference controls:** runs six `openssl s_server`/`s_client` pairs, each with a server limited to known groups. They confirm that the client reports the negotiated group in a form the parser reads, and that a group mismatch shows up as a handshake failure.
3. **Patch:** validates the fixture against the policy (one allowed file, edits only inside lines 137–141, allowlisted line forms and group names, exact context, no binary, mode, rename or path tricks), then applies it in memory.
4. **Source:** makes a fresh `git archive` export for each library arm, applies the patch and confirms that only the allowed file differs from the pin.
5. **Each arm** (OpenSSL ≥3.5, then 3.0):
   - `configure`, `make` and `make install` into a private prefix, then `make check`;
   - the identity check;
   - start a new cluster with `ssl=on`, run four handshakes through `openssl s_client -starttls postgres -tls1_3`, and stop the owned server.
6. **Integrity:** confirms that the gate, policy, client, libraries and the read-only PostgreSQL checkout are unchanged, and that every process the run started has stopped.

Child processes get only an allowlisted environment: `PATH`, `HOME`, `LANG`, `LC_ALL`, `TMPDIR` and `GIT_OPTIONAL_LOCKS`. API credentials are never passed to them. The gate refuses to start if any `DYLD_*` variable is set.

## Required handshake results

| Server arm | Client offer | Required |
|---|---|---|
| OpenSSL ≥3.5 | X25519MLKEM768:X25519:P-256 | success, X25519MLKEM768 observed |
| OpenSSL ≥3.5 | X25519MLKEM768 | success, X25519MLKEM768 observed |
| OpenSSL ≥3.5 | X25519 | success, X25519 observed |
| OpenSSL ≥3.5 | P-256 | success, P-256 observed |
| OpenSSL 3.0 | X25519MLKEM768:X25519:P-256 | success, X25519 or P-256 observed |
| OpenSSL 3.0 | X25519 | success, X25519 observed |
| OpenSSL 3.0 | P-256 | success, P-256 observed |
| OpenSSL 3.0 | X25519MLKEM768 | handshake failure (expected incompatibility; never a hybrid pass) |

The group is the one the client reports. A server log or configured string never counts as an observation.

## Verdict rules

The verdict rules are listed in `gate/policy.json` (`verdict_policy`):
- Problems with the environment or the reference controls give BLOCKED.
- A measured candidate failure gives REJECT.
- Only all-PASS gives ACCEPT.

A build or test failure counts against the candidate only when a baseline run with the same gate identity passed that check in the same arm. A startup failure also counts when the server log shows the `ssl_groups` error. A receipt with a missing log, a changed log, or fields that disagree with its re-parsed log blocks acceptance.

## Limitations

- One machine, one PostgreSQL commit, two library builds. No cross-machine, cross-path or performance claim.
- The fixtures are reviewed literal patches. The patch policy blocks path, mode, binary and out-of-region edits, but the build runs the candidate's code with the user's privileges. There is no protection against arbitrary executable patches.
- The TLS version is forced to 1.3 by the client. Server protocol settings are left at their defaults.
- Server authentication is classical (RSA test certificate). Only the key exchange is in scope.
- The six reference controls connect directly over TLS, because `s_server` does not speak the PostgreSQL SSL request. The PostgreSQL route is exercised by the server handshakes themselves.
- `lsof` port checks see only the current user's listeners.
- Receipt and hash consistency shows that the evidence was not edited after the run. It does not by itself prove authenticity or semantic correctness.
- The client's default group offer is not recorded.
- Published logs are sanitized: home and work paths are replaced with tokens, PEM blocks are removed, and long outputs are cut to their last lines as marked. Full logs stay outside the repository.

## Not implemented

Model-proposed patches, a repair loop, native SSL TAP tests, `shaar.py replay` and `shaar.py verify` (still stubs), and release sealing.

## Event-built versus prior work

Everything under `gate/`, this page and `evidence/event/gate-runs/` was written or generated during the event. PostgreSQL and OpenSSL are third-party dependencies: they were built only in a work directory outside the repository, and none of their source or binaries is included. Earlier measurements described in [PRIOR_WORK.md](PRIOR_WORK.md) are prior work and are not reused as results here.
