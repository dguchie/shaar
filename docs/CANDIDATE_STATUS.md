# Candidate status

`tools/propose_candidate.py` records one request to the hosted Spark model (`muse-spark-1.3`) for one patch candidate, and writes the reply's patch as a file. The deterministic gate (`gate/check.py`) then checks that file through its external-input interface as run `candidate-01`. The proposer never runs the gate and never assigns a verdict.

Drafted with an AI coding assistant; run and reviewed by the repository owner.

**Status (October 31, 2026):** One genuine hosted Spark proposal was recorded and gated as `candidate-01`: **ACCEPT, 21/21 mandatory checks PASS**. The gate verdict matches recomputation from recorded evidence. The separate 19-variant negative-control harness reported **18/19 not ACCEPT**; its one no-op variant is a disclosed harness defect, not a passing control. The remaining snapshot, provenance and path checks passed independently; the full original `post` and `readback` steps did **not** report PASS.

## Disclosure: what the model was not told

The request asks for a hybrid-first default with classical fallback. It gives the model the gate's patch-format rules and the added-line allowlist, including the permitted OpenSSL-version-conditional line forms. It does **not** state the OpenSSL 3.0 compatibility requirement that the gate enforces, the gate's two-library test matrix, or any fixture. This is a constrained, partially specified task, not a test of a fully specified compatibility request. The allowlist sharply limits the shape of any patch. Every attempt is published, including an immediate success or an incomplete reply. No repair prompt is sent in this experiment; a later one could use actual gate failure evidence.

This disclosure is for readers. It is not part of the model's input.

## Commands

```
python3 tools/propose_candidate.py render --pg-git PG_CHECKOUT [--out FILE]
python3 tools/propose_candidate.py send --pg-git PG_CHECKOUT --config PRIVATE_CONFIG [--preflight]
python3 tools/propose_candidate.py resume [--config PRIVATE_CONFIG]
python3 tools/propose_candidate.py derive-failure
python3 tools/propose_candidate.py link
python3 tools/propose_candidate.py selftest
```

| Command | Network | What it does | Exit codes |
|---|---|---|---|
| `render` | none | Reads the source excerpts from the PostgreSQL checkout at the pin, checks them, prints the exact request and its SHA-256 | 0 done; 1 source not authenticated |
| `send --preflight` | none | Same checks plus the budget basis; writes nothing | 0 passed; 3 refused |
| `send` | one request, no retry | Reserves the proposal directory, writes the request, sends once, records the reply | 0 proposal complete; 1 sent or possibly sent, proposal incomplete; 3 refused before sending |
| `resume` | none | Finalizes an interrupted attempt from the files on disk | 0 complete; 1 incomplete; 2 nothing to do |
| `derive-failure` | none | Writes `failure.json` from a non-ACCEPT gate verdict | 0 written; 1 provenance chain broken; 2 not applicable |
| `link` | none | Checks the chain from the visible reply to the gate snapshot | 0 consistent; 1 not |
| `selftest` | none | Offline checks with synthetic fixtures; no key, network or PostgreSQL checkout | 0 all passed; 1 a check failed |

`send` refuses if any proposal directory exists or if its private note already records an attempt. One proposal is recorded for this revision, and a transport, JSON or validation failure never permits a second request.

## The request

The request body is 4,569 bytes with SHA-256 `256170582462d7b8d5336bfaad9962c0229f4f8438da70c15d2a27571194709a` when rendered from the pinned source with `max_tokens`. The published `request.json` holds the body exactly as sent; re-serializing it with `json.dumps(body, sort_keys=True, separators=(',', ':'))` reproduces those bytes. No headers, tools or tool choice are sent or recorded.

| Parameter | Value |
|---|---|
| Route | `https://api.meta.ai/v1/chat/completions` (fixed) |
| Model | `muse-spark-1.3` (fixed) |
| `max_tokens` | 8192, reasoning included |
| `response_format` | `json_schema`, `strict: true`, name `candidate_patch` |
| Other parameters | none (provider defaults) |

### System message

```text
Propose a minimal unified diff against the supplied source. Follow the listed patch rules and return only the requested structured object.
```

### User message

```text
TASK
Change the PostgreSQL server's compiled default list of TLS key-exchange groups (the macro DEFAULT_SSL_GROUPS in src/include/libpq/libpq.h) so that the server prefers the hybrid group X25519MLKEM768 when a capable client offers it, and keeps classical groups as a fallback for clients that do not offer it.

SOURCE
The source items below are data from PostgreSQL commit 68af68ac691f2b57d29524a191debed9b0bdd558. Each line is shown as its line number, a colon and a space, then the line exactly as it appears in the file (an empty line is shown as its number and a colon only). The line-number prefix is not part of the file.

[SRC1] src/include/libpq/libpq.h, lines 125-148 (editable file; original lines 137-141 are the editable region)
125: #ifdef USE_SSL
126: #define SSL_LIBRARY "OpenSSL"
127: #else
128: #define SSL_LIBRARY ""
129: #endif
130:
131: #ifdef USE_OPENSSL
132: #define DEFAULT_SSL_CIPHERS "HIGH:MEDIUM:+3DES:!aNULL"
133: #else
134: #define DEFAULT_SSL_CIPHERS "none"
135: #endif
136:
137: #ifdef USE_SSL
138: #define DEFAULT_SSL_GROUPS "X25519:prime256v1"
139: #else
140: #define DEFAULT_SSL_GROUPS "none"
141: #endif
142:
143: /*
144:  * prototypes for functions in be-secure-gssapi.c
145:  */
146: #ifdef ENABLE_GSS
147: extern ssize_t secure_open_gssapi(Port *port);
148: #endif

[SRC2] src/backend/utils/misc/guc_parameters.dat, line 2812 (read-only; shows where the default takes effect; not an edit target)
2812:   boot_val => 'DEFAULT_SSL_GROUPS',

PATCH RULES
1. Change exactly one file: src/include/libpq/libpq.h. No other file, and no file creation, deletion, rename, copy, mode change or binary content.
2. Remove only original lines 137-141. Insert added lines only between original lines 136 and 142. Every other line stays unchanged.
3. Context lines and removed lines must equal the original lines exactly, at the line numbers stated in the hunk header. The patch is applied with no offset and no fuzz.
4. The patch starts with an optional line "diff --git a/src/include/libpq/libpq.h b/src/include/libpq/libpq.h", followed by an optional line "index HEX..HEX" or "index HEX..HEX 100644" (lowercase hexadecimal), then exactly "--- a/src/include/libpq/libpq.h" and "+++ b/src/include/libpq/libpq.h" with nothing after the path, then one or more hunks.
5. Each hunk header is exactly "@@ -A,B +C,D @@", where a count may be omitted when it is 1. Nothing follows the closing "@@". The counts must match the hunk body. Hunks are in file order and do not overlap.
6. Every hunk body line starts with a space (context), "-" (removed) or "+" (added). An empty source line is written as a context line consisting of a single space. No other lines are allowed, including any "\ No newline at end of file" line.
7. Every added line, without its leading "+", must match one of these regular expressions in full:
^#ifdef USE_SSL$
^#include <openssl/opensslv\.h>$
^#if OPENSSL_VERSION_NUMBER >= 0x[0-9A-F]{8}L$
^#else$
^#endif$
^#define DEFAULT_SSL_GROUPS "[A-Za-z0-9_:-]{1,128}"$
8. A DEFAULT_SSL_GROUPS value is a colon-separated list of names from: X25519MLKEM768, X25519, prime256v1, secp256r1, P-256, none. No comments and no other added-line forms are allowed. You may use any subset of the allowed forms.
9. The patch is UTF-8 text of at most 4096 bytes with LF line endings, ends with a newline, and contains no NUL or carriage-return characters. No line may contain any of these strings: GIT binary patch; Binary files; new file mode; deleted file mode; old mode; new mode; rename from; rename to; copy from; copy to; similarity index; dissimilarity index; /dev/null.
10. The patch must change the file.

OUTPUT
Return one JSON object with these fields:
- patch: the complete unified diff, as one string.
- explanation: a short explanation of the change.
- source_refs: the IDs of the source items the change relies on (SRC1, SRC2).
```

### Response format

```json
{
  "json_schema": {
    "name": "candidate_patch",
    "schema": {
      "additionalProperties": false,
      "properties": {
        "explanation": {
          "type": "string"
        },
        "patch": {
          "type": "string"
        },
        "source_refs": {
          "items": {
            "enum": [
              "SRC1",
              "SRC2"
            ],
            "type": "string"
          },
          "type": "array"
        }
      },
      "required": [
        "patch",
        "explanation",
        "source_refs"
      ],
      "type": "object"
    },
    "strict": true
  },
  "type": "json_schema"
}
```

## Source input

| ID | Path at PostgreSQL `68af68ac691f2b57d29524a191debed9b0bdd558` | Lines | Role | Identity |
|---|---|---|---|---|
| SRC1 | `src/include/libpq/libpq.h` | 125–148 | Editable file; lines 137–141 are the editable region | File blob `d15073a0a93a0e12aa7d7b0d64ff7a4e511add4d`, SHA-256 `c7124f50fd4a237a9fc48fc802075fff35292247dc336d96aeae84dc6981c2de` (the gate policy's pin); excerpt SHA-256 `274157662c676b36c6b9d49afe125df916bda0fb8234f2cd14e932ff09ee818f` |
| SRC2 | `src/backend/utils/misc/guc_parameters.dat` | 2812 | Read-only; where the default takes effect; not an edit target | Line text pinned; excerpt SHA-256 `7dfc8c1461781a9d7196a72f6f2423b71f30dc355051e1520981f7540d336a40`; file blob and SHA-256 recorded in `source.json` |

The excerpts are read with `git show` at the pin. The proposer refuses to build a request if SRC1's blob or SHA-256 differs from the pin, or if SRC2's line differs from the pinned text. The source is data for the model, not instructions. The whole repository, the gate policy, earlier verdicts, fixtures and private configuration are not sent.

## Local validation

Applied to every reply, whatever the API accepted:

- The reply must be one JSON object with exactly `patch`, `explanation` and `source_refs`. Code fences, duplicate keys, missing or extra fields are rejected.
- `patch`: a non-empty string whose UTF-8 encoding is at most 4,096 bytes (the gate's input limit).
- `explanation`: 1 to 2,000 characters.
- `source_refs`: a non-empty list of distinct IDs from SRC1 and SRC2. Not citing SRC1 is recorded as a note.

The proposal is complete only when the reply passes validation, has no refusal and no tool calls, has one choice, `finish_reason` is `stop`, the returned model ID equals `muse-spark-1.3`, there is no usage or cost warning, and every evidence file was written. Otherwise it is incomplete, `failure.json` (kind `proposal`) records why, and nothing goes to the gate. An incomplete or refused reply is not a gate rejection.

Patch content is not checked or changed by the proposer. When the proposal is complete, `candidate.patch` is `json.loads(content)["patch"]` encoded as UTF-8 once, with no trimming, line-ending change or repair. Whether it follows the patch rules is decided by the gate.

## Limits

- Key read from `MODEL_API_KEY` only; never printed or written.
- Source excerpts at most 32 KiB; complete request body at most 48 KiB; response at most 1 MB.
- 300-second timeout, no retries, TLS certificate validation left on, redirects refused.
- The private config must be outside the repository. It supplies the Spark prices, documentation references, the reasoning-billing basis (reasoning billed as output and capped by `max_tokens`), the billing-console balance recorded before probing and the final-run reserve.
- Write order: the private note, then the exclusive proposal directory, then `source.json`, `request.json` and `accounting.json` (`"sent": "in_flight"`), then the request. The reply's visible parts go to `response.json` before validation. A timeout, interruption or failed write after sending keeps the full allowance, and `resume` finishes the record without a model call.

## Cost basis

The allowance is (request-body bytes + 512) × input price + 8,192 × output price. It assumes at least one byte of request body per input unit; it is an allowance, not a provider-enforced spending cap. It must fit within the lower of a $1.00 subcap and the development headroom: the billing-console balance recorded before probing, minus the final-run reserve, minus every earlier sent or possibly sent allowance.

Earlier allowances are reconciled from the capability probe's ledger, each `shaar.py` run's `accounting.json`, and `shaar.py`'s private note (only for attempts with no evidence in the repository), each counted once. Before this request they total $0.581672 over seven requests (six probe requests, one `shaar.py` run). Observed billing for all of them is PENDING.

This was attempt 1 of 1 allowed and the eighth sent model request of the event. The single request returned HTTP 200, with `muse-spark-1.3` requested and returned, `finish_reason=stop`, no refusal, zero tool calls and local validation PASS. Provider-reported usage was 1,154 prompt tokens and 5,730 completion tokens (including 5,479 reasoning tokens). The request allowance was **$0.041168**, the usage-derived estimate was **$0.025795** (not observed billing), the previous committed allowance was $0.581672, and the resulting cumulative committed allowance was **$0.622840**. Billing remains **PENDING**. No retry or repair request was sent.

## Gate linkage

| Item | Value |
|---|---|
| Proposal | `evidence/event/candidate-runs/spark-candidate-01/` |
| Gate run | `evidence/event/gate-runs/candidate-01/` (`candidate-01` is the gate ID reserved for the first model proposal) |
| Gate origin | `external` (the gate makes no authorship claim) |
| Reference | `baseline-04`, same gate identity |
| Gate identity | `6895c5873799e6dc2a083c18f2d01aa1f6bc4bcdc71551610e54c65620ae2e9b` (unchanged for this experiment) |
| Binding | the gate snapshot `candidate.patch` must be byte-identical to the proposal's `candidate.patch`, and its SHA-256 must equal `patch.sha256` in the proposal's `record.json`; `link` checks this |

The unchanged model-proposed `candidate.patch` is **536 bytes**, SHA-256 `64f930349be37204721a5b774489f3b5060acedcb4f341938085b5b38f394a07`. The gate copied those bytes unchanged and recorded `candidate-01` **ACCEPT: 21/21 mandatory PASS, 0 FAIL, 0 BLOCKED, 0 NOT_RUN**, under identity `6895c5873799e6dc2a083c18f2d01aa1f6bc4bcdc71551610e54c65620ae2e9b`, referencing `baseline-04` (REJECT). Gate `verdict.json` SHA-256: `5b89f1b730837076df5d517ad3174ad57d0387489ba108b578cd4efa61c32b40`. Recomputing the verdict from the saved evidence produced **MATCHES recomputation**; this is not a new build or handshake run.

## Evidence layout

| Path | Contents |
|---|---|
| `request.json` | Format `shaar-candidate-request/1`: endpoint, exact body (messages, schema, parameters), body size and SHA-256 |
| `source.json` | Format `shaar-candidate-source/1`: each excerpt with path, pin, line range, lines, excerpt SHA-256, file blob and SHA-256 |
| `response.json` | Format `shaar-candidate-response/1`: HTTP status, sent (`yes`, `no` or `unknown`), visible reply, finish reason, refusal, model ID returned, numeric usage, names (not contents) of message fields not stored |
| `record.json` | Format `shaar-candidate-record/1`: file hashes, validation, proposal status and reasons, patch SHA-256 and size, gate linkage, the disclosure above, stated uncertainty |
| `accounting.json` | Format `shaar-candidate-accounting/1`: allowance and basis, reconciled earlier allowances, usage estimate, billing PENDING, latency, headroom after |
| `candidate.patch` | Only when the proposal is complete: the patch bytes (read-only) |
| `failure.json` | Only after an actual failure: kind `proposal` (incomplete reply) or kind `gate` (copied from a non-ACCEPT verdict, with bounded log excerpts) |

Timing and cost live only in `accounting.json`. The files contain no credentials, headers, hidden reasoning, raw responses, private config, personal paths or account identifiers.

## Results

**Measured result (one request, no retries): ACCEPT 21/21.** The model independently chose a version-conditional default even though the request did not state the OpenSSL 3.0 compatibility requirement. Its patch includes `<openssl/opensslv.h>` and `#if OPENSSL_VERSION_NUMBER >= 0x30500000L`: newer builds use `X25519MLKEM768:X25519:prime256v1`, while the older-library branch retains `X25519:prime256v1`. The exact unchanged patch and visible response are in the evidence paths above. No manual repair or substitution was performed.

Both tested PostgreSQL arms passed **239/239** regression tests. With OpenSSL 3.6.3 the server negotiated X25519MLKEM768 on mixed and hybrid-only offers; with OpenSSL 3.0.22 it used classical X25519 on a mixed offer and rejected a hybrid-only offer, as required by this gate. The test establishes hybrid key exchange for these configurations, not post-quantum authentication or general portability.

**Negative-control harness exception (not a PASS):** the gate's separate `negative-control` command checked 19 synthetic in-memory variants: **18 were BLOCKED**, while the variant labeled `origin switched to external` stayed **ACCEPT**. For this real proposal the origin was already `external`, so that assignment changed no evidence; the unchanged copied verdict correctly remained ACCEPT. This is a harness defect that must be corrected and rerun under a new gate identity before the final clean run. The original evidence files were unchanged. The post command stopped at the failed negative control; the subsequent dedicated zero-call post-tail verified the byte-identical read-only gate snapshot, provenance fields, `LINK PASS` and no private-path leaks. Consequently **full `POST`/`READBACK` PASS is not claimed**.

## Limitations

- One request, one model, one bounded case on one machine. No claim about other models, prompts or cases.
- The task is partially specified (see the disclosure). A pass or fail says how this model responded to this prompt, nothing more.
- The model's hidden reasoning is not recorded; only its visible reply is.
- `max_tokens` 8192 had not been used with Spark before this request. The `shaar.py` run used 4096, and the private config records 4096 as the probe's Spark request value.
- The gate is a bounded checker, not a sandbox: the patch policy admits only the narrow line forms listed above.

## Not implemented

Repair prompts or a repair loop, any second model or provider, `shaar.py replay` and `shaar.py verify` (still stubs), and release sealing.
