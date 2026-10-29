# CLI status

`shaar.py` is a minimal recording skeleton built during the event. It sends one bounded request to the hosted Spark model for a small synthetic task, validates the reply locally and writes the evidence. **The deterministic gate, replay and artifact verification are not implemented.** No command produces a candidate patch or a gate verdict, and no model text is ever treated as one.

Drafted with an AI coding assistant; run and reviewed by the repository owner.

## What is implemented

| Command | Status | Exit codes |
|---|---|---|
| `python3 shaar.py run --run-id RUN_ID --config PATH` | Implemented: one real request, local validation, evidence written | 0 recording complete and valid; 1 request reserved or sent but recording incomplete; 3 refused before anything was sent |
| `python3 shaar.py run ... --preflight` | Implemented: prints the budget basis and checks; sends nothing, writes nothing | 0 checks passed; 3 refused |
| `python3 shaar.py replay RUN_ID` | **Not implemented.** Prints `INCOMPLETE: gate replay is not implemented` | 2, no network access |
| `python3 shaar.py verify RUN_ID` | **Not implemented.** Prints `INCOMPLETE: artifact verification is not implemented` | 2, no network access |
| `python3 shaar.py selftest` | Implemented: offline checks with synthetic fixtures; no key or network | 0 all passed; 1 a check failed |

Argument errors also exit 2.

`run` exits 0 and prints `RECORDING COMPLETE; GATE NOT IMPLEMENTED` only when all of these hold:

- a reply was recorded and passes local validation
- the reply has no refusal
- `finish_reason` is `stop`
- the returned model ID equals the requested `muse-spark-1.3`
- there is no usage or cost warning
- both evidence files were written

Otherwise it prints `RECORDING INCOMPLETE; GATE NOT IMPLEMENTED`, records each reason, and exits 1. Neither line is a gate outcome.

## The `run` task

A synthetic source of three labeled lines (S1 to S3, written for this CLI) is sent to `muse-spark-1.3` with a native `response_format` of type `json_schema`. The reply must be a constraint map: `{"constraints": [{"id", "statement", "sources"}]}`.

Local validation is applied to every reply, whatever the API accepted. It rejects:

- malformed JSON, including code-fenced replies
- missing required fields
- extra fields
- source references that are not S1, S2 or S3
- duplicate constraint IDs
- empty arrays and out-of-range string lengths

Source lines that no constraint cites are recorded as a note, not a rejection.

## Limits on `run`

- **Fixed route and model:** `https://api.meta.ai/v1/chat/completions` and `muse-spark-1.3`, with no override. The private config must record the same route and model, or the run is refused.
- **Key:** read from `MODEL_API_KEY` only. It is never printed or written, and no other credential is read.
- **Private config:** must be outside the repository. It uses the capability probe's private config format; `run` reads the Spark prices, documentation references, reasoning-billing basis, maximum-output parameter, the billing-console balance observed before probing, and the final-run reserve.
- **Size limits:** the request body is at most 16 KiB, and requested output is 4096 units. Reasoning must be recorded as either not billed, or billed as output and capped by that parameter; otherwise the run is refused.
- **Allowance:** before sending, the request's allowance is computed as (request-body bytes + 512) × input price + 4096 × output price. This assumes at least one byte of request body per input unit. It is an allowance, not a provider-guaranteed billing cap.
- **Budget:** the allowance must fit within the lower of a $1.00 subcap and the development headroom: the billing-console balance observed before probing, minus the final-run reserve, minus every allowance already committed by the capability probe (read from its ledger).
- **One run:** this revision records exactly one run. `run` refuses if any run directory already exists, and never overwrites one.
- **Transport:** no retries, a 120-second timeout, a 1 MB response limit, TLS certificate validation left on, and redirects refused, never followed.
- **Warnings:** missing, negative or out-of-allowance usage, or reasoning units on a model recorded as non-reasoning, make the recording incomplete.
- **Order of writes:** the run directory is reserved exclusively, and `accounting.json` is written with `"sent": "in_flight"` before the request is sent. A request that times out, fails, or returns a malformed reply therefore stays accounted for at its full allowance. A private append-only note next to the private config is written before the request and updated after it, so an attempt remains accounted for even if the evidence write fails. After the request is sent, any error in processing the reply is caught and recorded as an incomplete run; no exception escapes.

## Evidence layout

| Path | Contents |
|---|---|
| `evidence/prior/` | Reserved for evidence of work done before the event. It is not present in this repository; prior work is described in [PRIOR_WORK.md](PRIOR_WORK.md). Nothing in it is an event result. |
| `evidence/event/capability-probe/` | The capability probe's ledger, frozen as accepted. Not written by `shaar.py`. |
| `evidence/event/runs/RUN_ID/record.json` | Format `shaar-run-record/1`. Contents are listed below. |
| `evidence/event/runs/RUN_ID/accounting.json` | Format `shaar-run-accounting/1`. Contents are listed below. |

`record.json` contains:

- `task`: the task ID, the synthetic label, the source IDs and the source text
- `request`: the fixed endpoint and the request body (no headers)
- `model`: the model ID requested and the model ID returned
- `transport`: the HTTP status, whether the request was sent (`yes`, `no` or `unknown`), and the outcome
- `response`: the visible reply, finish reason, numeric usage, and the names (not contents) of message fields that were not stored
- `error`: a sanitized error, if there was one
- `validation`: the local validation result
- `status`: recording `complete` or `incomplete`, with `incomplete_reasons` listing why; candidate `pending` (not implemented); gate `not_implemented`, with `gate_verdict` set to `null`; replay `not_implemented`

`accounting.json` contains:

- the allowance and its basis, with the pricing and reasoning documentation references
- whether the request was sent
- the usage estimate, or `UNKNOWN`
- billing `PENDING`
- the latency
- any warnings
- the budget before the request, and the headroom after it

Timing and cost live only in `accounting.json`, so `record.json` contains no timestamps.

Both files are canonical JSON: UTF-8, keys sorted, two-space indent, no NaN or infinity, ending in a newline.

Neither file contains:

- credentials or authorization headers
- hidden reasoning text
- raw responses
- the private config
- personal paths or account identifiers

No `verdict.json` or `failure.json` is produced; those belong to the gate, which is not implemented.

## Not implemented

- The PostgreSQL/OpenSSL gate: builds, tests, handshake checks and ACCEPT/REJECT verdicts.
- Candidate patch generation and application.
- Replay of a gate decision.
- Artifact verification. The planned contract is consistency of hashes, references and source citations across a run's files. It will not execute tests, and it will not prove authenticity.
- Wonder requests, tool calls and any other model role.

## Clean-clone invocation

No key or network is needed for these commands:

```bash
git clone https://github.com/dguchie/shaar.git
cd shaar
python3 shaar.py --help
python3 shaar.py selftest           # exit 0, ends with "SELFTEST n/n PASS"
python3 shaar.py replay any-run     # exit 2, INCOMPLETE
python3 shaar.py verify any-run     # exit 2, INCOMPLETE
```

`run` also needs `MODEL_API_KEY` and a private config, and refuses because this revision's one run is already recorded.
