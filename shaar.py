#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Sha'ar event CLI (minimal recording skeleton).

Records one bounded, locally validated reply from the hosted Spark model for
a small synthetic source-to-constraint-map task. The deterministic gate,
replay and artifact verification are NOT implemented in this revision.

Commands:
  python3 shaar.py run --run-id RUN_ID --config PATH [--preflight]
  python3 shaar.py replay RUN_ID
  python3 shaar.py verify RUN_ID
  python3 shaar.py selftest

Exit codes:
  0  run: recording complete and valid; selftest: all checks passed;
     run --preflight: checks passed and nothing was sent
  1  run: a request was reserved or sent but the recording is not complete
     (invalid reply, warning, HTTP or transport error, write failure);
     selftest: a check failed
  2  replay / verify: not implemented (also argument errors)
  3  run: refused before anything was sent

Standard library only; Python 3.9+. The API key is read from MODEL_API_KEY
and is never printed or written. No other credential is read.
See docs/CLI_STATUS.md for the full contract.

Drafted with an AI coding assistant; run and reviewed by the repository owner.
Some routines are adapted from tools/capability_probe.py (also event-built);
that file is not imported.
"""

import argparse
import http.client
import io
import json
import math
import os
import re
import socket
import ssl
import sys
import tempfile
import time
import urllib.error
import urllib.request
from contextlib import redirect_stdout
from pathlib import Path

REPO = Path(__file__).resolve().parent
RUNS_DIR = REPO / "evidence" / "event" / "runs"
PROBE_LEDGER = REPO / "evidence" / "event" / "capability-probe" / "probe-results.json"
PROBE_LEDGER_FORMAT = "shaar-capability-probe-results/1"

RECORD_FORMAT = "shaar-run-record/1"
ACCOUNTING_FORMAT = "shaar-run-accounting/1"
TASK_ID = "source-constraint-map/1"

ENDPOINT = "https://api.meta.ai/v1/chat/completions"  # fixed; no override
MODEL = "muse-spark-1.3"                               # fixed; no override
KEY_ENV = "MODEL_API_KEY"
MAX_OUT = 4096                 # requested output units, reasoning included
MAX_REQUEST_BYTES = 16 * 1024
SUBCAP_USD = 1.0               # spend allowance for this CLI's runs
INPUT_MARGIN = 512             # input allowance for message framing
HTTP_TIMEOUT_S = 120
MAX_RESPONSE_BYTES = 1_000_000
RUN_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}")
NOTE_NAME = "shaar-run-attempts.jsonl"   # private note, kept next to the config

INPUT_ASSUMPTION = (f"input units bounded by request-body bytes plus {INPUT_MARGIN}, assuming at least one "
                    "byte of body per input unit; this is an allowance, not a provider billing cap")

EXIT_OK, EXIT_INCOMPLETE_RUN, EXIT_NOT_IMPLEMENTED, EXIT_REFUSED = 0, 1, 2, 3

# ---------------------------------------------------------------------------
# Task: synthetic source lines -> constraint map
# ---------------------------------------------------------------------------

SOURCE_LINES = {
    "S1": "A patch may change only files listed in the request manifest.",
    "S2": "An accepted patch must leave every existing test passing.",
    "S3": "A patch that changes more than 200 lines is rejected without review.",
}
SOURCE_LABEL = "[SYNTHETIC SOURCE: written for this CLI; not taken from any real project]"
SOURCE_TEXT = SOURCE_LABEL + "\n" + "\n".join(f"{k}: {v}" for k, v in sorted(SOURCE_LINES.items()))

API_SCHEMA = {
    "type": "object", "additionalProperties": False, "required": ["constraints"],
    "properties": {"constraints": {"type": "array", "items": {
        "type": "object", "additionalProperties": False, "required": ["id", "statement", "sources"],
        "properties": {
            "id": {"type": "string"},
            "statement": {"type": "string"},
            "sources": {"type": "array", "items": {"type": "string", "enum": sorted(SOURCE_LINES)}},
        }}}},
}


def build_body(max_out_param):
    return {
        "model": MODEL,
        "messages": [
            {"role": "system", "content": "You extract constraints from source text."},
            {"role": "user", "content": SOURCE_TEXT + "\n\nReturn one constraint per rule. Each constraint "
             "has a short id, a statement, and the IDs of the source lines (S1, S2, S3) it comes from."},
        ],
        max_out_param: MAX_OUT,
        "response_format": {"type": "json_schema", "json_schema": {
            "name": "constraint_map", "strict": True, "schema": API_SCHEMA}},
    }


def validate_constraint_map(text):
    """Local validation. Returns {"ok", "errors", "notes"}; never trusts the model's own claims."""
    out = {"ok": False, "errors": [], "notes": []}
    if not isinstance(text, str) or not text.strip():
        out["errors"].append("empty reply")
        return out
    try:
        obj = json.loads(text)
    except ValueError as e:
        out["errors"].append(f"invalid JSON: {getattr(e, 'msg', str(e))}")
        return out
    errs = out["errors"]
    if not isinstance(obj, dict):
        errs.append("$: expected object")
        return out
    for k in obj:
        if k != "constraints":
            errs.append(f"$: unexpected field '{k}'")
    if "constraints" not in obj:
        errs.append("$: missing required field 'constraints'")
        return out
    cs = obj["constraints"]
    if not isinstance(cs, list) or not cs:
        errs.append("$.constraints: expected a non-empty array")
        return out
    if len(cs) > 20:
        errs.append("$.constraints: more than 20 items")
    seen = set()
    for i, c in enumerate(cs):
        p = f"$.constraints[{i}]"
        if not isinstance(c, dict):
            errs.append(f"{p}: expected object")
            continue
        for k in c:
            if k not in ("id", "statement", "sources"):
                errs.append(f"{p}: unexpected field '{k}'")
        for k in ("id", "statement", "sources"):
            if k not in c:
                errs.append(f"{p}: missing required field '{k}'")
        cid = c.get("id")
        if "id" in c:
            if not isinstance(cid, str) or not 1 <= len(cid) <= 20:
                errs.append(f"{p}.id: expected a string of 1 to 20 characters")
            elif cid in seen:
                errs.append(f"{p}.id: duplicate id '{cid}'")
            else:
                seen.add(cid)
        if "statement" in c and (not isinstance(c["statement"], str) or not 1 <= len(c["statement"]) <= 300):
            errs.append(f"{p}.statement: expected a string of 1 to 300 characters")
        if "sources" in c:
            s = c["sources"]
            if not isinstance(s, list) or not s:
                errs.append(f"{p}.sources: expected a non-empty array")
            else:
                for j, ref in enumerate(s):
                    if not isinstance(ref, str):
                        errs.append(f"{p}.sources[{j}]: expected a string source id")
                    elif ref not in SOURCE_LINES:
                        errs.append(f"{p}.sources[{j}]: unknown source id")
                strs = [x for x in s if isinstance(x, str)]
                if len(set(strs)) != len(strs):
                    errs.append(f"{p}.sources: duplicate source id")
    if errs:
        out["errors"] = errs[:20]
        return out
    out["ok"] = True
    cited = {r for c in cs for r in c["sources"]}
    missing = sorted(set(SOURCE_LINES) - cited)
    if missing:
        out["notes"].append("source lines not cited: " + ", ".join(missing))
    return out

# ---------------------------------------------------------------------------
# Run IDs and the run directory
# ---------------------------------------------------------------------------


def run_id_problem(run_id):
    if not isinstance(run_id, str) or not RUN_ID_RE.fullmatch(run_id):
        return ("run id must be 1 to 64 characters of letters, digits, '-' or '_', starting with a letter "
                "or digit (no separators, dots or traversal)")
    return None


def runs_problem(runs_dir, run_id):
    """This revision allows exactly one recorded run in the repository."""
    if (runs_dir / run_id).exists() or (runs_dir / run_id).is_symlink():
        return f"run directory for '{run_id}' already exists; runs are never overwritten"
    if runs_dir.exists() and any(runs_dir.iterdir()):
        return "a run directory already exists; this revision records one run only"
    return None


def reserve_run_dir(runs_dir, run_id):
    runs_dir.mkdir(parents=True, exist_ok=True)
    d = runs_dir / run_id
    d.mkdir()  # exclusive: raises FileExistsError if it exists
    return d

# ---------------------------------------------------------------------------
# Canonical JSON
# ---------------------------------------------------------------------------


def canonical(obj):
    """UTF-8, sorted keys, two-space indent, no NaN or infinity, trailing newline."""
    return json.dumps(obj, sort_keys=True, indent=2, ensure_ascii=False, allow_nan=False) + "\n"


def write_canonical(path, obj):
    data = canonical(obj).encode("utf-8")
    tmp = path.with_name("." + path.name + ".tmp")
    with open(tmp, "xb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)

# ---------------------------------------------------------------------------
# Sanitizing (adapted from tools/capability_probe.py)
# ---------------------------------------------------------------------------

SCRUB_PATTERNS = [
    (re.compile(r"Bearer\s+\S+"), "Bearer [redacted]"),
    (re.compile(r"\bsk-[A-Za-z0-9_\-]{8,}"), "[redacted-secret]"),
    (re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"), "[redacted-uuid]"),
    (re.compile(r"\b(?:org|acct|account|user|project)[-_:][A-Za-z0-9]{6,}\b", re.I), "[redacted-id]"),
]


class Scrub:
    def __init__(self, key):
        self.key = key or ""
        self.home = os.path.expanduser("~").rstrip("/")
        self.acct = os.path.basename(self.home)

    def __call__(self, s):
        if not isinstance(s, str):
            return s
        if self.key:
            s = s.replace(self.key, "[redacted-key]")
        if self.home:
            s = s.replace(self.home, "$HOME")
        if len(self.acct) >= 3:
            s = re.sub(r"(?<![A-Za-z0-9])" + re.escape(self.acct) + r"(?![A-Za-z0-9])", "[account]", s)
        for pat, rep in SCRUB_PATTERNS:
            s = pat.sub(rep, s)
        return s

# ---------------------------------------------------------------------------
# Budget basis
# ---------------------------------------------------------------------------


def is_num(v):
    return isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v)


def ceil_usd(x):
    return math.ceil(round(x * 1e6, 3)) / 1e6


def load_basis(config_path):
    """Read the private pricing/limit config and the spike ledger. Returns (basis, problems)."""
    problems = []
    cp = Path(config_path).expanduser().resolve()
    if REPO == cp or REPO in cp.parents:
        return None, ["private config must be outside the repository"]
    try:
        cfg = json.loads(cp.read_text())
    except (OSError, ValueError) as e:
        return None, [f"private config unreadable: {type(e).__name__}"]
    api = cfg.get("api") or {}
    m = (cfg.get("models") or {}).get("spark") or {}
    b = cfg.get("budget") or {}
    docs = {d.get("id"): d for d in cfg.get("docs") or [] if isinstance(d, dict)}
    route = str(api.get("base_url") or "").rstrip("/") + str(api.get("chat_path") or "")
    if route != ENDPOINT:
        problems.append("recorded route differs from the fixed route")
    if m.get("id") != MODEL:
        problems.append("recorded Spark model id differs from the fixed model id")
    if api.get("max_out_param") not in ("max_tokens", "max_completion_tokens"):
        problems.append("recorded max output parameter missing")
    for k in ("input_usd_per_mtok", "output_usd_per_mtok"):
        if not is_num(m.get(k)) or m.get(k) < 0:
            problems.append(f"recorded {k} missing or invalid")
    if m.get("pricing_doc") not in docs:
        problems.append("pricing documentation reference missing")
    dmo = m.get("documented_max_out")
    if dmo is not None and (not isinstance(dmo, int) or dmo < MAX_OUT):
        problems.append(f"documented max output is below {MAX_OUT} or invalid")
    r = m.get("reasoning")
    if r not in ("none", "not_billed", "billed_as_output"):
        problems.append("recorded reasoning billing basis missing")
    elif r == "billed_as_output" and m.get("reasoning_inside_max_out") is not True:
        problems.append("reasoning is billed as output but is not recorded as capped by the max output parameter")
    if m.get("reasoning_doc") not in docs:
        problems.append("reasoning documentation reference missing")
    rem, reserve = b.get("remaining_usd_billing_console"), b.get("final_reserve_usd")
    if not is_num(rem) or not is_num(reserve):
        problems.append("recorded billing-console balance or final-run reserve missing")
    prior = None
    try:
        led = json.loads(PROBE_LEDGER.read_text())
        if led.get("format") != PROBE_LEDGER_FORMAT:
            raise ValueError("format")
        prior = round(sum(a["cost_bound"]["usd"] for a in led["attempts"] if a.get("sent")), 6)
    except (OSError, ValueError, KeyError, TypeError):
        problems.append("capability-probe ledger unreadable; prior committed allowance unknown")
    if problems:
        return None, problems
    dev_left = round(rem - reserve - prior, 6)
    basis = {
        "max_out_param": api["max_out_param"],
        "input_usd_per_mtok": m["input_usd_per_mtok"],
        "output_usd_per_mtok": m["output_usd_per_mtok"],
        "reasoning": r,
        "pricing_doc": {k: docs[m["pricing_doc"]].get(k) for k in ("id", "title", "url", "retrieved")},
        "reasoning_doc": {k: docs[m["reasoning_doc"]].get(k) for k in ("id", "title", "url", "retrieved")},
        "remaining_usd_billing_console_before_probing": rem,
        "final_reserve_usd": reserve,
        "prior_committed_allowance_usd": prior,
        "development_headroom_usd": dev_left,
        "subcap_usd": SUBCAP_USD,
        "headroom_usd": round(min(SUBCAP_USD, dev_left), 6),
        "note_path": cp.parent / NOTE_NAME,
    }
    return basis, []


def allowance(body_bytes, basis):
    in_units = body_bytes + INPUT_MARGIN
    usd = ceil_usd(in_units * basis["input_usd_per_mtok"] / 1e6 + MAX_OUT * basis["output_usd_per_mtok"] / 1e6)
    return {"input_units_bound": in_units, "output_units_bound": MAX_OUT, "usd": usd,
            "input_assumption": INPUT_ASSUMPTION,
            "output_basis": "requested max output; reasoning recorded as included in it" if basis["reasoning"] ==
            "billed_as_output" else f"requested max output; reasoning recorded as '{basis['reasoning']}'"}

# ---------------------------------------------------------------------------
# Transport (the only network access in this file)
# ---------------------------------------------------------------------------


class RedirectRefused(Exception):
    def __init__(self, code):
        super().__init__(f"HTTP {code} redirect refused; not followed")
        self.code = code


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise RedirectRefused(code)


OPENER = urllib.request.build_opener(NoRedirect)


def post(raw, key):
    req = urllib.request.Request(ENDPOINT, data=raw, method="POST", headers={
        "Authorization": "Bearer " + key, "Content-Type": "application/json",
        "Accept": "application/json", "User-Agent": "shaar-cli/1"})
    out = {"status": None, "body": None, "sent": "yes", "timeout": False, "error": None, "redirect": False}
    t0 = time.monotonic()
    try:
        with OPENER.open(req, timeout=HTTP_TIMEOUT_S) as resp:
            out["status"] = resp.status
            out["body"] = resp.read(MAX_RESPONSE_BYTES + 1)
    except RedirectRefused as e:
        out["status"], out["redirect"], out["error"] = e.code, True, str(e)
    except urllib.error.HTTPError as e:
        out["status"] = e.code
        try:
            out["body"] = e.read(MAX_RESPONSE_BYTES + 1)
        except OSError:
            pass
    except urllib.error.URLError as e:
        reason = e.reason
        if isinstance(reason, (socket.timeout, TimeoutError)):
            out["timeout"], out["sent"] = True, "unknown"
        elif isinstance(reason, (ssl.SSLCertVerificationError, socket.gaierror, ConnectionRefusedError)):
            out["sent"] = "no"
        else:
            out["sent"] = "unknown"
        out["error"] = f"{type(reason).__name__}: {reason}"
    except (socket.timeout, TimeoutError) as e:
        out["timeout"], out["sent"], out["error"] = True, "unknown", f"timeout: {e}"
    except (OSError, http.client.HTTPException) as e:
        out["sent"], out["error"] = "unknown", f"{type(e).__name__}: {e}"
    except Exception as e:  # assume the request may have been billed
        out["sent"], out["error"] = "unknown", f"unexpected {type(e).__name__}: {e}"
    out["latency_ms"] = int((time.monotonic() - t0) * 1000)
    if out["body"] is not None and len(out["body"]) > MAX_RESPONSE_BYTES:
        out["body"], out["error"] = None, f"response larger than {MAX_RESPONSE_BYTES} bytes; not parsed"
    return out


def numeric_only(u):
    if not isinstance(u, dict):
        return None
    res = {}
    for k, v in u.items():
        if is_num(v):
            res[str(k)] = v
        elif isinstance(v, dict):
            sub = numeric_only(v)
            if sub:
                res[str(k)] = sub
    return res


def find_num(d, name):
    if not isinstance(d, dict):
        return None
    for k, v in d.items():
        if k == name and is_num(v):
            return v
        if isinstance(v, dict):
            r = find_num(v, name)
            if r is not None:
                return r
    return None


def interpret(r, scrub, basis, bound):
    """Turn a transport result into record/accounting fields. Never claims a gate outcome."""
    resp, err, warnings, usage = None, None, [], None
    obj = None
    if r["body"] is not None:
        try:
            obj = json.loads(r["body"].decode("utf-8", "replace"))
        except ValueError:
            obj = None
    if r["redirect"]:
        outcome = "REDIRECT_REFUSED"
        err = {"message": r["error"]}
    elif r["status"] == 200 and isinstance(obj, dict) and isinstance(obj.get("choices"), list) and obj["choices"]:
        ch = obj["choices"][0] if isinstance(obj["choices"][0], dict) else {}
        msg = ch.get("message") if isinstance(ch.get("message"), dict) else {}
        content = msg.get("content")
        if isinstance(content, list):
            content = "".join(p.get("text", "") for p in content if isinstance(p, dict) and isinstance(p.get("text"), str))
        usage = numeric_only(obj.get("usage"))
        ref = msg.get("refusal")
        if ref is None or ref == "":
            refusal = None
        elif isinstance(ref, str):
            refusal = scrub(ref)[:500]
        else:
            refusal = f"[refusal field of type {type(ref).__name__}; not stored]"
        tc = msg.get("tool_calls")
        tool_calls = 0 if tc is None else (len(tc) if isinstance(tc, list) else f"malformed ({type(tc).__name__})")
        resp = {
            "response_id": scrub(str(obj["id"])[:200]) if obj.get("id") is not None else None,
            "model_returned": scrub(str(obj["model"])[:200]) if obj.get("model") is not None else None,
            "finish_reason": scrub(str(ch.get("finish_reason")))[:50] if ch.get("finish_reason") is not None else None,
            "content": scrub(content) if isinstance(content, str) else None,
            "refusal": refusal,
            "tool_calls_returned": tool_calls,
            "usage": usage,
            "message_fields_not_stored": sorted(str(k) for k in msg if k not in ("role", "content", "refusal", "tool_calls")),
        }
        outcome = "REPLY_RECORDED"
    elif r["status"] is not None:
        outcome = "UNEXPECTED_RESPONSE" if r["status"] == 200 else "HTTP_ERROR"
        if isinstance(obj, dict) and isinstance(obj.get("error"), dict):
            e = obj["error"]
            err = {k: scrub(str(e[k])[:500]) for k in ("type", "code", "param", "message") if e.get(k) is not None}
        elif isinstance(obj, dict) and isinstance(obj.get("error"), str):
            err = {"message": scrub(obj["error"][:500])}
        else:
            err = {"message": scrub((r["body"] or b"").decode("utf-8", "replace")[:300]),
                   "note": "non-JSON body or unexpected shape; first 300 characters"}
    else:
        outcome = "NOT_SENT" if r["sent"] == "no" else "TRANSPORT_UNKNOWN"
        err = {"message": scrub(r["error"] or "")[:300]}
    est = None
    if usage:
        i = find_num(usage, "prompt_tokens")
        i = find_num(usage, "input_tokens") if i is None else i
        o = find_num(usage, "completion_tokens")
        o = find_num(usage, "output_tokens") if o is None else o
        rsn = find_num(usage, "reasoning_tokens")
        if is_num(i) and is_num(o):
            est = round(i * basis["input_usd_per_mtok"] / 1e6 + o * basis["output_usd_per_mtok"] / 1e6, 6)
        if any(is_num(x) and x < 0 for x in (i, o, rsn)):
            warnings.append("negative usage reported; cost data invalid")
        if is_num(i) and i > bound["input_units_bound"]:
            warnings.append("reported input units exceed the input allowance")
        if is_num(o) and o > bound["output_units_bound"]:
            warnings.append("reported output units exceed the output allowance")
        if is_num(rsn) and rsn > bound["output_units_bound"]:
            warnings.append("reported reasoning units exceed the output allowance")
        if basis["reasoning"] == "none" and is_num(rsn) and rsn > 0:
            warnings.append("reasoning units reported for a model recorded as non-reasoning")
    if resp is not None and est is None:
        warnings.append("usage missing or not in a recognized form; cost data unavailable")
    return outcome, resp, err, est, warnings


def evaluate(r, scrub, basis, bound):
    """Interpret, validate and apply the success criteria. Success requires: a recorded reply that
    passes local validation, no refusal, finish_reason "stop", the returned model id equal to the
    requested one, and no usage or cost warning."""
    outcome, resp, err, est, warnings = interpret(r, scrub, basis, bound)
    validation, reasons = None, []
    if resp is not None:
        validation = validate_constraint_map(resp["content"])
        if not validation["ok"]:
            outcome = "INVALID_REPLY"
            reasons.append("local validation failed")
        if resp["refusal"] is not None:
            reasons.append("the model returned a refusal")
        if resp["finish_reason"] != "stop":
            reasons.append(f"finish_reason is {resp['finish_reason']!r}, not 'stop'")
        if resp["model_returned"] != MODEL:
            reasons.append(f"returned model id {resp['model_returned']!r} differs from the requested {MODEL!r}")
    else:
        reasons.append(f"no reply recorded ({outcome})")
    reasons += ["warning: " + w for w in warnings]
    return {"outcome": outcome, "response": resp, "error": err, "usage_estimate_usd": est, "warnings": warnings,
            "validation": validation, "reasons": reasons, "complete": not reasons}


def processing_failure(exc):
    return {"outcome": "PROCESSING_ERROR", "response": None, "validation": None, "usage_estimate_usd": None,
            "error": {"message": f"reply processing failed: {type(exc).__name__}"}, "warnings": [],
            "reasons": ["reply processing failed after sending; recorded as incomplete"], "complete": False}

# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


def note(path, entry):
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, sort_keys=True) + "\n")
        f.flush()
        os.fsync(f.fileno())


def refuse(msg):
    print("REFUSED (nothing sent): " + msg)
    return EXIT_REFUSED


def cmd_run(args):
    run_id = args.run_id
    p = run_id_problem(run_id)
    if p:
        return refuse(p)
    p = runs_problem(RUNS_DIR, run_id)
    if p:
        return refuse(p)
    key = os.environ.get(KEY_ENV, "")
    if not key or re.search(r"\s", key):
        return refuse(f"{KEY_ENV} is not set or contains whitespace")
    basis, problems = load_basis(args.config)
    if problems:
        return refuse("; ".join(problems))
    body = build_body(basis["max_out_param"])
    raw = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if len(raw) > MAX_REQUEST_BYTES:
        return refuse(f"request body is {len(raw)} bytes; limit {MAX_REQUEST_BYTES}")
    bound = allowance(len(raw), basis)
    print(f"route: {ENDPOINT} | model: {MODEL} | request body: {len(raw)} bytes | {basis['max_out_param']}: {MAX_OUT}")
    print(f"prices (per million units): input ${basis['input_usd_per_mtok']} output ${basis['output_usd_per_mtok']} "
          f"[{basis['pricing_doc']['id']}] | reasoning: {basis['reasoning']} [{basis['reasoning_doc']['id']}]")
    print(f"allowance for this request: ${bound['usd']:.6f} (input <= {bound['input_units_bound']}, "
          f"output <= {bound['output_units_bound']}; {INPUT_ASSUMPTION})")
    print(f"prior committed allowance: ${basis['prior_committed_allowance_usd']:.6f} | development headroom: "
          f"${basis['development_headroom_usd']:.6f} (billing-console ${basis['remaining_usd_billing_console_before_probing']:.2f} "
          f"before probing, minus reserve ${basis['final_reserve_usd']:.2f}, minus prior allowance) | "
          f"subcap ${SUBCAP_USD:.2f} | headroom ${basis['headroom_usd']:.6f}")
    print(f"{KEY_ENV}: present (not printed)")
    if bound["usd"] > basis["headroom_usd"]:
        return refuse(f"allowance ${bound['usd']:.6f} exceeds headroom ${basis['headroom_usd']:.6f}")
    if args.preflight:
        print("PREFLIGHT PASS (nothing sent, nothing written)")
        return EXIT_OK

    scrub = Scrub(key)
    note_path = basis["note_path"]
    base_note = {"run_id": run_id, "allowance_usd": bound["usd"], "model": MODEL, "wall_clock_utc": int(time.time())}
    try:
        note(note_path, dict(base_note, event="reserving"))
    except OSError as e:
        return refuse(f"private accounting note not writable ({type(e).__name__})")
    try:
        run_dir = reserve_run_dir(RUNS_DIR, run_id)
    except OSError as e:
        note(note_path, dict(base_note, event="not sent: run directory not reserved"))
        return refuse(f"run directory not reserved ({type(e).__name__})")

    budget = {k: basis[k] for k in ("remaining_usd_billing_console_before_probing", "final_reserve_usd",
                                    "prior_committed_allowance_usd", "development_headroom_usd", "subcap_usd",
                                    "headroom_usd")}
    acct = {
        "format": ACCOUNTING_FORMAT, "run_id": run_id,
        "attempt": {"number": 1, "kind": "primary", "sent": "in_flight", "allowance": bound,
                    "pricing_doc": basis["pricing_doc"], "reasoning_doc": basis["reasoning_doc"],
                    "usage_estimate_usd": "UNKNOWN", "billing": "PENDING", "timing": None, "warnings": []},
        "budget_before": budget,
        "headroom_after_usd": round(basis["headroom_usd"] - bound["usd"], 6),
        "note": "allowance is counted in full for every sent or possibly sent request",
    }
    try:
        write_canonical(run_dir / "accounting.json", acct)
    except OSError as e:
        note(note_path, dict(base_note, event="not sent: accounting not written"))
        print(f"STOP (nothing sent): accounting.json not written ({type(e).__name__})")
        return EXIT_INCOMPLETE_RUN

    # From here on nothing may escape: every path writes a record, keeps the allowance and updates the note.
    try:
        r = post(raw, key)
    except BaseException as e:  # post() handles ordinary errors; this covers interrupts
        r = {"status": None, "body": None, "sent": "unknown", "timeout": False, "redirect": False,
             "error": f"interrupted during the request: {type(e).__name__}", "latency_ms": None}
    try:
        ev = evaluate(r, scrub, basis, bound)
    except BaseException as e:
        ev = processing_failure(e)
    written = False
    try:
        record = {
            "format": RECORD_FORMAT, "run_id": run_id,
            "task": {"id": TASK_ID, "input_label": "synthetic", "source_ids": sorted(SOURCE_LINES), "source_text": SOURCE_TEXT},
            "request": {"endpoint": ENDPOINT, "body": body},
            "model": {"requested": MODEL, "returned": ev["response"]["model_returned"] if ev["response"] else None},
            "transport": {"http_status": r["status"], "sent": r["sent"], "outcome": ev["outcome"]},
            "response": ev["response"], "error": ev["error"],
            "validation": ev["validation"],
            "status": {
                "recording": "complete" if ev["complete"] else "incomplete",
                "incomplete_reasons": ev["reasons"],
                "candidate": "pending: candidate generation is not implemented",
                "gate": "not_implemented", "gate_verdict": None,
                "replay": "not_implemented",
            },
        }
        acct["attempt"].update(sent=r["sent"], timing={"latency_ms": r["latency_ms"]}, warnings=ev["warnings"],
                               usage_estimate_usd=ev["usage_estimate_usd"] if ev["usage_estimate_usd"] is not None else "UNKNOWN")
        if r["sent"] == "no":
            acct["headroom_after_usd"] = basis["headroom_usd"]
            acct["note"] = "the request did not leave this computer; no allowance is counted"
        write_canonical(run_dir / "record.json", record)
        write_canonical(run_dir / "accounting.json", acct)
        written = True
    except BaseException as e:
        print(f"STOP: evidence write failed ({type(e).__name__}); the private accounting note keeps the attempt")
    try:
        note(note_path, dict(base_note, event="finished", sent=r["sent"], outcome=ev["outcome"],
                             recording="complete" if ev["complete"] and written else "incomplete",
                             evidence_written=written))
    except BaseException:
        print("WARNING: private accounting note not updated")
    try:
        resp, validation, err, est = ev["response"], ev["validation"], ev["error"], ev["usage_estimate_usd"]
        print(f"{run_id}: HTTP {r['status']} | sent: {r['sent']} | outcome: {ev['outcome']} | latency {r['latency_ms']} ms")
        if resp:
            print(f"  model requested: {MODEL} | returned: {resp['model_returned']} | finish: {resp['finish_reason']}"
                  f" | refusal: {'yes' if resp['refusal'] is not None else 'no'}")
            print(f"  usage: {json.dumps(resp['usage'], sort_keys=True)}")
            print(f"  reply (first 300 chars): {(resp['content'] or '')[:300]!r}")
        if validation:
            print(f"  local validation: {'PASS' if validation['ok'] else 'FAIL'}"
                  + ("".join("\n    error: " + e for e in validation["errors"][:5]))
                  + ("".join("\n    note: " + n for n in validation["notes"])))
        if err:
            print("  error (sanitized): " + json.dumps(err, sort_keys=True)[:400])
        for reason in ev["reasons"]:
            print("  INCOMPLETE: " + reason)
        print(f"  allowance ${bound['usd']:.6f} | usage estimate "
              + (f"${est:.6f}" if est is not None else "UNKNOWN") + " | billing PENDING")
    except BaseException as e:
        print(f"WARNING: summary not fully printed ({type(e).__name__}); see the run files")
    if ev["complete"] and written:
        print("RECORDING COMPLETE; GATE NOT IMPLEMENTED")
        return EXIT_OK
    print("RECORDING INCOMPLETE; GATE NOT IMPLEMENTED")
    return EXIT_INCOMPLETE_RUN


def cmd_replay(args):
    print("INCOMPLETE: gate replay is not implemented")
    return EXIT_NOT_IMPLEMENTED


def cmd_verify(args):
    print("INCOMPLETE: artifact verification is not implemented")
    return EXIT_NOT_IMPLEMENTED


def sandbox_run(content, reply):
    """Drive cmd_run end to end in a temporary directory with a fake transport (no key, no network)."""
    g = globals()
    saved = {k: g[k] for k in ("REPO", "RUNS_DIR", "PROBE_LEDGER", "post", "evaluate")}
    saved_key = os.environ.get(KEY_ENV)
    result = {"rc": None, "stdout": "", "record": None, "accounting": None, "note": {}}
    with tempfile.TemporaryDirectory() as t:
        t = Path(t).resolve()
        repo, priv = t / "repo", t / "private"
        repo.mkdir(); priv.mkdir()
        ledger = repo / "ledger.json"
        ledger.write_text(json.dumps({"format": PROBE_LEDGER_FORMAT, "attempts": [{"sent": True, "cost_bound": {"usd": 0.5}}]}))
        cfg = priv / "config.json"
        doc = {"id": "D1", "title": "test", "url": "https://example.com/doc", "retrieved": "2026-01-01"}
        cfg.write_text(json.dumps({
            "api": {"base_url": ENDPOINT.rsplit("/chat/completions", 1)[0], "chat_path": "/chat/completions", "max_out_param": "max_tokens"},
            "docs": [doc],
            "models": {"spark": {"id": MODEL, "input_usd_per_mtok": 1.0, "output_usd_per_mtok": 2.0, "pricing_doc": "D1",
                                 "documented_max_out": None, "reasoning": "billed_as_output", "reasoning_doc": "D1",
                                 "reasoning_inside_max_out": True}},
            "budget": {"remaining_usd_billing_console": 150, "final_reserve_usd": 30}}))
        message = {"role": "assistant", "content": reply.get("content", content)}
        for k in ("refusal", "tool_calls"):
            if k in reply:
                message[k] = reply[k]
        body = {"id": "test-1", "model": reply.get("model", MODEL), "usage": {"prompt_tokens": 100, "completion_tokens": 50},
                "choices": [{"finish_reason": reply.get("finish_reason", "stop"), "message": message}]}

        def fake_post(raw, key):
            return {"status": 200, "body": json.dumps(body).encode(), "sent": "yes", "timeout": False,
                    "error": None, "redirect": False, "latency_ms": 1}

        def broken_evaluate(*a, **k):
            raise TypeError("simulated")
        try:
            g.update(REPO=repo, RUNS_DIR=repo / "runs", PROBE_LEDGER=ledger, post=fake_post)
            if reply.get("raise"):
                g["evaluate"] = broken_evaluate
            os.environ[KEY_ENV] = "selftest-key-0000"
            buf = io.StringIO()
            with redirect_stdout(buf):
                result["rc"] = main(["run", "--run-id", "t1", "--config", str(cfg)])
            result["stdout"] = buf.getvalue()
            run_dir = repo / "runs" / "t1"
            for name in ("record", "accounting"):
                f = run_dir / f"{name}.json"
                result[name] = json.loads(f.read_text()) if f.exists() else None
            lines = (priv / NOTE_NAME).read_text().splitlines()
            result["note"] = json.loads(lines[-1]) if lines else {}
        finally:
            g.update(saved)
            if saved_key is None:
                os.environ.pop(KEY_ENV, None)
            else:
                os.environ[KEY_ENV] = saved_key
    return result


def run_selftests():
    res = []

    def case(name, ok):
        res.append((name, bool(ok)))

    good = '{"constraints":[{"id":"C1","statement":"Change only manifest files.","sources":["S1"]},' \
           '{"id":"C2","statement":"Keep tests passing.","sources":["S2"]}]}'
    case("reply: valid constraint map accepted", validate_constraint_map(good)["ok"])
    case("reply: uncited source line noted, not rejected",
         validate_constraint_map(good)["notes"] == ["source lines not cited: S3"])
    for name, text in (
        ("malformed JSON", '{"constraints":[{"id":"C1"'),
        ("empty reply", ""),
        ("missing top-level field", '{}'),
        ("missing item field", '{"constraints":[{"id":"C1","sources":["S1"]}]}'),
        ("extra top-level field", '{"constraints":[{"id":"C1","statement":"x","sources":["S1"]}],"note":"x"}'),
        ("extra item field", '{"constraints":[{"id":"C1","statement":"x","sources":["S1"],"x":1}]}'),
        ("unknown source id", '{"constraints":[{"id":"C1","statement":"x","sources":["S4"]}]}'),
        ("duplicate constraint id", '{"constraints":[{"id":"C1","statement":"x","sources":["S1"]},'
                                    '{"id":"C1","statement":"y","sources":["S2"]}]}'),
        ("empty sources", '{"constraints":[{"id":"C1","statement":"x","sources":[]}]}'),
        ("empty constraints", '{"constraints":[]}'),
        ("non-string statement", '{"constraints":[{"id":"C1","statement":5,"sources":["S1"]}]}'),
        ("code-fenced reply", '```json\n' + good + '\n```'),
    ):
        case(f"reply: {name} rejected", not validate_constraint_map(text)["ok"])
    case("run id: ordinary id accepted", run_id_problem("spark-sourcemap-01") is None)
    for bad in ("", "../x", "a/b", "..", ".", "a.b", "-x", "_x", "x" * 65, "a\\b", "a b", "a\nb"):
        label = repr(bad) if len(bad) <= 10 else f"{len(bad)}-character id"
        case(f"run id: {label} refused", run_id_problem(bad) is not None)
    with tempfile.TemporaryDirectory() as t:
        runs = Path(t) / "runs"
        case("run dir: fresh run accepted", runs_problem(runs, "r1") is None)
        reserve_run_dir(runs, "r1")
        case("run dir: existing run refused", runs_problem(runs, "r1") is not None)
        case("run dir: second run refused (one run per revision)", runs_problem(runs, "r2") is not None)
        try:
            reserve_run_dir(runs, "r1")
            case("run dir: exclusive reservation", False)
        except FileExistsError:
            case("run dir: exclusive reservation", True)
        p = Path(t) / "c.json"
        write_canonical(p, {"b": 1, "a": [1, 2]})
        case("canonical JSON: sorted keys, fixed form", p.read_text() == '{\n  "a": [\n    1,\n    2\n  ],\n  "b": 1\n}\n')
        try:
            canonical({"x": float("nan")})
            case("canonical JSON: NaN refused", False)
        except ValueError:
            case("canonical JSON: NaN refused", True)
    basis = {"input_usd_per_mtok": 1.0, "output_usd_per_mtok": 2.0, "reasoning": "billed_as_output"}
    b = allowance(1000, basis)
    case("allowance: (bytes + 512) at input price plus 4096 at output price", b["usd"] == 0.009704)
    s = Scrub("TESTKEYVALUE12345678")
    home = os.path.expanduser("~").rstrip("/")
    out = s(f"key TESTKEYVALUE12345678 at {home}/x Bearer abc.def")
    case("sanitizer: key, home path and bearer value removed",
         "TESTKEYVALUE" not in out and (not home or home not in out) and "abc.def" not in out)
    try:
        NoRedirect().redirect_request(None, None, 302, "Found", {}, "https://example.com/")
        case("transport: redirect refused", False)
    except RedirectRefused:
        case("transport: redirect refused", True)
    fake = {"status": 200, "sent": "yes", "redirect": False, "error": None, "latency_ms": 1,
            "body": json.dumps({"model": MODEL, "choices": [{"finish_reason": "stop", "message": {
                "content": good, "reasoning_content": "hidden"}}], "usage": {"prompt_tokens": 9, "completion_tokens": 9999}}).encode()}
    o, resp, _, _, w = interpret(fake, s, dict(basis, input_usd_per_mtok=1.0), b)
    case("usage: output over the allowance raises a warning", any("output units exceed" in x for x in w))
    case("response: hidden reasoning text not stored", "hidden" not in json.dumps(resp))
    fake2 = dict(fake, body=json.dumps({"model": MODEL, "choices": [{"message": {"content": good}}]}).encode())
    case("usage: missing usage raises a warning", any("usage missing" in x for x in interpret(fake2, s, basis, b)[4]))
    for name, reply, expect in (
        ("valid reply, finish 'stop', same model: complete, exit 0", {}, "complete"),
        ("source reference is an object: incomplete", {"content": '{"constraints":[{"id":"C1","statement":"x","sources":[{"id":"S1"}]}]}'}, "local validation failed"),
        ("source reference is an array: incomplete", {"content": '{"constraints":[{"id":"C1","statement":"x","sources":[["S1"]]}]}'}, "local validation failed"),
        ("tool_calls is a number: recorded, no crash", {"tool_calls": 5}, "complete"),
        ("tool_calls is an object: recorded, no crash", {"tool_calls": {"x": 1}}, "complete"),
        ("refusal returned: incomplete", {"refusal": "I cannot help with that."}, "the model returned a refusal"),
        ("refusal of an unexpected type: incomplete", {"refusal": {"x": 1}}, "the model returned a refusal"),
        ("finish_reason 'length': incomplete", {"finish_reason": "length"}, "finish_reason is 'length'"),
        ("returned model differs: incomplete", {"model": "muse-spark-1.4"}, "returned model id 'muse-spark-1.4' differs"),
        ("processing raises after send: incomplete", {"raise": True}, "reply processing failed after sending"),
    ):
        out = sandbox_run(good, reply)
        rec, acc = out["record"], out["accounting"]
        ok = (rec is not None and acc is not None and acc["attempt"]["sent"] == "yes"
              and acc["headroom_after_usd"] == round(acc["budget_before"]["headroom_usd"] - acc["attempt"]["allowance"]["usd"], 6)
              and out["note"].get("event") == "finished")
        if expect == "complete":
            ok = ok and out["rc"] == 0 and rec["status"]["recording"] == "complete" and "RECORDING COMPLETE" in out["stdout"]
        else:
            ok = ok and out["rc"] == 1 and rec["status"]["recording"] == "incomplete" \
                and any(expect in x for x in rec["status"]["incomplete_reasons"]) and "RECORDING INCOMPLETE" in out["stdout"] \
                and out["note"].get("recording") == "incomplete" and rec["status"]["gate_verdict"] is None
        case(f"run (offline sandbox): {name}", ok)
    global post
    real_post = post

    def no_network(*a, **k):
        raise AssertionError("network used")
    post = no_network
    try:
        for cmd, text in (("replay", "INCOMPLETE: gate replay is not implemented"),
                          ("verify", "INCOMPLETE: artifact verification is not implemented")):
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = main([cmd, "any-run"])
            case(f"{cmd}: exit 2, prints INCOMPLETE, no network", rc == 2 and buf.getvalue().strip() == text)
    finally:
        post = real_post
    return res


def cmd_selftest(_args):
    res = run_selftests()
    for name, ok in res:
        print(("PASS " if ok else "FAIL ") + name)
    n = sum(ok for _, ok in res)
    print(f"SELFTEST {n}/{len(res)} PASS")
    return EXIT_OK if n == len(res) else EXIT_INCOMPLETE_RUN


def main(argv=None):
    ap = argparse.ArgumentParser(prog="shaar.py", description="Sha'ar event CLI (recording skeleton; gate not implemented)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="record one Spark source-map reply (one real request)")
    r.add_argument("--run-id", required=True)
    r.add_argument("--config", required=True, help="private pricing/limit config outside the repository")
    r.add_argument("--preflight", action="store_true", help="check and print the budget basis; send nothing")
    for name, text in (("replay", "not implemented; exits 2"), ("verify", "not implemented; exits 2")):
        q = sub.add_parser(name, help=text)
        q.add_argument("run_id")
    sub.add_parser("selftest", help="offline checks; no key or network needed")
    a = ap.parse_args(argv)
    return {"run": cmd_run, "replay": cmd_replay, "verify": cmd_verify, "selftest": cmd_selftest}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
