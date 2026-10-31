#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Sha'ar candidate proposer: one recorded Spark request for one gate candidate.

Sends one bounded request to the hosted Spark model. The request carries a short
task, narrow excerpts of the pinned PostgreSQL source (read from a local git
checkout and checked against pinned hashes) and the gate's patch-format rules.
The reply is validated locally and recorded. When the reply is usable, its
patch string is encoded as UTF-8 exactly once and written as candidate.patch.
This program never runs the gate and never assigns a verdict; the patch goes
to gate/check.py through its external-input interface, run separately.

Commands:
  python3 tools/propose_candidate.py render --pg-git PG [--out FILE]
  python3 tools/propose_candidate.py send --pg-git PG --config PATH [--preflight]
  python3 tools/propose_candidate.py resume [--config PATH]
  python3 tools/propose_candidate.py derive-failure
  python3 tools/propose_candidate.py link
  python3 tools/propose_candidate.py selftest

Exit codes:
  0  render/preflight/selftest/link passed; send/resume: proposal complete
  1  send/resume: a request was reserved or sent but the proposal is incomplete;
     selftest/link: a check failed
  2  argument error, or the command does not apply (for example resume when
     the proposal is already final, or derive-failure on an ACCEPT)
  3  send: refused before anything was sent

Only send can use the network, at most once per proposal ID. resume,
derive-failure and link make no model call. Standard library only;
Python 3.9+. The API key is read from MODEL_API_KEY only and is never
printed or written. See docs/CANDIDATE_STATUS.md.

Drafted with an AI coding assistant; run and reviewed by the repository owner.
Routines are adapted from shaar.py (also event-built); that file is not
imported and its task is unchanged.
"""

import argparse
import hashlib
import http.client
import io
import json
import math
import os
import re
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from contextlib import redirect_stdout
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
PROPOSALS_DIR = REPO / "evidence" / "event" / "candidate-runs"
GATE_RUNS_DIR = REPO / "evidence" / "event" / "gate-runs"
CLI_RUNS_DIR = REPO / "evidence" / "event" / "runs"
PROBE_LEDGER = REPO / "evidence" / "event" / "capability-probe" / "probe-results.json"
PROBE_LEDGER_FORMAT = "shaar-capability-probe-results/1"
CLI_ACCOUNTING_FORMAT = "shaar-run-accounting/1"

PROPOSAL_ID = "spark-candidate-01"     # fixed for this revision
GATE_RUN_ID = "candidate-01"           # gate run ID reserved for the first model proposal
GATE_ORIGIN = "external"
GATE_REFERENCE = "baseline-04"
TASK_ID = "pg-default-ssl-groups-hybrid/1"

F_REQUEST = "shaar-candidate-request/1"
F_SOURCE = "shaar-candidate-source/1"
F_RESPONSE = "shaar-candidate-response/1"
F_RECORD = "shaar-candidate-record/1"
F_ACCOUNTING = "shaar-candidate-accounting/1"
F_FAILURE = "shaar-candidate-failure/1"

ENDPOINT = "https://api.meta.ai/v1/chat/completions"  # fixed; no override
MODEL = "muse-spark-1.3"                               # fixed; no override
KEY_ENV = "MODEL_API_KEY"
MAX_OUT = 8192                  # requested output units, reasoning included
MAX_SOURCE_BYTES = 32 * 1024    # all source excerpts together
MAX_REQUEST_BYTES = 48 * 1024   # complete serialized request body
MAX_PATCH_BYTES = 4096          # the gate's external-input limit
MAX_EXPLANATION_CHARS = 2000
SUBCAP_USD = 1.0                # spend allowance for this one request
INPUT_MARGIN = 512
HTTP_TIMEOUT_S = 300
MAX_RESPONSE_BYTES = 1_000_000
NOTE_NAME = "shaar-candidate-attempts.jsonl"   # private note, next to the config
CLI_NOTE_NAME = "shaar-run-attempts.jsonl"     # shaar.py's private note, read only

INPUT_ASSUMPTION = (f"input units bounded by request-body bytes plus {INPUT_MARGIN}, assuming at least one "
                    "byte of body per input unit; this is an allowance, not a provider billing cap")

EXIT_OK, EXIT_INCOMPLETE, EXIT_NA, EXIT_REFUSED = 0, 1, 2, 3

# ---------------------------------------------------------------------------
# Pinned source
# ---------------------------------------------------------------------------

PG_PIN = "68af68ac691f2b57d29524a191debed9b0bdd558"
HEADER_PATH = "src/include/libpq/libpq.h"
GUC_PATH = "src/backend/utils/misc/guc_parameters.dat"
EDITABLE = (137, 141)

SOURCE_SPECS = [
    {"id": "SRC1", "path": HEADER_PATH, "first": 125, "last": 148,
     "role": "editable file; original lines 137-141 are the editable region",
     "pin": {"git_blob": "d15073a0a93a0e12aa7d7b0d64ff7a4e511add4d",
             "sha256": "c7124f50fd4a237a9fc48fc802075fff35292247dc336d96aeae84dc6981c2de"}},
    {"id": "SRC2", "path": GUC_PATH, "first": 2812, "last": 2812,
     "role": "read-only; shows where the default takes effect; not an edit target",
     "pin": {"lines": ["  boot_val => 'DEFAULT_SSL_GROUPS',"]}},
]
SOURCE_IDS = [s["id"] for s in SOURCE_SPECS]


def git_blob_id(data):
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def git_reader(pg_git):
    """Read a file at the pin from a local PostgreSQL checkout (read-only git commands)."""
    env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "GIT_OPTIONAL_LOCKS": "0", "HOME": os.path.expanduser("~"),
           "LANG": "C", "LC_ALL": "C"}

    def read(path):
        spec = f"{PG_PIN}:{path}"
        p = subprocess.run(["git", "-C", str(pg_git), "show", spec], stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, timeout=60, env=env)
        q = subprocess.run(["git", "-C", str(pg_git), "rev-parse", spec], stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, timeout=60, env=env)
        if p.returncode != 0 or q.returncode != 0:
            raise ValueError(f"git could not read {path} at the pin")
        return p.stdout, q.stdout.decode("ascii", "replace").strip()
    return read


def load_sources(read, specs=None):
    """Return the source items. Raises ValueError on any pin or size problem."""
    specs = SOURCE_SPECS if specs is None else specs
    out, total = [], 0
    for s in specs:
        data, blob = read(s["path"])
        if git_blob_id(data) != blob:
            raise ValueError(f"{s['id']}: git blob id does not match the bytes read")
        pin = s["pin"]
        if "git_blob" in pin and blob != pin["git_blob"]:
            raise ValueError(f"{s['id']}: git blob {blob} differs from the pinned {pin['git_blob']}")
        if "sha256" in pin and sha256(data) != pin["sha256"]:
            raise ValueError(f"{s['id']}: SHA-256 differs from the pinned value")
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            raise ValueError(f"{s['id']}: not UTF-8")
        lines = text.split("\n")
        if not 1 <= s["first"] <= s["last"] <= len(lines) - (1 if text.endswith("\n") else 0):
            raise ValueError(f"{s['id']}: line range outside the file")
        excerpt = lines[s["first"] - 1:s["last"]]
        if "lines" in pin and excerpt != pin["lines"]:
            raise ValueError(f"{s['id']}: excerpt differs from the pinned lines")
        etext = "\n".join(excerpt) + "\n"
        total += len(etext.encode("utf-8"))
        out.append({"id": s["id"], "path": s["path"], "commit": PG_PIN, "first_line": s["first"],
                    "last_line": s["last"], "role": s["role"], "lines": excerpt,
                    "excerpt_sha256": sha256(etext.encode("utf-8")), "file_git_blob": blob,
                    "file_sha256": sha256(data), "file_bytes": len(data)})
    if total > MAX_SOURCE_BYTES:
        raise ValueError(f"source excerpts are {total} bytes; limit {MAX_SOURCE_BYTES}")
    return out

# ---------------------------------------------------------------------------
# The request (everything in build_body is model-visible)
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = ("Propose a minimal unified diff against the supplied source. Follow the listed patch rules and "
                 "return only the requested structured object.")

ADDED_LINE_PATTERNS = [
    r"^#ifdef USE_SSL$",
    r"^#include <openssl/opensslv\.h>$",
    r"^#if OPENSSL_VERSION_NUMBER >= 0x[0-9A-F]{8}L$",
    r"^#else$",
    r"^#endif$",
    r'^#define DEFAULT_SSL_GROUPS "[A-Za-z0-9_:-]{1,128}"$',
]
GROUP_NAMES = ["X25519MLKEM768", "X25519", "prime256v1", "secp256r1", "P-256", "none"]
FORBIDDEN_MARKERS = ["GIT binary patch", "Binary files", "new file mode", "deleted file mode", "old mode",
                     "new mode", "rename from", "rename to", "copy from", "copy to", "similarity index",
                     "dissimilarity index", "/dev/null"]


def render_user(sources):
    p = HEADER_PATH
    src = []
    for s in sources:
        width = len(str(s["last_line"]))
        rng = (f"line {s['first_line']}" if s["first_line"] == s["last_line"]
               else f"lines {s['first_line']}-{s['last_line']}")
        src.append(f"[{s['id']}] {s['path']}, {rng} ({s['role']})")
        src += [f"{n:>{width}}: {ln}" if ln else f"{n:>{width}}:"
                for n, ln in zip(range(s["first_line"], s["last_line"] + 1), s["lines"])]
        src.append("")
    rules = [
        f"1. Change exactly one file: {p}. No other file, and no file creation, deletion, rename, copy, mode "
        "change or binary content.",
        f"2. Remove only original lines {EDITABLE[0]}-{EDITABLE[1]}. Insert added lines only between original "
        f"lines {EDITABLE[0] - 1} and {EDITABLE[1] + 1}. Every other line stays unchanged.",
        "3. Context lines and removed lines must equal the original lines exactly, at the line numbers stated "
        "in the hunk header. The patch is applied with no offset and no fuzz.",
        f'4. The patch starts with an optional line "diff --git a/{p} b/{p}", followed by an optional line '
        '"index HEX..HEX" or "index HEX..HEX 100644" (lowercase hexadecimal), then exactly '
        f'"--- a/{p}" and "+++ b/{p}" with nothing after the path, then one or more hunks.',
        '5. Each hunk header is exactly "@@ -A,B +C,D @@", where a count may be omitted when it is 1. Nothing '
        'follows the closing "@@". The counts must match the hunk body. Hunks are in file order and do not '
        "overlap.",
        '6. Every hunk body line starts with a space (context), "-" (removed) or "+" (added). An empty source '
        'line is written as a context line consisting of a single space. No other lines are allowed, including '
        'any "\\ No newline at end of file" line.',
        '7. Every added line, without its leading "+", must match one of these regular expressions in full:',
    ] + ADDED_LINE_PATTERNS + [
        "8. A DEFAULT_SSL_GROUPS value is a colon-separated list of names from: " + ", ".join(GROUP_NAMES)
        + ". No comments and no other added-line forms are allowed. You may use any subset of the allowed "
        "forms.",
        f"9. The patch is UTF-8 text of at most {MAX_PATCH_BYTES} bytes with LF line endings, ends with a "
        "newline, and contains no NUL or carriage-return characters. No line may contain any of these strings: "
        + "; ".join(FORBIDDEN_MARKERS) + ".",
        "10. The patch must change the file.",
    ]
    return "\n".join([
        "TASK",
        "Change the PostgreSQL server's compiled default list of TLS key-exchange groups (the macro "
        f"DEFAULT_SSL_GROUPS in {p}) so that the server prefers the hybrid group X25519MLKEM768 when a capable "
        "client offers it, and keeps classical groups as a fallback for clients that do not offer it.",
        "",
        "SOURCE",
        f"The source items below are data from PostgreSQL commit {PG_PIN}. Each line is shown as its line "
        "number, a colon and a space, then the line exactly as it appears in the file (an empty line is shown "
        "as its number and a colon only). The line-number prefix is not part of the file.",
        "",
    ] + src + [
        "PATCH RULES",
    ] + rules + [
        "",
        "OUTPUT",
        "Return one JSON object with these fields:",
        "- patch: the complete unified diff, as one string.",
        "- explanation: a short explanation of the change.",
        "- source_refs: the IDs of the source items the change relies on (" + ", ".join(SOURCE_IDS) + ").",
    ])


API_SCHEMA = {
    "type": "object", "additionalProperties": False, "required": ["patch", "explanation", "source_refs"],
    "properties": {
        "patch": {"type": "string"},
        "explanation": {"type": "string"},
        "source_refs": {"type": "array", "items": {"type": "string", "enum": SOURCE_IDS}},
    },
}


def build_body(max_out_param, sources):
    return {
        "model": MODEL,
        "messages": [{"role": "system", "content": SYSTEM_PROMPT},
                     {"role": "user", "content": render_user(sources)}],
        max_out_param: MAX_OUT,
        "response_format": {"type": "json_schema", "json_schema": {
            "name": "candidate_patch", "strict": True, "schema": API_SCHEMA}},
    }


def serialize_body(body):
    """The exact bytes sent. request.json records the same object; re-serializing it this way reproduces them."""
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")

# ---------------------------------------------------------------------------
# Local validation of the visible reply
# ---------------------------------------------------------------------------


class DuplicateKey(ValueError):
    pass


def _no_dupes(pairs):
    d = {}
    for k, v in pairs:
        if k in d:
            raise DuplicateKey(f"duplicate key '{k}'")
        d[k] = v
    return d


def validate_reply(text):
    """Types, sizes, schema and references only. Patch content is the gate's business, not this program's."""
    out = {"ok": False, "errors": [], "notes": []}
    if not isinstance(text, str) or not text.strip():
        out["errors"].append("empty reply")
        return out, None
    try:
        obj = json.loads(text, object_pairs_hook=_no_dupes)
    except DuplicateKey as e:
        out["errors"].append(f"invalid JSON: {e}")
        return out, None
    except ValueError as e:
        out["errors"].append(f"invalid JSON: {getattr(e, 'msg', str(e))}")
        return out, None
    errs = out["errors"]
    if not isinstance(obj, dict):
        errs.append("$: expected object")
        return out, None
    for k in obj:
        if k not in API_SCHEMA["properties"]:
            errs.append(f"$: unexpected field '{k}'")
    for k in API_SCHEMA["required"]:
        if k not in obj:
            errs.append(f"$: missing required field '{k}'")
    pt = obj.get("patch")
    if "patch" in obj:
        if not isinstance(pt, str) or not pt:
            errs.append("$.patch: expected a non-empty string")
        else:
            try:
                n = len(pt.encode("utf-8"))
                if n > MAX_PATCH_BYTES:
                    errs.append(f"$.patch: {n} UTF-8 bytes; the gate input limit is {MAX_PATCH_BYTES}")
            except UnicodeEncodeError:
                errs.append("$.patch: not encodable as UTF-8 (unpaired surrogate)")
    ex = obj.get("explanation")
    if "explanation" in obj and (not isinstance(ex, str) or not 1 <= len(ex) <= MAX_EXPLANATION_CHARS):
        errs.append(f"$.explanation: expected a string of 1 to {MAX_EXPLANATION_CHARS} characters")
    if isinstance(ex, str):
        try:
            ex.encode("utf-8")
        except UnicodeEncodeError:
            errs.append("$.explanation: not encodable as UTF-8")
    refs = obj.get("source_refs")
    if "source_refs" in obj:
        if not isinstance(refs, list) or not refs:
            errs.append("$.source_refs: expected a non-empty array")
        else:
            for j, r in enumerate(refs):
                if not isinstance(r, str):
                    errs.append(f"$.source_refs[{j}]: expected a string source id")
                elif r not in SOURCE_IDS:
                    errs.append(f"$.source_refs[{j}]: unresolved source id")
            strs = [r for r in refs if isinstance(r, str)]
            if len(set(strs)) != len(strs):
                errs.append("$.source_refs: duplicate source id")
    if errs:
        out["errors"] = errs[:20]
        return out, None
    out["ok"] = True
    if "SRC1" not in refs:
        out["notes"].append("the editable source item SRC1 is not cited")
    return out, obj

# ---------------------------------------------------------------------------
# Canonical JSON, files and the private note
# ---------------------------------------------------------------------------


def canonical(obj):
    return json.dumps(obj, sort_keys=True, indent=2, ensure_ascii=False, allow_nan=False) + "\n"


class IntegrityStop(Exception):
    """An existing evidence file differs from what the stored evidence implies. Nothing is overwritten."""


_KILL_AT = None   # self-test only: name of a checkpoint at which a test subprocess ends abruptly


def _checkpoint(name):
    if _KILL_AT == name:
        os._exit(77)


def create_atomic(path, data, mode=0o644):
    """Create path with exactly data, or fail if it exists. A crash leaves either no file or the whole file
    (plus at most a stale dot-temp file, which resume removes)."""
    tmp = path.with_name(f".{path.name}.tmp.{os.getpid()}")
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.link(str(tmp), str(path))     # fails if path exists; never replaces
    finally:
        os.unlink(str(tmp))


def put_or_verify(path, data, mode=0o644):
    """Idempotent write: create path, or verify that the existing file has exactly these bytes."""
    if path.exists() or path.is_symlink():
        if path.is_symlink() or not path.is_file() or path.read_bytes() != data:
            raise IntegrityStop(f"{path.name} exists and differs from what the stored evidence implies; "
                                "not overwritten")
        return "verified"
    create_atomic(path, data, mode)
    return "written"


def write_canonical(path, obj, replace=False):
    data = canonical(obj).encode("utf-8")
    if not replace:
        create_atomic(path, data)
        return
    tmp = path.with_name("." + path.name + ".tmp")
    if tmp.exists() or tmp.is_symlink():
        tmp.unlink()
    with open(tmp, "xb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def write_new(path, data, mode=0o644):
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())


def file_sha(path):
    return sha256(Path(path).read_bytes())


def note(path, entry):
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, sort_keys=True) + "\n")
        f.flush()
        os.fsync(f.fileno())


def read_note(path):
    """Entries of a private JSON-lines note. Raises ValueError on a malformed line."""
    if not path.exists():
        return []
    out = []
    for i, ln in enumerate(path.read_text(encoding="utf-8").splitlines()):
        if ln.strip():
            e = json.loads(ln)
            if not isinstance(e, dict):
                raise ValueError(f"line {i + 1} is not an object")
            out.append(e)
    return out

# ---------------------------------------------------------------------------
# Sanitizing (adapted from shaar.py)
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
# Budget basis and reconciliation of earlier reservations
# ---------------------------------------------------------------------------


def is_num(v):
    return isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v)


def ceil_usd(x):
    return math.ceil(round(x * 1e6, 3)) / 1e6


def prior_reservations(note_dir):
    """Every sent or possibly sent allowance recorded before this request, each counted once.
    Returns (items, problems)."""
    items, problems = [], []
    try:
        led = json.loads(PROBE_LEDGER.read_text())
        if led.get("format") != PROBE_LEDGER_FORMAT:
            raise ValueError("format")
        att = [a for a in led["attempts"] if a.get("sent")]
        usd = round(sum(a["cost_bound"]["usd"] for a in att), 6)
        if not is_num(usd) or usd < 0:
            raise ValueError("value")
        items.append({"source": "evidence/event/capability-probe/probe-results.json", "kind": "capability probe",
                      "requests": len(att), "usd": usd})
    except (OSError, ValueError, KeyError, TypeError):
        problems.append("capability-probe ledger unreadable")
    seen = set()
    if CLI_RUNS_DIR.is_dir():
        for d in sorted(CLI_RUNS_DIR.iterdir()):
            seen.add(d.name)
            try:
                a = json.loads((d / "accounting.json").read_text())
                if a.get("format") != CLI_ACCOUNTING_FORMAT or a.get("run_id") != d.name:
                    raise ValueError("format")
                sent, usd = a["attempt"]["sent"], a["attempt"]["allowance"]["usd"]
                if not is_num(usd) or usd < 0 or sent not in ("yes", "unknown", "in_flight", "no"):
                    raise ValueError("value")
            except (OSError, ValueError, KeyError, TypeError):
                problems.append(f"shaar.py run {d.name}: accounting unreadable")
                continue
            if sent != "no":
                items.append({"source": f"evidence/event/runs/{d.name}/accounting.json", "kind": "shaar.py run",
                              "requests": 1, "sent": sent, "usd": usd})
    try:
        entries = read_note(note_dir / CLI_NOTE_NAME)
    except (OSError, ValueError, UnicodeDecodeError):
        entries, _ = [], problems.append("shaar.py private note unreadable")
    by_run = {}
    for e in entries:
        by_run.setdefault(e.get("run_id"), []).append(e)
    for rid, es in sorted(by_run.items(), key=lambda x: str(x[0])):
        if rid in seen:
            continue          # counted from the evidence above
        if any(str(e.get("event", "")).startswith("not sent") for e in es):
            continue
        usd = max([e.get("allowance_usd") for e in es if is_num(e.get("allowance_usd"))] or [None], key=lambda v: v or 0)
        if usd is None:
            problems.append(f"shaar.py private note: attempt {rid!r} has no allowance")
            continue
        items.append({"source": "shaar.py private note (no evidence in the repository)", "kind": "shaar.py run",
                      "requests": 1, "sent": "unknown", "usd": usd, "run_id": str(rid)})
    return items, problems


def load_basis(config_path):
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
    if str(api.get("base_url") or "").rstrip("/") + str(api.get("chat_path") or "") != ENDPOINT:
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
    items, p2 = prior_reservations(cp.parent)
    problems += p2
    if problems:
        return None, problems
    prior = round(sum(i["usd"] for i in items), 6)
    dev_left = round(rem - reserve - prior, 6)
    basis = {
        "max_out_param": api["max_out_param"],
        "input_usd_per_mtok": m["input_usd_per_mtok"], "output_usd_per_mtok": m["output_usd_per_mtok"],
        "reasoning": r,
        "probe_request_max_out": m.get("request_max_out"),
        "pricing_doc": {k: docs[m["pricing_doc"]].get(k) for k in ("id", "title", "url", "retrieved")},
        "reasoning_doc": {k: docs[m["reasoning_doc"]].get(k) for k in ("id", "title", "url", "retrieved")},
        "budget": {
            "remaining_usd_billing_console_before_probing": rem, "final_reserve_usd": reserve,
            "prior_reservations": items, "prior_committed_allowance_usd": prior,
            "development_headroom_usd": dev_left, "subcap_usd": SUBCAP_USD,
            "headroom_usd": round(min(SUBCAP_USD, dev_left), 6),
            "basis_note": ("billing-console balance as recorded before probing, minus the final-run reserve, minus "
                           "every earlier sent or possibly sent allowance; observed billing is not read"),
        },
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
        "Accept": "application/json", "User-Agent": "shaar-candidate/1"})
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


def response_doc(r, scrub):
    """The visible parts of a transport result. Message content is kept verbatim (it may become the patch);
    everything else is sanitized. Returns (doc, private_verbatim_or_None)."""
    obj = None
    if r.get("body") is not None:
        try:
            obj = json.loads(r["body"].decode("utf-8", "replace"))
        except ValueError:
            obj = None
    doc = {"format": F_RESPONSE, "proposal_id": PROPOSAL_ID,
           "transport": {"http_status": r.get("status"), "sent": r.get("sent"), "timeout": bool(r.get("timeout")),
                         "redirect_refused": bool(r.get("redirect"))},
           "reply": None, "error": None, "sanitizer": {"content_changed": False}}
    private = None
    if r.get("redirect"):
        doc["transport"]["outcome"] = "REDIRECT_REFUSED"
        doc["error"] = {"message": scrub(r.get("error") or "")[:300]}
    elif r.get("status") == 200 and isinstance(obj, dict) and isinstance(obj.get("choices"), list) and obj["choices"]:
        ch = obj["choices"][0] if isinstance(obj["choices"][0], dict) else {}
        msg = ch.get("message") if isinstance(ch.get("message"), dict) else {}
        content = msg.get("content")
        if isinstance(content, list):
            content = "".join(p.get("text", "") for p in content if isinstance(p, dict) and isinstance(p.get("text"), str))
        if not isinstance(content, str):
            content = None
        if content is not None and scrub(content) != content:
            private, content = content, scrub(content)
            doc["sanitizer"]["content_changed"] = True
        ref = msg.get("refusal")
        if ref is None or ref == "":
            refusal = None
        elif isinstance(ref, str):
            refusal = scrub(ref)[:500]
        else:
            refusal = f"[refusal field of type {type(ref).__name__}; not stored]"
        tc = msg.get("tool_calls")
        doc["reply"] = {
            "response_id": scrub(str(obj["id"])[:200]) if obj.get("id") is not None else None,
            "model_returned": scrub(str(obj["model"])[:200]) if obj.get("model") is not None else None,
            "choices_returned": len(obj["choices"]),
            "finish_reason": scrub(str(ch.get("finish_reason")))[:50] if ch.get("finish_reason") is not None else None,
            "content": content,
            "refusal": refusal,
            "tool_calls_returned": 0 if tc is None else (len(tc) if isinstance(tc, list) else f"malformed ({type(tc).__name__})"),
            "usage": numeric_only(obj.get("usage")),
            "message_fields_not_stored": sorted(str(k) for k in msg if k not in ("role", "content", "refusal", "tool_calls")),
        }
        doc["transport"]["outcome"] = "REPLY_RECORDED"
    elif r.get("status") is not None:
        doc["transport"]["outcome"] = "UNEXPECTED_RESPONSE" if r["status"] == 200 else "HTTP_ERROR"
        if isinstance(obj, dict) and isinstance(obj.get("error"), dict):
            e = obj["error"]
            doc["error"] = {k: scrub(str(e[k])[:500]) for k in ("type", "code", "param", "message") if e.get(k) is not None}
        elif isinstance(obj, dict) and isinstance(obj.get("error"), str):
            doc["error"] = {"message": scrub(obj["error"][:500])}
        else:
            doc["error"] = {"message": scrub((r.get("body") or b"").decode("utf-8", "replace")[:300]),
                            "note": "non-JSON body or unexpected shape; first 300 characters"}
    else:
        doc["transport"]["outcome"] = "NOT_SENT" if r.get("sent") == "no" else "TRANSPORT_UNKNOWN"
        doc["error"] = {"message": scrub(r.get("error") or "")[:300]}
    return doc, private


def usage_check(usage, bound, basis_reasoning, prices):
    est, warnings = None, []
    if usage:
        i = find_num(usage, "prompt_tokens")
        i = find_num(usage, "input_tokens") if i is None else i
        o = find_num(usage, "completion_tokens")
        o = find_num(usage, "output_tokens") if o is None else o
        rsn = find_num(usage, "reasoning_tokens")
        if is_num(i) and is_num(o):
            est = round(i * prices[0] / 1e6 + o * prices[1] / 1e6, 6)
        if any(is_num(x) and x < 0 for x in (i, o, rsn)):
            warnings.append("negative usage reported; cost data invalid")
        if is_num(i) and i > bound["input_units_bound"]:
            warnings.append("reported input units exceed the input allowance")
        if is_num(o) and o > bound["output_units_bound"]:
            warnings.append("reported output units exceed the output allowance")
        if is_num(rsn) and rsn > bound["output_units_bound"]:
            warnings.append("reported reasoning units exceed the output allowance")
        if basis_reasoning == "none" and is_num(rsn) and rsn > 0:
            warnings.append("reasoning units reported for a model recorded as non-reasoning")
    if est is None:
        warnings.append("usage missing or not in a recognized form; cost data unavailable")
    return est, warnings

# ---------------------------------------------------------------------------
# Finalizing a proposal from the files on disk (shared by send and resume)
# ---------------------------------------------------------------------------

DISCLOSURE = (
    "The request asks for a hybrid-first default with classical fallback and supplies the gate's patch-format "
    "rules and added-line allowlist, including the permitted OpenSSL-version-conditional line forms. It does not "
    "state the OpenSSL 3.0 compatibility requirement that the gate enforces, the gate's two-library test matrix, "
    "or any fixture. This is a constrained, partially specified task, not a test of a fully specified "
    "compatibility request. The allowlist sharply limits the shape of any patch. No repair prompt was sent.")

UNCERTAINTY = [
    "The model's reasoning is not visible and is not stored; only the visible reply is recorded.",
    "Usage figures are as reported by the provider; observed billing is PENDING.",
    "The allowance is an assumption-based bound, not a provider-enforced spending cap.",
    "The gate records origin 'external'; it makes no authorship claim. The model-origin claim rests on this "
    "record: the gate input SHA-256 must equal patch.sha256 in this record.",
]


def proposal_paths(pid=None):
    d = PROPOSALS_DIR / (pid or PROPOSAL_ID)
    return {k: d / f"{k}.json" for k in ("request", "source", "response", "record", "accounting", "failure")}, d


def finalize(run_dir, latency_ms):
    """Turn the files on disk into record.json (+ candidate.patch or failure.json). Idempotent: an artifact
    that already exists is verified byte for byte and kept; any difference raises IntegrityStop and nothing
    is overwritten. Returns (complete, reasons). Makes no network call."""
    paths, _ = proposal_paths()
    paths = {k: run_dir / v.name for k, v in paths.items()}
    req = json.loads(paths["request"].read_text(encoding="utf-8")) if paths["request"].exists() else None
    acct = json.loads(paths["accounting"].read_text(encoding="utf-8"))
    resp = json.loads(paths["response"].read_text(encoding="utf-8"))
    bound = acct["attempt"]["allowance"]
    reply, reasons, validation, obj = resp.get("reply"), [], None, None
    sent = resp["transport"]["sent"]
    est, warnings = None, []
    if reply is not None:
        validation, obj = validate_reply(reply["content"])
        if not validation["ok"]:
            reasons.append("local validation failed")
        if resp["sanitizer"]["content_changed"]:
            reasons.append("visible reply matched the sanitizer; published copy is sanitized; patch not extracted")
        if reply["refusal"] is not None:
            reasons.append("the model returned a refusal")
        if reply["finish_reason"] != "stop":
            reasons.append(f"finish_reason is {reply['finish_reason']!r}, not 'stop'")
        if reply["model_returned"] != MODEL:
            reasons.append(f"returned model id {reply['model_returned']!r} differs from the requested {MODEL!r}")
        if reply["choices_returned"] != 1:
            reasons.append(f"{reply['choices_returned']} choices returned; expected 1")
        if reply["tool_calls_returned"] != 0:
            reasons.append("tool calls returned; none were offered and none are executed")
        est, warnings = usage_check(reply["usage"], bound, acct["basis"]["reasoning"],
                                    (acct["basis"]["input_usd_per_mtok"], acct["basis"]["output_usd_per_mtok"]))
    else:
        reasons.append(f"no reply recorded ({resp['transport'].get('outcome')})")
    reasons += ["warning: " + w for w in warnings]
    complete = not reasons
    if req is None and sent != "no":
        raise IntegrityStop("request.json is missing but the response does not record 'not sent'")
    body_sha = acct["attempt"].get("body_sha256") or (req or {}).get("body_sha256")
    if req is not None and body_sha != req["body_sha256"]:
        raise IntegrityStop("accounting.json and request.json record different request bodies")
    if complete and paths["failure"].exists():
        raise IntegrityStop("failure.json exists but the stored reply gives a complete proposal; not overwritten")
    if not complete and (run_dir / "candidate.patch").exists():
        raise IntegrityStop("candidate.patch exists but the stored reply gives an incomplete proposal; not overwritten")
    old_sent = acct["attempt"].get("sent")
    if old_sent not in ("in_flight", sent):
        raise IntegrityStop(f"accounting.json records sent {old_sent!r}; the response records {sent!r}")
    patch = None
    if complete:
        data = obj["patch"].encode("utf-8")          # encoded exactly once; no other transformation
        put_or_verify(run_dir / "candidate.patch", data, 0o444)
        if (run_dir / "candidate.patch").read_bytes() != data:
            raise IntegrityStop("candidate.patch read-back differs")
        _checkpoint("patch")
        patch = {"file": "candidate.patch", "sha256": sha256(data), "bytes": len(data),
                 "derivation": "json.loads(response.json reply.content)['patch'].encode('utf-8'); no trimming, "
                               "line-ending change or repair"}
    files = {k: file_sha(paths[k]) for k in ("request", "source", "response") if paths[k].exists()}
    record = {
        "format": F_RECORD, "proposal_id": PROPOSAL_ID,
        "task": {"id": TASK_ID, "input_label": "authenticated upstream source excerpts",
                 "source_ids": SOURCE_IDS},
        "files_sha256": {k + ".json": v for k, v in files.items()},
        "request_body_sha256": body_sha,
        "model": {"requested": MODEL, "returned": reply["model_returned"] if reply else None},
        "transport": {"http_status": resp["transport"]["http_status"], "sent": sent,
                      "outcome": resp["transport"].get("outcome")},
        "validation": validation,
        "proposal": {"status": "complete" if complete else "incomplete", "incomplete_reasons": reasons},
        "patch": patch,
        "gate": {"run_id": GATE_RUN_ID if complete else None, "origin": GATE_ORIGIN, "reference_run": GATE_REFERENCE,
                 "input_sha256_required": patch["sha256"] if patch else None, "verdict": None,
                 "note": ("the verdict is decided only by gate/check.py and lives only in "
                          "evidence/event/gate-runs/%s/verdict.json" % GATE_RUN_ID) if complete else
                 "no usable patch; nothing is submitted to the gate"},
        "reader_disclosure": {"sent_to_model": False, "text": DISCLOSURE},
        "uncertainty": UNCERTAINTY,
    }
    if not complete:
        put_or_verify(paths["failure"], canonical({
            "format": F_FAILURE, "proposal_id": PROPOSAL_ID, "kind": "proposal", "derived_from": "response.json",
            "transport_outcome": resp["transport"].get("outcome"), "sent": sent, "reasons": reasons,
            "validation_errors": (validation or {}).get("errors"), "gate": "not run: no usable patch",
            "note": "an incomplete or refused proposal is not a gate rejection"}).encode("utf-8"))
        _checkpoint("failure")
    timing = acct["attempt"].get("timing")
    if latency_ms is not None or not timing:
        timing = {"latency_ms": latency_ms}
    acct["attempt"].update(sent=sent, timing=timing, warnings=warnings,
                           usage_estimate_usd=est if est is not None else "UNKNOWN")
    if sent == "no":
        acct["headroom_after_usd"] = acct["budget_before"]["headroom_usd"]
        acct["cumulative_committed_allowance_usd"] = acct["budget_before"]["prior_committed_allowance_usd"]
        acct["note"] = "the request did not leave this computer; no allowance is counted"
    write_canonical(paths["accounting"], acct, replace=True)
    _checkpoint("final-accounting")
    put_or_verify(paths["record"], canonical(record).encode("utf-8"))
    _checkpoint("record")
    return complete, reasons

# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


def refuse(msg):
    print("REFUSED (nothing sent): " + msg)
    return EXIT_REFUSED


def prepared(pg_git):
    sources = load_sources(make_reader(pg_git))
    return sources


def make_reader(pg_git):
    return git_reader(pg_git)


def print_request(body, raw):
    for m in body["messages"]:
        print(f"----- message role={m['role']} ({len(m['content'].encode('utf-8'))} bytes) -----")
        print(m["content"])
    print("----- response_format -----")
    print(canonical(body["response_format"]), end="")
    print(f"----- request body: {len(raw)} bytes, SHA-256 {sha256(raw)} -----")


def cmd_render(args):
    try:
        sources = prepared(args.pg_git)
    except (ValueError, OSError, subprocess.SubprocessError) as e:
        print(f"STOP: source not authenticated: {e}")
        return EXIT_INCOMPLETE
    body = build_body(args.max_out_param, sources)
    raw = serialize_body(body)
    print_request(body, raw)
    for s in sources:
        print(f"{s['id']}: {s['path']} lines {s['first_line']}-{s['last_line']} excerpt SHA-256 {s['excerpt_sha256']} "
              f"| file blob {s['file_git_blob']} SHA-256 {s['file_sha256']}")
    if args.out:
        out = Path(args.out).expanduser().resolve()
        if REPO == out or REPO in out.parents:
            print("STOP: --out must be outside the repository")
            return EXIT_NA
        write_new(out, raw, 0o600)
        print(f"wrote request body to --out ({len(raw)} bytes)")
    print("RENDER DONE (nothing sent)")
    return EXIT_OK


def own_attempts(note_path):
    try:
        return read_note(note_path)
    except (OSError, ValueError, UnicodeDecodeError):
        return None


def initial_accounting(basis, bound, raw):
    bb = basis["budget"]
    return {
        "format": F_ACCOUNTING, "proposal_id": PROPOSAL_ID,
        "attempt": {"number": 1, "of_allowed": 1, "kind": "primary", "sent": "in_flight", "allowance": bound,
                    "body_bytes": len(raw) if isinstance(raw, bytes) else raw[0],
                    "body_sha256": sha256(raw) if isinstance(raw, bytes) else raw[1],
                    "usage_estimate_usd": "UNKNOWN", "billing": "PENDING", "timing": None, "warnings": []},
        "basis": {k: basis[k] for k in ("input_usd_per_mtok", "output_usd_per_mtok", "reasoning", "max_out_param",
                                        "probe_request_max_out", "pricing_doc", "reasoning_doc")},
        "budget_before": bb,
        "headroom_after_usd": round(bb["headroom_usd"] - bound["usd"], 6),
        "cumulative_committed_allowance_usd": round(bb["prior_committed_allowance_usd"] + bound["usd"], 6),
        "note": "allowance is counted in full for every sent or possibly sent request",
    }


def cmd_send(args):
    paths, run_dir = proposal_paths()
    if PROPOSALS_DIR.exists() and any(PROPOSALS_DIR.iterdir()):
        return refuse("a proposal directory already exists; this revision records one proposal only (see resume)")
    key = os.environ.get(KEY_ENV, "")
    if not key or re.search(r"\s", key):
        return refuse(f"{KEY_ENV} is not set or contains whitespace")
    basis, problems = load_basis(args.config)
    if problems:
        return refuse("; ".join(problems))
    prior = own_attempts(basis["note_path"])
    if prior is None:
        return refuse("private candidate note unreadable")
    if prior:
        return refuse("the private candidate note already records an attempt; no second request (see resume)")
    try:
        sources = prepared(args.pg_git)
    except (ValueError, OSError, subprocess.SubprocessError) as e:
        return refuse(f"source not authenticated: {e}")
    body = build_body(basis["max_out_param"], sources)
    raw = serialize_body(body)
    if len(raw) > MAX_REQUEST_BYTES:
        return refuse(f"request body is {len(raw)} bytes; limit {MAX_REQUEST_BYTES}")
    bound = allowance(len(raw), basis)
    bb = basis["budget"]
    print(f"route: {ENDPOINT} | model: {MODEL} | request body: {len(raw)} bytes, SHA-256 {sha256(raw)} | "
          f"{basis['max_out_param']}: {MAX_OUT}")
    print(f"prices (per million units): input ${basis['input_usd_per_mtok']} output ${basis['output_usd_per_mtok']} "
          f"[{basis['pricing_doc']['id']}] | reasoning: {basis['reasoning']} [{basis['reasoning_doc']['id']}]")
    print(f"allowance for this request: ${bound['usd']:.6f} (input <= {bound['input_units_bound']}, "
          f"output <= {bound['output_units_bound']}; {INPUT_ASSUMPTION})")
    for it in bb["prior_reservations"]:
        print(f"  prior reservation: ${it['usd']:.6f} from {it['source']} ({it['requests']} request(s))")
    print(f"prior committed allowance: ${bb['prior_committed_allowance_usd']:.6f} | development headroom: "
          f"${bb['development_headroom_usd']:.6f} | subcap ${SUBCAP_USD:.2f} | headroom ${bb['headroom_usd']:.6f}")
    print(f"{KEY_ENV}: present (not printed)")
    if bound["usd"] > bb["headroom_usd"]:
        return refuse(f"allowance ${bound['usd']:.6f} exceeds headroom ${bb['headroom_usd']:.6f}")
    if args.preflight:
        print("PREFLIGHT PASS (nothing sent, nothing written)")
        return EXIT_OK

    scrub = Scrub(key)
    note_path = basis["note_path"]
    base_note = {"proposal_id": PROPOSAL_ID, "allowance_usd": bound["usd"], "model": MODEL,
                 "body_sha256": sha256(raw), "body_bytes": len(raw), "wall_clock_utc": int(time.time())}
    try:
        note(note_path, dict(base_note, event="reserving"))
    except OSError as e:
        return refuse(f"private candidate note not writable ({type(e).__name__})")
    try:
        PROPOSALS_DIR.mkdir(parents=True, exist_ok=True)
        run_dir.mkdir()  # exclusive
        _checkpoint("dir")
        write_canonical(paths["source"], {"format": F_SOURCE, "proposal_id": PROPOSAL_ID, "items": [
            {k: s[k] for k in ("id", "path", "commit", "first_line", "last_line", "role", "lines", "excerpt_sha256",
                               "file_git_blob", "file_sha256", "file_bytes")} for s in sources],
            "note": "excerpts read with git show at the pin; SRC1 checked against the gate policy's pinned blob "
                    "and SHA-256; SRC2's line checked against the pinned text"})
        _checkpoint("source")
        write_canonical(paths["request"], {
            "format": F_REQUEST, "proposal_id": PROPOSAL_ID, "endpoint": ENDPOINT, "body": body,
            "body_bytes": len(raw), "body_sha256": sha256(raw),
            "serialization": "json.dumps(body, sort_keys=True, separators=(',', ':')) encoded as UTF-8",
            "headers_recorded": "none", "tools_offered": "none", "retries": 0})
        _checkpoint("request")
        write_canonical(paths["accounting"], initial_accounting(basis, bound, raw))
        _checkpoint("accounting")
    except OSError as e:
        try:
            note(note_path, dict(base_note, event="not sent: evidence before the request not written"))
        except OSError:
            pass
        print(f"STOP (nothing sent): evidence before the request not written ({type(e).__name__})")
        return EXIT_INCOMPLETE

    # From here on nothing may escape: every path keeps the allowance and updates the note.
    try:
        r = post(raw, key)
    except BaseException as e:  # post() handles ordinary errors; this covers interrupts
        r = {"status": None, "body": None, "sent": "unknown", "timeout": False, "redirect": False,
             "error": f"interrupted during the request: {type(e).__name__}", "latency_ms": None}
    _checkpoint("post")
    try:
        note(note_path, dict(base_note, event="received", sent=r.get("sent"), latency_ms=r.get("latency_ms")))
    except BaseException:
        print("WARNING: private candidate note not updated after the request")
    complete, reasons, written = False, ["evidence not finalized"], False
    try:
        doc, private = response_doc(r, scrub)
        if private is not None:
            note(note_path.with_name(PROPOSAL_ID + ".verbatim-reply.txt"), {"content": private})
        write_canonical(paths["response"], doc)
        _checkpoint("response")
        complete, reasons = finalize(run_dir, r.get("latency_ms"))
        written = True
    except BaseException as e:
        print(f"STOP: evidence finalization failed ({type(e).__name__}); the private note keeps the attempt; "
              "run resume (no model call)")
    try:
        note(note_path, dict(base_note, event="finished", sent=r.get("sent"), latency_ms=r.get("latency_ms"),
                             finalized=written, proposal="complete" if complete and written else "incomplete"))
    except BaseException:
        print("WARNING: private candidate note not updated")
    return summarize(run_dir, written and complete)


def summarize(run_dir, complete):
    try:
        rec = json.loads((run_dir / "record.json").read_text(encoding="utf-8"))
        resp = json.loads((run_dir / "response.json").read_text(encoding="utf-8"))
        acct = json.loads((run_dir / "accounting.json").read_text(encoding="utf-8"))
        t, rp = resp["transport"], resp.get("reply")
        print(f"{PROPOSAL_ID}: HTTP {t['http_status']} | sent: {t['sent']} | outcome: {t.get('outcome')}")
        if rp:
            print(f"  model requested: {MODEL} | returned: {rp['model_returned']} | finish: {rp['finish_reason']} | "
                  f"refusal: {'yes' if rp['refusal'] is not None else 'no'} | tool calls: {rp['tool_calls_returned']}")
            print(f"  usage: {json.dumps(rp['usage'], sort_keys=True)}")
        v = rec.get("validation")
        if v:
            print(f"  local validation: {'PASS' if v['ok'] else 'FAIL'}" + "".join("\n    error: " + e for e in v["errors"][:5])
                  + "".join("\n    note: " + n for n in v["notes"]))
        if resp.get("error"):
            print("  error (sanitized): " + json.dumps(resp["error"], sort_keys=True)[:400])
        for x in rec["proposal"]["incomplete_reasons"]:
            print("  INCOMPLETE: " + x)
        if rec.get("patch"):
            print(f"  candidate.patch: {rec['patch']['bytes']} bytes, SHA-256 {rec['patch']['sha256']}")
        a = acct["attempt"]
        print(f"  allowance ${a['allowance']['usd']:.6f} | usage estimate {a['usage_estimate_usd']} | billing "
              f"{a['billing']} | latency {(a.get('timing') or {}).get('latency_ms')} ms | cumulative committed "
              f"${acct['cumulative_committed_allowance_usd']:.6f}")
    except BaseException as e:
        print(f"WARNING: summary not printed ({type(e).__name__}); see the proposal files")
    if complete:
        print("PROPOSAL COMPLETE; GATE NOT YET RUN")
        return EXIT_OK
    print("PROPOSAL INCOMPLETE; NO GATE RUN")
    return EXIT_INCOMPLETE


STALE_TMP = re.compile(r"^\..+\.tmp(\.[0-9]+)?$")


def verify_final(run_dir):
    """Problems with an already final proposal: hashes in record.json and the patch/failure invariant."""
    probs = []
    rec = json.loads((run_dir / "record.json").read_text(encoding="utf-8"))
    for k, v in rec["files_sha256"].items():
        if not (run_dir / k).is_file() or file_sha(run_dir / k) != v:
            probs.append(f"{k} differs from the hash in record.json")
    cp = run_dir / "candidate.patch"
    if rec["proposal"]["status"] == "complete":
        if not cp.is_file() or sha256(cp.read_bytes()) != rec["patch"]["sha256"]:
            probs.append("candidate.patch missing or differs from record.json")
        fl = run_dir / "failure.json"
        if fl.exists() and json.loads(fl.read_text(encoding="utf-8")).get("kind") == "proposal":
            probs.append("proposal failure.json present for a complete proposal")
    else:
        if cp.exists():
            probs.append("candidate.patch present for an incomplete proposal")
        if not (run_dir / "failure.json").is_file():
            probs.append("failure.json missing for an incomplete proposal")
    return probs


def cmd_resume(args):
    """Finalize an interrupted attempt from the files on disk. Never sends; never overwrites evidence."""
    paths, run_dir = proposal_paths()
    if not run_dir.is_dir():
        print("NOT APPLICABLE: no proposal directory; if the private note records 'reserving', nothing was sent "
              "(the directory is reserved before sending)")
        return EXIT_NA
    for f in sorted(run_dir.iterdir()):
        if STALE_TMP.match(f.name) and f.is_file() and not f.is_symlink():
            f.unlink()
            print(f"removed stale temporary file {f.name} (never linked into the evidence)")
    if paths["record"].exists():
        probs = verify_final(run_dir)
        for p in probs:
            print("  PROBLEM: " + p)
        if probs:
            print("STOP: final proposal evidence is inconsistent; nothing changed")
            return EXIT_INCOMPLETE
        print("NOT APPLICABLE: proposal already final (record.json exists and verifies); nothing changed")
        return EXIT_NA
    note_path = Path(args.config).expanduser().resolve().parent / NOTE_NAME if args.config else None
    entries = (own_attempts(note_path) or []) if note_path else []
    not_sent = False
    if not paths["accounting"].exists():
        # accounting.json is the last file written before the request, so the request was not sent.
        if not args.config:
            print("STOP: accounting.json is missing (the request was not sent); pass --config to finalize")
            return EXIT_INCOMPLETE
        res = next((e for e in entries if e.get("event") == "reserving" and e.get("proposal_id") == PROPOSAL_ID), None)
        basis, problems = load_basis(args.config)
        if res is None or problems or not isinstance(res.get("body_bytes"), int):
            print("STOP: cannot rebuild the accounting basis (private note or config): " + "; ".join(problems))
            return EXIT_INCOMPLETE
        bound = allowance(res["body_bytes"], basis)
        if bound["usd"] != res.get("allowance_usd"):
            print("STOP: recomputed allowance differs from the private note; nothing written")
            return EXIT_INCOMPLETE
        if paths["request"].exists():
            rq = json.loads(paths["request"].read_text(encoding="utf-8"))
            if (rq["body_sha256"], rq["body_bytes"]) != (res.get("body_sha256"), res["body_bytes"]):
                print("STOP: request.json differs from the private note; nothing written")
                return EXIT_INCOMPLETE
        write_canonical(paths["accounting"], initial_accounting(basis, bound, (res["body_bytes"], res["body_sha256"])))
        not_sent = True
        print("accounting.json was missing: the request was not sent (accounting is written before sending)")
    latency = next((e.get("latency_ms") for e in reversed(entries)
                    if e.get("event") in ("received", "finished") and e.get("latency_ms") is not None), None)
    if not paths["response"].exists():
        if not_sent:
            r = {"status": None, "body": None, "sent": "no", "timeout": False, "redirect": False,
                 "error": "interrupted before the request was sent"}
        else:
            r = {"status": None, "body": None, "sent": "unknown", "timeout": False, "redirect": False,
                 "error": "reply not recorded: the process ended after the request may have been sent"}
        doc, _ = response_doc(r, Scrub(None))
        write_canonical(paths["response"], doc)
    try:
        complete, _ = finalize(run_dir, latency)
    except IntegrityStop as e:
        print(f"STOP: {e}. Evidence kept as found; report this.")
        return EXIT_INCOMPLETE
    except (OSError, ValueError, KeyError, TypeError) as e:
        print(f"STOP: finalization failed ({type(e).__name__}: {e}). Evidence kept as found; report this.")
        return EXIT_INCOMPLETE
    if note_path is not None:
        try:
            note(note_path, {"proposal_id": PROPOSAL_ID, "event": "finalized by resume",
                             "proposal": "complete" if complete else "incomplete", "wall_clock_utc": int(time.time())})
        except OSError:
            print("WARNING: private candidate note not updated")
    print("RESUME: finalized from files on disk; zero model calls")
    return summarize(run_dir, complete)


def gate_files_for(run_id):
    d = GATE_RUNS_DIR / run_id
    v = json.loads((d / "verdict.json").read_text(encoding="utf-8"))
    o = json.loads((d / "observations.json").read_text(encoding="utf-8"))
    return d, v, o


def chain_problems():
    """Provenance chain from the visible reply to the gate snapshot. Returns (problems, facts)."""
    probs, facts = [], {}
    paths, run_dir = proposal_paths()
    rec = json.loads(paths["record"].read_text(encoding="utf-8"))
    resp = json.loads(paths["response"].read_text(encoding="utf-8"))
    if paths["request"].exists():
        req = json.loads(paths["request"].read_text(encoding="utf-8"))
        raw = serialize_body(req["body"])
        facts["request_body_sha256"] = sha256(raw)
        if (sha256(raw) != req["body_sha256"] or len(raw) != req["body_bytes"]
                or rec["request_body_sha256"] != req["body_sha256"]):
            probs.append("request body does not re-serialize to the recorded SHA-256")
    elif rec["transport"]["sent"] != "no":
        probs.append("request.json missing for a request that was sent or possibly sent")
    else:
        facts["request"] = "not written; the request was not sent"
    probs += verify_final(run_dir)
    facts["proposal"] = rec["proposal"]["status"]
    if rec["proposal"]["status"] != "complete":
        return probs, facts
    _, obj = validate_reply(resp["reply"]["content"])
    decoded = obj["patch"].encode("utf-8") if obj else None
    cp = (run_dir / "candidate.patch").read_bytes()
    facts["patch_sha256"] = sha256(cp)
    if decoded != cp or sha256(cp) != rec["patch"]["sha256"] or len(cp) != rec["patch"]["bytes"]:
        probs.append("candidate.patch differs from the decoded reply patch or from record.json")
    gd = GATE_RUNS_DIR / GATE_RUN_ID
    if not (gd / "verdict.json").exists():
        facts["gate"] = "not run"
        return probs, facts
    _, v, o = gate_files_for(GATE_RUN_ID)
    snap = (gd / "candidate.patch").read_bytes() if (gd / "candidate.patch").exists() else None
    if snap != cp:
        probs.append("gate snapshot differs from candidate.patch")
    inp = o.get("input") or {}
    if inp.get("sha256") != sha256(cp) or (v.get("patch") or {}).get("sha256") != sha256(cp):
        probs.append("gate input/verdict SHA-256 differs from candidate.patch")
    if inp.get("origin") != GATE_ORIGIN or inp.get("derived_from") is not None:
        probs.append("gate origin is not external / derived_from is set")
    if (v.get("reference_run") or {}).get("run_id") != GATE_REFERENCE:
        probs.append("gate reference run is not %s" % GATE_REFERENCE)
    facts.update(gate=v.get("outcome"), gate_identity=v.get("gate_identity"), counts=v.get("counts"),
                 verdict_sha256=file_sha(gd / "verdict.json"))
    return probs, facts


def cmd_link(_args):
    try:
        probs, facts = chain_problems()
    except (OSError, ValueError, KeyError, TypeError) as e:
        print(f"LINK FAIL: evidence unreadable ({type(e).__name__}: {e})")
        return EXIT_INCOMPLETE
    for k in sorted(facts):
        print(f"  {k}: {json.dumps(facts[k], sort_keys=True)}")
    for p in probs:
        print("  PROBLEM: " + p)
    print("LINK " + ("PASS" if not probs else "FAIL") + " (zero model calls)")
    return EXIT_OK if not probs else EXIT_INCOMPLETE


def log_tail(gd, rel, scrub, n=15, cap=1500):
    if not isinstance(rel, str) or rel.startswith("/") or ".." in rel.split("/"):
        return None
    p = gd / rel
    if not p.is_file():
        return None
    data = p.read_bytes()
    t = "\n".join(data.decode("utf-8", "replace").splitlines()[-n:])
    return {"log": rel, "log_sha256": sha256(data), "tail": scrub(t[-cap:]), "lines": n, "max_chars": cap}


def cmd_derive_failure(_args):
    """Structured gate-failure report copied from the gate's own files. No model call, no verdict of its own."""
    paths, run_dir = proposal_paths()
    try:
        probs, facts = chain_problems()
    except (OSError, ValueError, KeyError, TypeError) as e:
        print(f"STOP: evidence unreadable ({type(e).__name__})")
        return EXIT_INCOMPLETE
    if probs:
        for p in probs:
            print("  PROBLEM: " + p)
        print("STOP: provenance chain broken; failure.json not written")
        return EXIT_INCOMPLETE
    if facts.get("gate") in (None, "not run"):
        print("NOT APPLICABLE: no gate verdict for this proposal")
        return EXIT_NA
    if facts["gate"] == "ACCEPT":
        print("NOT APPLICABLE: the gate verdict is ACCEPT; no failure report")
        return EXIT_NA
    if paths["failure"].exists():
        print("NOT APPLICABLE: failure.json already exists; nothing changed")
        return EXIT_NA
    gd, v, o = gate_files_for(GATE_RUN_ID)
    scrub = Scrub(None)
    by = lambda r: sorted(c["id"] for c in v["checks"] if c["result"] == r)
    excerpts = {}
    for cid in by("FAIL") + by("BLOCKED"):
        t = log_tail(gd, (o["receipts"].get(cid) or {}).get("log"), scrub)
        if t:
            excerpts[cid] = t
    write_canonical(paths["failure"], {
        "format": F_FAILURE, "proposal_id": PROPOSAL_ID, "kind": "gate", "gate_run_id": GATE_RUN_ID,
        "derived_from": [f"evidence/event/gate-runs/{GATE_RUN_ID}/verdict.json",
                         f"evidence/event/gate-runs/{GATE_RUN_ID}/observations.json"],
        "verdict_sha256": facts["verdict_sha256"], "gate_identity": v["gate_identity"],
        "patch_sha256": facts["patch_sha256"], "outcome": v["outcome"], "reason": v["reason"],
        "counts": v["counts"], "fail": by("FAIL"), "blocked": by("BLOCKED"), "not_run": by("NOT_RUN"),
        "log_excerpts": excerpts,
        "decided_by": "gate/check.py; this file copies the verdict and is not model-written",
        "note": "a later repair prompt may use this report; no repair was attempted here"})
    print(f"failure.json written: outcome {v['outcome']}, FAIL {by('FAIL')}, BLOCKED {by('BLOCKED')}, "
          f"NOT_RUN {len(by('NOT_RUN'))} (zero model calls)")
    return EXIT_OK

# ---------------------------------------------------------------------------
# Self-test (offline: no key, no network, no PostgreSQL checkout)
# ---------------------------------------------------------------------------


def synthetic_sources():
    """A synthetic stand-in for the pinned files, used only by the self-test."""
    hdr = "".join(f"/* synthetic line {n} */\n" for n in range(1, 125))
    hdr += "\n".join(["#ifdef USE_SSL", "#define SSL_LIBRARY \"OpenSSL\"", "#else", "#define SSL_LIBRARY \"\"",
                      "#endif", "", "#ifdef USE_OPENSSL", "#define DEFAULT_SSL_CIPHERS \"x\"", "#else",
                      "#define DEFAULT_SSL_CIPHERS \"none\"", "#endif", "", "#ifdef USE_SSL",
                      "#define DEFAULT_SSL_GROUPS \"X25519:prime256v1\"", "#else",
                      "#define DEFAULT_SSL_GROUPS \"none\"", "#endif", "", "/*", " * x", " */", "#ifdef ENABLE_GSS",
                      "extern int x;", "#endif", "", "#endif"]) + "\n"
    guc = "".join(f"# synthetic {n}\n" for n in range(1, 2812)) + "  boot_val => 'DEFAULT_SSL_GROUPS',\n"
    files = {HEADER_PATH: hdr.encode(), GUC_PATH: guc.encode()}
    specs = json.loads(json.dumps(SOURCE_SPECS))
    specs[0]["pin"] = {"git_blob": git_blob_id(files[HEADER_PATH]), "sha256": sha256(files[HEADER_PATH])}

    def read(path):
        return files[path], git_blob_id(files[path])
    return read, specs, files


GOOD_PATCH = ("--- a/src/include/libpq/libpq.h\n+++ b/src/include/libpq/libpq.h\n@@ -137,5 +137,5 @@\n"
              " #ifdef USE_SSL\n-#define DEFAULT_SSL_GROUPS \"X25519:prime256v1\"\n"
              "+#define DEFAULT_SSL_GROUPS \"X25519MLKEM768:X25519:prime256v1\"\n #else\n"
              " #define DEFAULT_SSL_GROUPS \"none\"\n #endif\n")


def reply_json(patch=GOOD_PATCH, refs=("SRC1",), explanation="Prefer the hybrid group first."):
    return json.dumps({"patch": patch, "explanation": explanation, "source_refs": list(refs)})


def sandbox(reply=None, raw_body=None, post_mode="ok", finalize_raises=False, preflight=False, pre=None,
            config_mut=None, then=None):
    """Drive cmd_send end to end in a temporary repository with a fake transport."""
    g = globals()
    saved = {k: g[k] for k in ("REPO", "PROPOSALS_DIR", "GATE_RUNS_DIR", "CLI_RUNS_DIR", "PROBE_LEDGER", "post",
                               "make_reader", "finalize")}
    saved_key = os.environ.get(KEY_ENV)
    res = {"rc": None, "out": "", "calls": 0, "files": {}, "note": [], "then": None}
    read, specs, _ = synthetic_sources()
    reply = reply or {}
    with tempfile.TemporaryDirectory() as t:
        t = Path(t).resolve()
        repo, priv = t / "repo", t / "private"
        repo.mkdir()
        priv.mkdir()
        ledger = repo / "ledger.json"
        ledger.write_text(json.dumps({"format": PROBE_LEDGER_FORMAT, "attempts": [
            {"sent": True, "cost_bound": {"usd": 0.5}}, {"sent": False, "cost_bound": {"usd": 9.0}}]}))
        cli = repo / "runs" / "spark-sourcemap-01"
        cli.mkdir(parents=True)
        (cli / "accounting.json").write_text(json.dumps({"format": CLI_ACCOUNTING_FORMAT, "run_id": cli.name,
                                                         "attempt": {"sent": "yes", "allowance": {"usd": 0.02}}}))
        (priv / CLI_NOTE_NAME).write_text(json.dumps({"run_id": cli.name, "allowance_usd": 0.02, "event": "reserving"})
                                          + "\n")
        doc = {"id": "D1", "title": "test", "url": "https://example.com/doc", "retrieved": "2026-01-01"}
        cfgd = {"api": {"base_url": "https://api.meta.ai/v1", "chat_path": "/chat/completions", "max_out_param": "max_tokens"},
                "docs": [doc],
                "models": {"spark": {"id": MODEL, "input_usd_per_mtok": 1.0, "output_usd_per_mtok": 2.0, "pricing_doc": "D1",
                                     "documented_max_out": None, "reasoning": "billed_as_output", "reasoning_doc": "D1",
                                     "reasoning_inside_max_out": True, "request_max_out": 4096}},
                "budget": {"remaining_usd_billing_console": 150, "final_reserve_usd": 30}}
        if config_mut:
            config_mut(cfgd, priv, repo)
        cfg = priv / "config.json"
        cfg.write_text(json.dumps(cfgd))
        msg = {"role": "assistant", "content": reply.get("content", reply_json())}
        for k in ("refusal", "tool_calls", "reasoning_content"):
            if k in reply:
                msg[k] = reply[k]
        body = {"id": "test-1", "model": reply.get("model", MODEL),
                "usage": reply.get("usage", {"prompt_tokens": 1500, "completion_tokens": 900,
                                             "completion_tokens_details": {"reasoning_tokens": 700}}),
                "choices": [{"finish_reason": reply.get("finish_reason", "stop"), "message": msg}]}
        if "usage" in reply and reply["usage"] is None:
            body.pop("usage")

        def fake_post(raw, key):
            res["calls"] += 1
            res["sent_raw"] = raw
            if post_mode == "interrupt":
                raise KeyboardInterrupt()
            if post_mode == "timeout":
                return {"status": None, "body": None, "sent": "unknown", "timeout": True, "error": "timeout",
                        "redirect": False, "latency_ms": 5}
            if post_mode == "http500":
                return {"status": 500, "body": b'{"error":{"message":"boom"}}', "sent": "yes", "timeout": False,
                        "error": None, "redirect": False, "latency_ms": 5}
            return {"status": 200, "body": raw_body if raw_body is not None else json.dumps(body).encode(),
                    "sent": "yes", "timeout": False, "error": None, "redirect": False, "latency_ms": 7}

        def broken_finalize(*a, **k):
            raise OSError("simulated write failure")
        try:
            g.update(REPO=repo, PROPOSALS_DIR=repo / "candidate-runs", GATE_RUNS_DIR=repo / "gate-runs",
                     CLI_RUNS_DIR=repo / "runs", PROBE_LEDGER=ledger, post=fake_post, make_reader=lambda _p: read)
            g["load_sources"].__defaults__ = (specs,)
            if finalize_raises:
                g["finalize"] = broken_finalize
            os.environ[KEY_ENV] = "selftest-key-0000"
            if pre:
                pre(repo, priv)
            buf = io.StringIO()
            with redirect_stdout(buf):
                argv = ["send", "--pg-git", "unused", "--config", str(cfg)] + (["--preflight"] if preflight else [])
                res["rc"] = main(argv)
                if then:
                    g["finalize"] = saved["finalize"]
                    res["then"] = then(repo, priv, cfg)
            res["out"] = buf.getvalue()
            d = repo / "candidate-runs" / PROPOSAL_ID
            if d.is_dir():
                for f in sorted(d.iterdir()):
                    res["files"][f.name] = f.read_bytes()
            if (priv / NOTE_NAME).exists():
                res["note"] = read_note(priv / NOTE_NAME)
            res["priv"] = sorted(p.name for p in priv.iterdir())
        finally:
            g.update(saved)
            g["load_sources"].__defaults__ = (None,)
            if saved_key is None:
                os.environ.pop(KEY_ENV, None)
            else:
                os.environ[KEY_ENV] = saved_key
    return res


def jf(res, name):
    return json.loads(res["files"][name]) if name in res["files"] else None



KILL_DRIVER = """
import importlib.util, os, sys
from pathlib import Path
mp, repo, kill, canned, calls = sys.argv[1:6]
spec = importlib.util.spec_from_file_location("proposer_under_test", mp)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
repo = Path(repo)
m.REPO, m.PROPOSALS_DIR, m.GATE_RUNS_DIR = repo, repo / "candidate-runs", repo / "gate-runs"
m.CLI_RUNS_DIR, m.PROBE_LEDGER = repo / "runs", repo / "ledger.json"
read, specs, _ = m.synthetic_sources()
m.make_reader = lambda _p: read
m.load_sources.__defaults__ = (specs,)
def fake_post(raw, key):
    open(os.path.join(calls, "call-%d" % len(os.listdir(calls))), "w").close()
    return {"status": 200, "body": open(canned, "rb").read(), "sent": "yes", "timeout": False, "error": None,
            "redirect": False, "latency_ms": 7}
m.post = fake_post
m._KILL_AT = kill
os.environ["MODEL_API_KEY"] = "selftest-key-0000"
sys.exit(m.main(sys.argv[6:]))
"""

KILL_POINTS = ["dir", "source", "request", "accounting", "post", "response", "patch", "failure",
               "final-accounting", "record"]


def kill_sandbox(kill_at, content=None, tamper=None):
    """Run send in a subprocess that ends abruptly (os._exit) at one checkpoint, then resume in-process
    with the network routine replaced by one that fails the test if called."""
    g = globals()
    saved = {k: g[k] for k in ("REPO", "PROPOSALS_DIR", "GATE_RUNS_DIR", "CLI_RUNS_DIR", "PROBE_LEDGER", "post",
                               "make_reader")}
    out = {"send_rc": None, "calls_after_send": None, "calls": None, "resume": [], "files": {}, "inodes": {},
           "inodes_after": {}, "link": None, "send_again": None, "net": 0}
    read, specs, _ = synthetic_sources()
    with tempfile.TemporaryDirectory() as t:
        t = Path(t).resolve()
        repo, priv, calls = t / "repo", t / "private", t / "calls"
        for d in (repo, priv, calls):
            d.mkdir()
        (repo / "ledger.json").write_text(json.dumps({"format": PROBE_LEDGER_FORMAT, "attempts": [
            {"sent": True, "cost_bound": {"usd": 0.5}}]}))
        cli = repo / "runs" / "spark-sourcemap-01"
        cli.mkdir(parents=True)
        (cli / "accounting.json").write_text(json.dumps({"format": CLI_ACCOUNTING_FORMAT, "run_id": cli.name,
                                                         "attempt": {"sent": "yes", "allowance": {"usd": 0.02}}}))
        doc = {"id": "D1", "title": "test", "url": "https://example.com/doc", "retrieved": "2026-01-01"}
        cfg = priv / "config.json"
        cfg.write_text(json.dumps({
            "api": {"base_url": "https://api.meta.ai/v1", "chat_path": "/chat/completions", "max_out_param": "max_tokens"},
            "docs": [doc], "budget": {"remaining_usd_billing_console": 150, "final_reserve_usd": 30},
            "models": {"spark": {"id": MODEL, "input_usd_per_mtok": 1.0, "output_usd_per_mtok": 2.0, "pricing_doc": "D1",
                                 "documented_max_out": None, "reasoning": "billed_as_output", "reasoning_doc": "D1",
                                 "reasoning_inside_max_out": True, "request_max_out": 4096}}}))
        canned = t / "canned.json"
        canned.write_bytes(json.dumps({"id": "t", "model": MODEL, "usage": {"prompt_tokens": 1500, "completion_tokens": 900},
                                       "choices": [{"finish_reason": "stop", "message": {
                                           "role": "assistant", "content": content or reply_json()}}]}).encode())
        p = subprocess.run([sys.executable, "-I", "-B", "-c", KILL_DRIVER, os.path.abspath(__file__), str(repo), kill_at,
                            str(canned), str(calls), "send", "--pg-git", "unused", "--config", str(cfg)],
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=120)
        out["send_rc"] = p.returncode
        out["calls_after_send"] = len(os.listdir(calls))
        d = repo / "candidate-runs" / PROPOSAL_ID
        if tamper:
            tamper(d)
        for f in (sorted(d.iterdir()) if d.is_dir() else []):
            out["inodes"][f.name] = (os.stat(f).st_ino, f.read_bytes())

        def no_network(*a, **k):
            out["net"] += 1
            raise AssertionError("network used during resume")
        try:
            g.update(REPO=repo, PROPOSALS_DIR=repo / "candidate-runs", GATE_RUNS_DIR=repo / "gate-runs",
                     CLI_RUNS_DIR=repo / "runs", PROBE_LEDGER=repo / "ledger.json", post=no_network,
                     make_reader=lambda _p: read)
            g["load_sources"].__defaults__ = (specs,)
            buf = io.StringIO()
            with redirect_stdout(buf):
                out["resume"].append(main(["resume", "--config", str(cfg)]))
                out["resume"].append(main(["resume", "--config", str(cfg)]))
                out["link"] = main(["link"])
                os.environ[KEY_ENV] = "selftest-key-0000"
                try:
                    out["send_again"] = main(["send", "--pg-git", "unused", "--config", str(cfg)])
                finally:
                    os.environ.pop(KEY_ENV, None)
            out["stdout"] = buf.getvalue()
        finally:
            g.update(saved)
            g["load_sources"].__defaults__ = (None,)
        out["calls"] = len(os.listdir(calls))
        for f in (sorted(d.iterdir()) if d.is_dir() else []):
            out["files"][f.name] = f.read_bytes()
            out["inodes_after"][f.name] = (os.stat(f).st_ino, f.read_bytes())
    return out


def kill_tests(case):
    bad = '```json\n{}\n```'
    expect = {   # kill point -> (reply, calls, resume rc, proposal status, sent)
        "dir": (None, 0, 1, "incomplete", "no"),
        "source": (None, 0, 1, "incomplete", "no"),
        "request": (None, 0, 1, "incomplete", "no"),
        "accounting": (None, 0, 1, "incomplete", "unknown"),
        "post": (None, 1, 1, "incomplete", "unknown"),
        "response": (None, 1, 0, "complete", "yes"),
        "patch": (None, 1, 0, "complete", "yes"),
        "failure": (bad, 1, 1, "incomplete", "yes"),
        "final-accounting": (None, 1, 0, "complete", "yes"),
        "record": (None, 1, EXIT_NA, "complete", "yes"),
    }
    for kp in KILL_POINTS:
        content, calls, rc, status, sent = expect[kp]
        x = kill_sandbox(kp, content)
        rec = json.loads(x["files"]["record.json"]) if "record.json" in x["files"] else None
        acc = json.loads(x["files"]["accounting.json"]) if "accounting.json" in x["files"] else None
        kept = all(x["inodes_after"].get(n) == v for n, v in x["inodes"].items()
                   if n in ("candidate.patch", "failure.json", "record.json", "response.json", "request.json", "source.json"))
        ok = (x["send_rc"] == 77 and x["calls_after_send"] == calls and x["calls"] == calls and x["net"] == 0
              and x["resume"] == [rc, EXIT_NA] and x["link"] == 0 and x["send_again"] == EXIT_REFUSED
              and rec is not None and rec["proposal"]["status"] == status and rec["transport"]["sent"] == sent
              and acc["attempt"]["sent"] == sent and kept and not any(STALE_TMP.match(n) for n in x["files"]))
        if status == "complete":
            ok = ok and x["files"].get("candidate.patch") == GOOD_PATCH.encode() and "failure.json" not in x["files"]
            ok = ok and acc["attempt"]["timing"] == {"latency_ms": 7}
        else:
            ok = ok and "candidate.patch" not in x["files"] and json.loads(x["files"]["failure.json"])["kind"] == "proposal"
        if sent == "no":
            ok = ok and acc["headroom_after_usd"] == acc["budget_before"]["headroom_usd"] and "response.json" in x["files"]
        else:
            ok = ok and acc["headroom_after_usd"] == round(acc["budget_before"]["headroom_usd"] - acc["attempt"]["allowance"]["usd"], 6)
        case(f"kill after {kp}: resume completes with zero calls ({status}, sent {sent}); nothing overwritten", ok)

    def flip_patch(d):
        os.chmod(d / "candidate.patch", 0o644)
        (d / "candidate.patch").write_bytes(GOOD_PATCH.encode().replace(b"X25519MLKEM768:", b""))
    x = kill_sandbox("patch", tamper=flip_patch)
    case("kill after patch, patch then edited: resume STOPs, edited bytes kept, no record, zero calls",
         x["resume"][0] == 1 and "record.json" not in x["files"] and x["net"] == 0 and x["calls"] == 1
         and x["inodes_after"]["candidate.patch"] == x["inodes"]["candidate.patch"])

    def flip_failure(d):
        (d / "failure.json").write_bytes((d / "failure.json").read_bytes().replace(b"local validation", b"other"))
    x = kill_sandbox("failure", content=bad, tamper=flip_failure)
    case("kill after failure.json, file then edited: resume STOPs, no record, nothing overwritten",
         x["resume"][0] == 1 and "record.json" not in x["files"]
         and x["inodes_after"]["failure.json"] == x["inodes"]["failure.json"])

    def plant_patch(d):
        create_atomic(d / "candidate.patch", GOOD_PATCH.encode(), 0o444)
    x = kill_sandbox("failure", content=bad, tamper=plant_patch)
    case("candidate.patch present for an incomplete reply: resume STOPs, no record",
         x["resume"][0] == 1 and "record.json" not in x["files"])

    def edit_response(d):
        os.chmod(d / "response.json", 0o644)
        r = json.loads((d / "response.json").read_text())
        r["reply"]["content"] = reply_json(patch=GOOD_PATCH + " \\n")
        (d / "response.json").write_text(canonical(r))
    x = kill_sandbox("patch", tamper=edit_response)
    case("response edited after candidate.patch was written: resume STOPs, patch kept",
         x["resume"][0] == 1 and "record.json" not in x["files"]
         and x["inodes_after"]["candidate.patch"] == x["inodes"]["candidate.patch"])

    def stale_tmp(d):
        (d / ".record.json.tmp.99999").write_bytes(b"partial")
    x = kill_sandbox("final-accounting", tamper=stale_tmp)
    case("stale temporary file from a crash is removed, then resume completes",
         x["resume"][0] == 0 and ".record.json.tmp.99999" not in x["files"] and "record.json" in x["files"])

    def edit_record_source(d):
        os.chmod(d / "source.json", 0o644)
        (d / "source.json").write_bytes((d / "source.json").read_bytes() + b" ")
    x = kill_sandbox("record", tamper=edit_record_source)
    case("final proposal with an edited file: resume STOPs, link fails", x["resume"][0] == 1 and x["link"] == 1)


def run_selftests():
    res = []

    def case(name, ok):
        res.append((name, bool(ok)))

    read, specs, files = synthetic_sources()
    src = load_sources(read, specs)
    case("source: synthetic excerpts load with pins", [s["id"] for s in src] == SOURCE_IDS)
    case("source: SRC1 shows lines 125-148", src[0]["first_line"] == 125 and len(src[0]["lines"]) == 24)
    for name, mut in (("changed byte refused", lambda f: f[HEADER_PATH].replace(b"X25519:", b"X25519;")),
                      ("SRC2 line differs refused", None)):
        f2 = dict(files)
        if mut:
            f2[HEADER_PATH] = mut(f2)
        else:
            f2[GUC_PATH] = f2[GUC_PATH].replace(b"  boot_val", b" boot_val")
        try:
            load_sources(lambda p: (f2[p], git_blob_id(f2[p])), specs)
            case(f"source: {name}", False)
        except ValueError:
            case(f"source: {name}", True)
    try:
        load_sources(lambda p: (files[p], "0" * 40), specs)
        case("source: git blob id inconsistent with bytes refused", False)
    except ValueError:
        case("source: git blob id inconsistent with bytes refused", True)
    b1 = serialize_body(build_body("max_tokens", src))
    case("request: deterministic bytes", b1 == serialize_body(build_body("max_tokens", load_sources(read, specs))))
    user = build_body("max_tokens", src)["messages"][1]["content"]
    case("request: all six added-line patterns present verbatim", all(("\n" + p + "\n") in user for p in ADDED_LINE_PATTERNS))
    case("request: version-conditional form disclosed", "OPENSSL_VERSION_NUMBER" in user)
    low = user.lower()
    case("request: no withheld requirement or fixture text",
         not any(w in low for w in ("3.0", "compatib", "fixture", "matrix", "startup", "older", "legacy", "gate")))
    case("request: schema has no descriptions", "description" not in json.dumps(API_SCHEMA))
    case("request: ASCII serialization, no tools field", b1.isascii() and b'"tools"' not in b1)

    ok_v, obj = validate_reply(reply_json())
    case("reply: valid object accepted", ok_v["ok"] and obj["patch"] == GOOD_PATCH)
    case("reply: SRC1 not cited is a note", validate_reply(reply_json(refs=("SRC2",)))[0]["notes"] != [])
    for name, text in (
            ("malformed JSON", '{"patch": "x"'), ("empty reply", ""), ("code-fenced reply", "```json\n" + reply_json() + "\n```"),
            ("missing field", json.dumps({"patch": "x", "explanation": "y"})),
            ("extra field", json.dumps({"patch": "x", "explanation": "y", "source_refs": ["SRC1"], "z": 1})),
            ("duplicate key", '{"patch":"a","patch":"b","explanation":"y","source_refs":["SRC1"]}'),
            ("unresolved source id", reply_json(refs=("SRC3",))), ("duplicate source id", reply_json(refs=("SRC1", "SRC1"))),
            ("empty source_refs", reply_json(refs=())), ("source ref object", json.dumps({"patch": "x", "explanation": "y", "source_refs": [{"id": "SRC1"}]})),
            ("non-string patch", json.dumps({"patch": 5, "explanation": "y", "source_refs": ["SRC1"]})),
            ("empty patch", reply_json(patch="")), ("oversize patch", reply_json(patch="+" * (MAX_PATCH_BYTES + 1))),
            ("unpaired surrogate", '{"patch":"\\ud800","explanation":"y","source_refs":["SRC1"]}'),
            ("empty explanation", reply_json(explanation="")), ("top level array", "[]")):
        case(f"reply: {name} rejected", not validate_reply(text)[0]["ok"])
    case("reply: 4096-byte patch is within the size limit", validate_reply(reply_json(patch="+" * MAX_PATCH_BYTES))[0]["ok"])

    basis = {"input_usd_per_mtok": 1.0, "output_usd_per_mtok": 2.0, "reasoning": "billed_as_output"}
    case("allowance: (bytes + 512) x input + 8192 x output", allowance(1000, basis)["usd"] == ceil_usd((1512 * 1 + 8192 * 2) / 1e6))
    s = Scrub("TESTKEYVALUE12345678")
    home = os.path.expanduser("~").rstrip("/")
    o = s(f"key TESTKEYVALUE12345678 at {home}/x Bearer abc.def")
    case("sanitizer: key, home path and bearer value removed", "TESTKEYVALUE" not in o and (not home or home not in o) and "abc.def" not in o)
    try:
        NoRedirect().redirect_request(None, None, 302, "Found", {}, "https://example.com/")
        case("transport: redirect refused", False)
    except RedirectRefused:
        case("transport: redirect refused", True)

    # --- end to end, offline
    r = sandbox()
    rec, acc, req = jf(r, "record.json"), jf(r, "accounting.json"), jf(r, "request.json")
    case("send: valid reply -> complete, exit 0, one call", r["rc"] == 0 and r["calls"] == 1 and rec["proposal"]["status"] == "complete")
    case("send: candidate.patch is the decoded patch string, UTF-8 once", r["files"].get("candidate.patch") == GOOD_PATCH.encode())
    case("send: request.json re-serializes to the bytes sent", serialize_body(req["body"]) == r["sent_raw"]
         and req["body_sha256"] == sha256(r["sent_raw"]))
    case("send: prior reservations deduplicated (probe 0.5 + CLI 0.02)",
         acc["budget_before"]["prior_committed_allowance_usd"] == 0.52 and len(acc["budget_before"]["prior_reservations"]) == 2)
    case("send: cumulative committed includes this allowance",
         acc["cumulative_committed_allowance_usd"] == round(0.52 + acc["attempt"]["allowance"]["usd"], 6))
    case("send: no failure.json on a complete proposal", "failure.json" not in r["files"])
    case("send: note reserving, received, finished", [e["event"] for e in r["note"]] == ["reserving", "received", "finished"])
    case("send: no key or hidden reasoning in evidence", all(b"selftest-key" not in v and b"HIDDENREASON" not in v
                                                             for v in sandbox(reply={"reasoning_content": "HIDDENREASON"})["files"].values()))
    case("send: record.json has no timestamps", b"wall_clock" not in r["files"]["record.json"] and b"latency" not in r["files"]["record.json"])
    tricky = "--- a/x\n+++ b/x\n@@ -1 +1 @@\n-a\té\n+b \\ \"q\"\n"
    r2 = sandbox(reply={"content": reply_json(patch=tricky)})
    case("send: tabs, non-ASCII, quotes and backslashes kept byte-exact", r2["files"].get("candidate.patch") == tricky.encode("utf-8"))
    r2b = sandbox(reply={"content": reply_json(patch=GOOD_PATCH.replace("\n", "\r\n"))})
    case("send: CRLF patch not normalized (left for the gate policy)", r2b["files"].get("candidate.patch") == GOOD_PATCH.replace("\n", "\r\n").encode())
    for name, kw, expect in (
            ("malformed native JSON", {"reply": {"content": '{"patch":'}}, "local validation failed"),
            ("code-fenced reply", {"reply": {"content": "```json\n" + reply_json() + "\n```"}}, "local validation failed"),
            ("unresolved reference", {"reply": {"content": reply_json(refs=("SRC9",))}}, "local validation failed"),
            ("refusal", {"reply": {"refusal": "cannot"}}, "the model returned a refusal"),
            ("finish 'length'", {"reply": {"finish_reason": "length"}}, "finish_reason is 'length'"),
            ("returned model differs", {"reply": {"model": "muse-spark-1.4"}}, "differs from the requested"),
            ("missing usage", {"reply": {"usage": None}}, "usage missing"),
            ("output over the allowance", {"reply": {"usage": {"prompt_tokens": 10, "completion_tokens": 9000}}}, "output units exceed"),
            ("tool calls returned", {"reply": {"tool_calls": [{"x": 1}]}}, "tool calls returned"),
            ("non-JSON HTTP body", {"raw_body": b"<html>"}, "no reply recorded"),
            ("HTTP 500", {"post_mode": "http500"}, "no reply recorded (HTTP_ERROR)"),
            ("timeout", {"post_mode": "timeout"}, "no reply recorded (TRANSPORT_UNKNOWN)"),
            ("interrupt during the request", {"post_mode": "interrupt"}, "no reply recorded (TRANSPORT_UNKNOWN)")):
        x = sandbox(**kw)
        rc_, ac_, fl_ = jf(x, "record.json"), jf(x, "accounting.json"), jf(x, "failure.json")
        ok = (x["rc"] == 1 and x["calls"] == 1 and rc_ is not None and rc_["proposal"]["status"] == "incomplete"
              and any(expect in y for y in rc_["proposal"]["incomplete_reasons"]) and "candidate.patch" not in x["files"]
              and fl_ is not None and fl_["kind"] == "proposal" and rc_["gate"]["run_id"] is None
              and ac_["attempt"]["sent"] in ("yes", "unknown")
              and ac_["headroom_after_usd"] == round(ac_["budget_before"]["headroom_usd"] - ac_["attempt"]["allowance"]["usd"], 6)
              and x["note"][-1]["event"] == "finished")
        case(f"send: {name} -> incomplete, allowance kept, failure.json, no patch", ok)

    def resume_then(repo, priv, cfg):
        buf = io.StringIO()
        globals()["post"] = lambda *a, **k: (_ for _ in ()).throw(AssertionError("network used"))
        with redirect_stdout(buf):
            rc1 = main(["resume", "--config", str(cfg)])
            rc2 = main(["resume", "--config", str(cfg)])
            rc3 = main(["send", "--pg-git", "unused", "--config", str(cfg)])
        return rc1, rc2, rc3, buf.getvalue()
    x = sandbox(finalize_raises=True, then=resume_then)
    rc1, rc2, rc3, out = x["then"]
    case("interrupted finalization: send exits 1 and the note keeps the attempt",
         x["rc"] == 1 and [e for e in x["note"] if e["event"] == "finished"][0].get("finalized") is False
         and [e for e in x["note"] if e["event"] == "finished"][0].get("sent") == "yes")
    case("resume: completes from response.json with zero calls", rc1 == 0 and x["calls"] == 1
         and jf(x, "record.json")["proposal"]["status"] == "complete" and x["files"].get("candidate.patch") == GOOD_PATCH.encode())
    case("resume: second resume is not applicable", rc2 == EXIT_NA)
    case("send after an attempt is refused (no second request)", rc3 == EXIT_REFUSED and x["calls"] == 1)

    def lost_reply(repo, priv, cfg):
        d = repo / "candidate-runs" / PROPOSAL_ID
        for n in ("response.json", "record.json", "candidate.patch"):
            if (d / n).exists():
                os.chmod(d / n, 0o644)
                (d / n).unlink()
        acc = json.loads((d / "accounting.json").read_text())
        acc["attempt"]["sent"] = "in_flight"
        (d / "accounting.json").write_text(canonical(acc))
        buf = io.StringIO()
        with redirect_stdout(buf):
            return main(["resume", "--config", str(cfg)])
    x = sandbox(then=lost_reply)
    rec = jf(x, "record.json")
    case("resume: reply lost after sending -> incomplete, sent unknown, full allowance, zero calls",
         x["then"] == 1 and x["calls"] == 1 and rec["transport"]["sent"] == "unknown"
         and jf(x, "accounting.json")["headroom_after_usd"] < jf(x, "accounting.json")["budget_before"]["headroom_usd"])

    x = sandbox(preflight=True)
    case("preflight: exit 0, nothing sent, nothing written", x["rc"] == 0 and x["calls"] == 0 and not x["files"] and not x["note"])
    x = sandbox(pre=lambda repo, priv: (priv / NOTE_NAME).write_text('{"event":"reserving"}\n'))
    case("send: refused when the private note records an attempt", x["rc"] == EXIT_REFUSED and x["calls"] == 0)
    x = sandbox(pre=lambda repo, priv: (repo / "candidate-runs" / "other").mkdir(parents=True))
    case("send: refused when any proposal directory exists", x["rc"] == EXIT_REFUSED and x["calls"] == 0)
    x = sandbox(pre=lambda repo, priv: (priv / CLI_NOTE_NAME).write_text("not json\n"))
    case("send: refused when the shaar.py note is malformed", x["rc"] == EXIT_REFUSED and x["calls"] == 0)
    x = sandbox(pre=lambda repo, priv: (repo / "runs" / "spark-sourcemap-01" / "accounting.json").unlink())
    case("send: refused when a CLI run has no accounting", x["rc"] == EXIT_REFUSED and x["calls"] == 0)

    def orphan(repo, priv):
        with open(priv / CLI_NOTE_NAME, "a") as f:
            f.write(json.dumps({"run_id": "lost-run", "allowance_usd": 0.03, "event": "reserving"}) + "\n")
            f.write(json.dumps({"run_id": "unsent-run", "allowance_usd": 0.04, "event": "reserving"}) + "\n")
            f.write(json.dumps({"run_id": "unsent-run", "allowance_usd": 0.04,
                                "event": "not sent: run directory not reserved"}) + "\n")
    x = sandbox(pre=orphan, preflight=True)
    case("budget: note-only CLI attempt counted once; a 'not sent' attempt not counted",x["rc"] == 0 and "prior committed allowance: $0.550000" in x["out"])
    x = sandbox(config_mut=lambda c, p, r: c["budget"].update(remaining_usd_billing_console=30.1), preflight=True)
    case("budget: allowance above headroom refused", x["rc"] == EXIT_REFUSED and x["calls"] == 0)
    x = sandbox(config_mut=lambda c, p, r: c["models"]["spark"].update(reasoning_inside_max_out=False), preflight=True)
    case("budget: reasoning not capped by max output refused", x["rc"] == EXIT_REFUSED)
    x = sandbox(config_mut=lambda c, p, r: c["models"]["spark"].update(documented_max_out=4096), preflight=True)
    case("budget: documented max output below the request refused", x["rc"] == EXIT_REFUSED)
    x = sandbox(config_mut=lambda c, p, r: c["models"]["spark"].pop("output_usd_per_mtok"), preflight=True)
    case("budget: missing price refused", x["rc"] == EXIT_REFUSED)

    # --- gate linkage, with synthetic gate evidence
    def gate_then(outcome, tamper=None):
        def fn(repo, priv, cfg):
            d = repo / "candidate-runs" / PROPOSAL_ID
            cp = (d / "candidate.patch").read_bytes()
            gd = repo / "gate-runs" / GATE_RUN_ID
            (gd / "logs").mkdir(parents=True)
            (gd / "candidate.patch").write_bytes(cp + (b"x" if tamper == "snapshot" else b""))
            (gd / "logs" / "patch.txt").write_text("line1\nREJECTED: synthetic\n")
            checks = [{"id": "patch", "result": "FAIL" if outcome == "REJECT" else "PASS"}, {"id": "newer.build", "result": "NOT_RUN" if outcome == "REJECT" else "PASS"}]
            v = {"outcome": outcome, "reason": "synthetic", "checks": checks, "counts": {"pass": 1}, "gate_identity": "0" * 64,
                 "patch": {"sha256": sha256(cp), "fixture": None}, "reference_run": {"run_id": GATE_REFERENCE}}
            ob = {"input": {"sha256": sha256(cp), "origin": "external", "derived_from": None},
                  "receipts": {"patch": {"log": "logs/patch.txt"}}}
            (gd / "verdict.json").write_text(canonical(v))
            (gd / "observations.json").write_text(canonical(ob))
            buf = io.StringIO()
            with redirect_stdout(buf):
                return main(["link"]), main(["derive-failure"]), main(["derive-failure"]), buf.getvalue()
        return fn
    x = sandbox(then=gate_then("REJECT"))
    l1, d1, d2, out = x["then"]
    fl = jf(x, "failure.json")
    case("link: chain reply -> candidate.patch -> gate snapshot passes", l1 == 0)
    case("derive-failure: gate REJECT -> failure.json from verdict, zero calls",
         d1 == 0 and x["calls"] == 1 and fl["kind"] == "gate" and fl["fail"] == ["patch"] and "patch" in fl["log_excerpts"])
    case("derive-failure: never overwrites", d2 == EXIT_NA)
    x = sandbox(then=gate_then("ACCEPT"))
    case("derive-failure: ACCEPT writes nothing", x["then"][1] == EXIT_NA and "failure.json" not in x["files"])
    x = sandbox(then=gate_then("REJECT", tamper="snapshot"))
    case("link: gate snapshot differing from candidate.patch fails, no failure.json",
         x["then"][0] == 1 and x["then"][1] == 1 and "failure.json" not in x["files"])

    kill_tests(case)

    global post
    real_post = post
    post = lambda *a, **k: (_ for _ in ()).throw(AssertionError("network used"))
    try:
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main(["resume"])
        case("resume with no proposal: not applicable, no network", rc == EXIT_NA)
    finally:
        post = real_post
    return res


def cmd_selftest(_args):
    res = run_selftests()
    for name, ok in res:
        print(("PASS " if ok else "FAIL ") + name)
    n = sum(ok for _, ok in res)
    print(f"SELFTEST {n}/{len(res)} PASS")
    return EXIT_OK if n == len(res) else EXIT_INCOMPLETE


def main(argv=None):
    ap = argparse.ArgumentParser(prog="propose_candidate.py", description="one recorded Spark patch proposal")
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("render", help="print the exact request built from the authenticated source; sends nothing")
    r.add_argument("--pg-git", required=True)
    r.add_argument("--max-out-param", default="max_tokens", choices=["max_tokens", "max_completion_tokens"])
    r.add_argument("--out", help="also write the exact body bytes to this new file outside the repository")
    s = sub.add_parser("send", help="one real request (at most once)")
    s.add_argument("--pg-git", required=True)
    s.add_argument("--config", required=True, help="private pricing/limit config outside the repository")
    s.add_argument("--preflight", action="store_true", help="check and print; send nothing, write nothing")
    q = sub.add_parser("resume", help="finalize an interrupted attempt from disk; never sends")
    q.add_argument("--config")
    sub.add_parser("derive-failure", help="write failure.json from a non-ACCEPT gate verdict; no model call")
    sub.add_parser("link", help="check the chain from the reply to the gate snapshot; no model call")
    sub.add_parser("selftest", help="offline checks; no key, network or PostgreSQL checkout needed")
    a = ap.parse_args(argv)
    return {"render": cmd_render, "send": cmd_send, "resume": cmd_resume, "derive-failure": cmd_derive_failure,
            "link": cmd_link, "selftest": cmd_selftest}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
