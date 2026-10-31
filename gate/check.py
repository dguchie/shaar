#!/usr/bin/env python3
"""Sha'ar gate: bounded PostgreSQL default TLS-groups compatibility check.

Scope: one PostgreSQL source pin, one header location (DEFAULT_SSL_GROUPS),
two OpenSSL library arms on one macOS machine. Python standard library only.
The harness owns patch validation, application, checks and verdicts. It runs
the reviewed literal fixtures, or one explicit external candidate patch
(case "candidate") whose exact bytes are snapshotted into the run's evidence.
It is not a sandbox: a candidate's build runs with the user's privileges.

Commands:
  selftest          offline checks: patch policy, client-output parser, verdict logic,
                    external-input contract
  identity          print the gate files' SHA-256 and the gate identity
  run               build, test and observe one case; writes evidence for that run
  evaluate          recompute a run's verdict from its observations and logs
  negative-control  show that missing or edited evidence prevents ACCEPT

External candidate (all of these are required for --case candidate and refused
for the other cases):
  run --case candidate --run-id candidate-NN --patch-file PATH --patch-sha256 HEX
      --origin {scripted,external} [--derived-from FIXTURE] --reference-run baseline-NN
      plus the usual environment arguments.
"""
import argparse
import datetime
import difflib
import hashlib
import json
import os
import re
import shlex
import signal
import stat
import subprocess
import sys
import tempfile
import time

GATE_DIR = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(GATE_DIR)
POLICY_PATH = os.path.join(GATE_DIR, "policy.json")
GATE_FILES = ["gate/check.py", "gate/policy.json",
              "gate/fixtures/hybrid-unconditional.patch",
              "gate/fixtures/hybrid-versioned.patch"]
EVIDENCE_ROOT = os.path.join(REPO, "evidence", "event", "gate-runs")
ARMS = ["newer", "v30"]
SAFE_PATH = re.compile(r"^[A-Za-z0-9_./@+-]+$")
SSL_GROUPS_ERROR = "could not set group names specified in ssl_groups"
CHILD_PATH = "/usr/bin:/bin:/usr/sbin:/sbin"
CRED_NAME = re.compile(r"(KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL)", re.I)


# ---------------------------------------------------------------- basics

def canon(obj):
    return json.dumps(obj, sort_keys=True, indent=2, ensure_ascii=False,
                      allow_nan=False) + "\n"


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def load_policy():
    with open(POLICY_PATH, "rb") as f:
        return json.loads(f.read().decode("utf-8"))


def gate_hashes():
    files = {p: sha256_file(os.path.join(REPO, p)) for p in GATE_FILES}
    identity = sha256_bytes(canon(files).encode("utf-8"))
    return files, identity


def utc_now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def write_new(path, data, mode=0o644):
    """Create a file that must not exist yet."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(fd, "wb") as f:
        f.write(data if isinstance(data, bytes) else data.encode("utf-8"))


def version_tuple(text):
    m = re.match(r"^(\d+)\.(\d+)\.(\d+)", text or "")
    return tuple(int(x) for x in m.groups()) if m else None


def full(pattern, text):
    """Whole-string match ('$' alone would also accept a trailing newline)."""
    return isinstance(text, str) and re.fullmatch(pattern, text) is not None


def inside(path, root):
    """True if real path `path` is `root` or below it (both already realpath'd)."""
    return path == root or path.startswith(root.rstrip(os.sep) + os.sep)


# ---------------------------------------------------------------- external candidate input

HEX64 = re.compile(r"[0-9a-f]{64}")


class InputError(Exception):
    pass


def fixture_hashes(gate_files, policy):
    """Fixture name -> SHA-256, taken from the gate files hashed for the identity."""
    return {name: gate_files.get(meta["path"]) for name, meta in policy["fixtures"].items()}


def check_run_args(a, policy):
    """Argument contract for `run`. Returns an error string or None. No I/O."""
    cases = policy["cases"]
    if a.case not in cases:
        return "unknown case %r" % a.case
    case = cases[a.case]
    if not full(policy["run_id_pattern"], a.run_id) or a.run_id.split("-")[0] != case["run_id_prefix"]:
        return "run id must match %s with prefix %s" % (policy["run_id_pattern"], case["run_id_prefix"])
    ext = [n for n in ("patch_file", "patch_sha256", "origin", "derived_from") if getattr(a, n, None) is not None]
    if not case.get("external_input"):
        if ext:
            return "--%s applies only to --case %s" % (ext[0].replace("_", "-"), policy["external_input"]["case"])
        if a.case == "baseline" and a.reference_run:
            return "baseline runs take no reference"
        return None
    xi = policy["external_input"]
    if not a.patch_file:
        return "--patch-file is required for --case candidate"
    if a.patch_sha256 is None or not HEX64.fullmatch(a.patch_sha256):
        return "--patch-sha256 is required: 64 lowercase hex characters"
    if a.origin not in xi["origins"]:
        return "--origin must be one of %s" % sorted(xi["origins"])
    rule = xi["origins"][a.origin]
    if not full(rule["run_id_pattern"], a.run_id):
        return "origin %s requires a run id matching %s" % (a.origin, rule["run_id_pattern"])
    if rule["derived_from"] == "required":
        if a.derived_from not in policy["fixtures"]:
            return "origin %s requires --derived-from naming a fixture %s" % (a.origin, sorted(policy["fixtures"]))
    elif a.derived_from is not None:
        return "--derived-from is not allowed with origin %s" % a.origin
    if not a.reference_run:
        return "--reference-run (a baseline under the same gate identity) is required for --case candidate"
    return None


def read_input_once(path, limit):
    """Open a regular file once without following a final symlink; read at most limit + 1 bytes."""
    try:
        st = os.lstat(path)
    except OSError as e:
        raise InputError("candidate input not readable: %s" % e.strerror)
    if stat.S_ISLNK(st.st_mode):
        raise InputError("candidate input is a symlink")
    if not stat.S_ISREG(st.st_mode):
        raise InputError("candidate input is not a regular file")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(path, flags)
    except OSError as e:
        raise InputError("candidate input not readable: %s" % e.strerror)
    try:
        fst = os.fstat(fd)
        if not stat.S_ISREG(fst.st_mode) or (fst.st_dev, fst.st_ino) != (st.st_dev, st.st_ino):
            raise InputError("candidate input changed type or identity while opening")
        chunks, n = [], 0
        while n <= limit:
            b = os.read(fd, limit + 1 - n)
            if not b:
                break
            chunks.append(b)
            n += len(b)
    finally:
        os.close(fd)
    data = b"".join(chunks)
    if len(data) > limit:
        raise InputError("candidate input larger than %d bytes" % limit)
    if not data:
        raise InputError("candidate input is empty")
    return data


def prepare_candidate(a, policy, gate_files, protected_roots):
    """Validate location, read once, check the digest and origin. Returns a frozen input dict."""
    real = os.path.realpath(a.patch_file)
    for root in protected_roots:
        if inside(real, root):
            raise InputError("candidate input lies inside a protected, work or repository path")
    data = read_input_once(a.patch_file, policy["patch_policy"]["max_patch_bytes"])
    digest = sha256_bytes(data)
    if digest != a.patch_sha256:
        raise InputError("candidate input SHA-256 %s differs from --patch-sha256" % digest)
    if a.derived_from is not None and fixture_hashes(gate_files, policy).get(a.derived_from) != digest:
        raise InputError("origin scripted: input bytes differ from fixture %s" % a.derived_from)
    return {"bytes": data, "info": {"snapshot": policy["external_input"]["snapshot"], "sha256": digest,
                                    "bytes": len(data), "origin": a.origin, "derived_from": a.derived_from}}


PINNED_HEADER = "src/include/libpq/libpq.h"

# A different, policy-valid patch (classical groups replaced by "none"). Used only by the
# negative control and the self-test to substitute a run's snapshot; never applied to a build.
SUBSTITUTE_PATCH = (
    b"--- a/src/include/libpq/libpq.h\n+++ b/src/include/libpq/libpq.h\n@@ -135,7 +135,7 @@\n"
    b" #endif\n \n #ifdef USE_SSL\n-#define DEFAULT_SSL_GROUPS \"X25519:prime256v1\"\n"
    b"+#define DEFAULT_SSL_GROUPS \"none\"\n #else\n #define DEFAULT_SSL_GROUPS \"none\"\n #endif\n")


def load_pinned_header(pg_git, policy):
    """The pinned header from a PostgreSQL checkout, only if its SHA-256 equals the policy's."""
    if not pg_git:
        return None
    try:
        p = subprocess.run(["git", "-C", pg_git, "show", "%s:%s" % (policy["upstream"]["commit"], PINNED_HEADER)],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60,
                           env={"PATH": CHILD_PATH, "GIT_OPTIONAL_LOCKS": "0", "HOME": os.path.expanduser("~")})
    except (OSError, subprocess.SubprocessError):
        return None
    if p.returncode != 0 or sha256_bytes(p.stdout) != policy["patch_policy"]["allowed_files"][PINNED_HEADER]["sha256"]:
        return None
    try:
        return p.stdout.decode("utf-8")
    except UnicodeDecodeError:
        return None


def reapply_problems(snap, receipts, policy, pinned_header):
    """Re-apply the saved snapshot to the authenticated pinned header and bind the result to the
    patch receipt and to the header recorded in each arm's source export."""
    r = receipts.get("patch")
    if snap is None or not isinstance(r, dict) or r.get("status") not in ("pass", "fail"):
        return []
    want_hdr = policy["patch_policy"]["allowed_files"][PINNED_HEADER]["sha256"]
    if not isinstance(pinned_header, str) or sha256_bytes(pinned_header.encode("utf-8")) != want_hdr:
        return ["pinned header not available or not authenticated, so the snapshot cannot be re-applied "
                "(evaluate needs --pg-git)"]
    try:
        _p, patched, _d = validate_and_apply(snap, pinned_header, policy)
        result, err = sha256_bytes(patched.encode("utf-8")), None
    except PatchError as e:
        result, err = None, str(e)
    if r["status"] == "fail":
        return ["re-applied snapshot passes the policy while the patch receipt says FAIL"] if result else []
    if result is None:
        return ["re-applied snapshot is rejected by the policy (%s) while the patch receipt says PASS" % err]
    probs = []
    if r.get("patched_sha256") != result:
        probs.append("re-applied snapshot result %s differs from the patch receipt" % result[:16])
    src = receipts.get("source")
    if isinstance(src, dict) and src.get("status") == "pass":
        got = src.get("patched_file_sha256")
        if not isinstance(got, dict) or sorted(got) != sorted(ARMS):
            probs.append("source receipt has no per-arm exported-header hashes")
        else:
            probs += ["%s arm exported header differs from the re-applied snapshot result" % a
                      for a in ARMS if got[a] != result]
    return probs


def candidate_binding(obs, policy, read_log, fixture_sha, read_ref, pinned_header=None):
    """Problems binding a run's patch evidence to its saved input. Empty list = consistent."""
    probs = []
    case = obs.get("case")
    is_cand = bool(policy["cases"].get(case, {}).get("external_input"))
    inp = obs.get("input")
    if not is_cand:
        return ["input block present for a non-candidate case"] if inp is not None else []
    xi = policy["external_input"]
    if not isinstance(inp, dict):
        return ["input block missing"]
    origin, derived, sha = inp.get("origin"), inp.get("derived_from"), inp.get("sha256")
    if inp.get("snapshot") != xi["snapshot"]:
        probs.append("snapshot name is not %s" % xi["snapshot"])
    if not isinstance(sha, str) or not HEX64.fullmatch(sha):
        probs.append("input sha256 malformed")
    rule = xi["origins"].get(origin)
    if rule is None:
        probs.append("origin %r not allowed by policy" % origin)
    else:
        if not full(rule["run_id_pattern"], obs.get("run_id")):
            probs.append("origin %s not allowed for run id %s" % (origin, obs.get("run_id")))
        if rule["derived_from"] == "required":
            if derived not in policy["fixtures"]:
                probs.append("origin %s without a fixture in derived_from" % origin)
            elif fixture_sha is None or fixture_sha.get(derived) != sha:
                probs.append("input does not equal the bytes of fixture %s" % derived)
        elif derived is not None:
            probs.append("derived_from set for origin %s" % origin)
    snap = read_log(xi["snapshot"])
    if snap is None:
        probs.append("snapshot %s missing" % xi["snapshot"])
    else:
        if sha256_bytes(snap) != sha:
            probs.append("snapshot SHA-256 differs from the input block")
        if len(snap) != inp.get("bytes") or len(snap) > policy["patch_policy"]["max_patch_bytes"]:
            probs.append("snapshot size differs from the input block or the limit")
    r = (obs.get("receipts") or {}).get("patch")
    if isinstance(r, dict) and r.get("status") in ("pass", "fail"):
        if r.get("fixture") is not None:
            probs.append("patch receipt claims fixture %r for an external input" % r.get("fixture"))
        for k, v in (("input_origin", origin), ("derived_from", derived), ("patch_sha256", sha),
                     ("snapshot_sha256", sha)):
            if r.get(k) != v:
                probs.append("patch receipt %s disagrees with the input block" % k)
        if r.get("status") == "pass":
            if not isinstance(r.get("patched_sha256"), str) or not HEX64.fullmatch(r["patched_sha256"]):
                probs.append("patch receipt has no patched_sha256")
    probs += reapply_problems(snap, obs.get("receipts") or {}, policy, pinned_header)
    ref = obs.get("reference")
    if not isinstance(ref, dict):
        probs.append("reference run missing")
    else:
        if ref.get("gate_identity") != obs.get("gate_identity"):
            probs.append("reference gate identity differs from the run's")
        probs += reference_problems(ref, read_ref)
    return probs


def reference_problems(ref, read_ref):
    """Re-read the reference verdict and compare with the copy in the observations."""
    if read_ref is None:
        return ["reference verdict not checkable"]
    rid = ref.get("run_id")
    if not full(r"baseline-[0-9]{2}", rid):
        return ["reference run id %r is not a baseline id" % rid]
    raw = read_ref(rid)
    if raw is None:
        return ["reference verdict %s missing" % rid]
    derived = reference_from_raw(rid, raw)
    if derived is None:
        return ["reference verdict %s unreadable or not a baseline" % rid]
    if derived != ref:
        return ["reference verdict %s differs from the recorded reference" % rid]
    return []


# ---------------------------------------------------------------- patch policy

class PatchError(Exception):
    pass


HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@$")


def parse_patch(raw, policy):
    """Parse and validate a single-file unified diff. Raises PatchError."""
    pp = policy["patch_policy"]
    if len(raw) > pp["max_patch_bytes"]:
        raise PatchError("patch larger than %d bytes" % pp["max_patch_bytes"])
    if b"\0" in raw or b"\r" in raw:
        raise PatchError("NUL or carriage return in patch")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise PatchError("patch is not UTF-8 text")
    if not text.endswith("\n"):
        raise PatchError("patch does not end with a newline")
    lines = text[:-1].split("\n")
    for ln in lines:
        for marker in pp["forbidden_header_markers"]:
            if marker in ln:
                raise PatchError("forbidden marker: %s" % marker)
    i = 0
    path = None
    if i < len(lines) and lines[i].startswith("diff --git "):
        m = re.match(r"^diff --git a/(\S+) b/(\S+)$", lines[i])
        if not m or m.group(1) != m.group(2):
            raise PatchError("malformed diff --git header")
        path = m.group(1)
        i += 1
        if i < len(lines) and lines[i].startswith("index "):
            if not re.match(r"^index [0-9a-f]{7,64}\.\.[0-9a-f]{7,64}( 100644)?$", lines[i]):
                raise PatchError("index line with unexpected mode or format")
            i += 1
    if i + 1 >= len(lines) or not lines[i].startswith("--- a/") or not lines[i + 1].startswith("+++ b/"):
        raise PatchError("expected '--- a/PATH' and '+++ b/PATH' headers")
    old_p, new_p = lines[i][6:], lines[i + 1][6:]
    if old_p != new_p or (path is not None and path != old_p):
        raise PatchError("header paths differ")
    path = old_p
    if (path.startswith("/") or "\\" in path or "//" in path
            or any(part in ("", ".", "..") for part in path.split("/"))):
        raise PatchError("unsafe path: %r" % path)
    if path not in pp["allowed_files"]:
        raise PatchError("file not allowed by policy: %s" % path)
    i += 2
    hunks = []
    while i < len(lines):
        m = HUNK_RE.match(lines[i])
        if not m:
            raise PatchError("unexpected line %d: %r" % (i + 1, lines[i][:60]))
        os_, oc, ns, nc = (int(m.group(1)), int(m.group(2) or 1),
                           int(m.group(3)), int(m.group(4) or 1))
        i += 1
        body = []
        o_seen = n_seen = 0
        while i < len(lines) and not lines[i].startswith("@@"):
            ln = lines[i]
            if ln[:1] not in (" ", "-", "+"):
                raise PatchError("bad hunk line %d: %r" % (i + 1, ln[:60]))
            if ln[:1] in (" ", "-"):
                o_seen += 1
            if ln[:1] in (" ", "+"):
                n_seen += 1
            body.append(ln)
            i += 1
        if (o_seen, n_seen) != (oc, nc):
            raise PatchError("hunk line counts do not match header")
        hunks.append((os_, oc, ns, nc, body))
    if not hunks:
        raise PatchError("no hunks")
    check_hunks(hunks, pp["allowed_files"][path], pp)
    return path, hunks


def check_hunks(hunks, rule, pp):
    lo, hi = rule["editable_lines"]
    pats = [re.compile(p) for p in pp["added_line_patterns"]]
    allowed_groups = set(pp["allowed_group_names"])
    prev_end = 0
    changed = False
    for os_, oc, _ns, _nc, body in hunks:
        if os_ <= prev_end:
            raise PatchError("overlapping or unordered hunks")
        prev_end = os_ + oc - 1
        cur = os_
        for ln in body:
            tag, content = ln[0], ln[1:]
            if tag == " ":
                cur += 1
            elif tag == "-":
                if not lo <= cur <= hi:
                    raise PatchError("removes line %d outside editable lines %d-%d" % (cur, lo, hi))
                changed = True
                cur += 1
            else:
                if not lo <= cur <= hi + 1:
                    raise PatchError("inserts before line %d outside editable lines %d-%d" % (cur, lo, hi))
                if not any(p.match(content) for p in pats):
                    raise PatchError("added line not allowed by policy: %r" % content[:80])
                m = re.match(r'^#define DEFAULT_SSL_GROUPS "([^"]*)"$', content)
                if m:
                    bad = [g for g in m.group(1).split(":") if g not in allowed_groups]
                    if bad:
                        raise PatchError("group names not allowed by policy: %s" % ",".join(bad))
                changed = True
    if not changed:
        raise PatchError("patch makes no change")


def apply_hunks(original, hunks):
    """Exact application: context must match at the stated line; no offset, no fuzz."""
    if not original.endswith("\n"):
        raise PatchError("target file does not end with a newline")
    src = original[:-1].split("\n")
    out = []
    pos = 0
    for os_, _oc, _ns, _nc, body in hunks:
        start = os_ - 1
        out.extend(src[pos:start])
        pos = start
        for ln in body:
            tag, content = ln[0], ln[1:]
            if tag in (" ", "-"):
                if pos >= len(src) or src[pos] != content:
                    raise PatchError("context mismatch at line %d" % (pos + 1))
                if tag == " ":
                    out.append(content)
                pos += 1
            else:
                out.append(content)
    out.extend(src[pos:])
    return "\n".join(out) + "\n"


def region_unchanged_outside(original, patched, rule):
    lo, hi = rule["editable_lines"]
    a = original.split("\n")
    b = patched.split("\n")
    tail = len(a) - hi
    return a[:lo - 1] == b[:lo - 1] and a[len(a) - tail:] == b[len(b) - tail:]


def validate_and_apply(raw, original, policy):
    """Returns (path, patched_text, report_lines). Raises PatchError."""
    path, hunks = parse_patch(raw, policy)
    rule = policy["patch_policy"]["allowed_files"][path]
    if sha256_bytes(original.encode("utf-8")) != rule["sha256"]:
        raise PatchError("target file hash differs from the pinned hash")
    patched = apply_hunks(original, hunks)
    if not region_unchanged_outside(original, patched, rule):
        raise PatchError("resulting file differs outside the editable region")
    diff = list(difflib.unified_diff(original.splitlines(), patched.splitlines(),
                                     "a/" + path, "b/" + path, lineterm=""))
    return path, patched, diff


# ---------------------------------------------------------------- client output

def parse_client_output(text, rc, policy):
    """Classify one s_client transcript: ok (with group), tls_failure, or client_error."""
    cl = policy["client"]
    aliases = cl["group_aliases"]
    pats = [re.compile(p) for p in cl["group_line_patterns"]]
    nulls = set(cl["null_group_values"])
    raw, null_lines = [], 0
    lines = [l.rstrip() for l in text.splitlines()]
    for ln in lines:
        for p in pats:
            m = p.match(ln)
            if m:
                if m.group(1) in nulls:
                    null_lines += 1
                else:
                    raw.append(m.group(1))
                break
        else:
            if any(ln.startswith(x) for x in cl["group_line_prefixes"]):
                raw.append("UNRECOGNIZED")
    verified = "Verification: OK" in lines
    peer_ok = ("Verified peername: %s" % policy["test_certificates"]["expected_peer_name"]) in lines
    tls13 = any(re.match(p, ln) for p in cl["tls13_patterns"] for ln in lines)
    alert40 = cl["tls_failure_marker"] in text
    group = aliases.get(raw[0]) if len(raw) == 1 else None
    if rc == 0 and group and verified and peer_ok and tls13 and not alert40 and not null_lines:
        cls = "ok"
    elif rc not in (0, None) and alert40 and not raw and not any(
            l.startswith("Verified peername:") for l in lines):
        cls = "tls_failure"
    else:
        cls = "client_error"
    return {"classification": cls, "group": group if cls == "ok" else None,
            "raw_group_lines": raw, "null_group_lines": null_lines, "verified": verified,
            "peer_name_ok": peer_ok,
            "tls13": tls13}


def judge(parsed, expect):
    cls = parsed["classification"]
    if cls == "client_error":
        return "blocked"
    if expect["result"] == "ok":
        if cls != "ok":
            return "fail"
        want = expect.get("group_in") or [expect["group"]]
        return "pass" if parsed["group"] in want else "fail"
    return "pass" if cls == "tls_failure" else "fail"


# ---------------------------------------------------------------- verdict logic

RES = {"pass": "PASS", "fail": "FAIL", "blocked": "BLOCKED", "not_run": "NOT_RUN"}


def source_binding(src, patch, policy, case):
    """The per-arm file written into each export must be the validated result."""
    got = src.get("patched_file_sha256")
    external = bool(policy["cases"].get(case, {}).get("external_input"))
    if got is None and not external:
        return []  # older receipts do not carry the field
    if not isinstance(got, dict) or sorted(got) != sorted(ARMS):
        return ["per-arm patched-file hashes missing"]
    if case == "baseline":
        want = policy["patch_policy"]["allowed_files"]["src/include/libpq/libpq.h"]["sha256"]
    else:
        want = patch.get("patched_sha256") if isinstance(patch, dict) else None
    if not want:
        return ["no validated result to compare with"]
    return ["%s arm file differs from the validated result" % a for a in ARMS if got[a] != want]


def mandatory_ids(policy):
    mc = policy["mandatory_checks"]
    return list(mc["global"]) + ["%s.%s" % (a, c) for a in ARMS for c in mc["per_arm"]]


def evaluate(obs, policy, read_log, fixture_sha=None, read_ref=None, pinned_header=None):
    """Derive the verdict from observations, logs and policy only.

    fixture_sha: fixture name -> SHA-256 of the current fixture files (scripted-input binding).
    read_ref: run id -> raw verdict.json bytes of a reference run, or None.
    pinned_header: text of the pinned libpq.h (authenticated by SHA-256 here); a candidate's
    snapshot is re-applied to it. Without it a candidate cannot be ACCEPT.
    """
    rec = obs.get("receipts") if isinstance(obs.get("receipts"), dict) else {}
    case = obs.get("case")
    ref = obs.get("reference")
    ref_ok = not (isinstance(ref, dict) and read_ref is not None and reference_problems(ref, read_ref))
    binding = candidate_binding(obs, policy, read_log, fixture_sha, read_ref, pinned_header)

    def load(rid):
        r = rec.get(rid)
        if not isinstance(r, dict) or r.get("id") != rid or r.get("status") not in RES:
            return None, None, "missing or malformed receipt %s" % rid
        data = None
        if r.get("log") is not None:
            data = read_log(r["log"])
            if data is None:
                return None, None, "missing log for %s" % rid
            if sha256_bytes(data) != r.get("log_sha256"):
                return None, None, "log hash mismatch for %s" % rid
        return r, data, None

    def ref_pass(arm, chk):
        return (case != "baseline" and isinstance(ref, dict) and ref_ok
                and ref.get("gate_identity") == obs.get("gate_identity")
                and ref.get("arm_results", {}).get(arm, {}).get(chk) == "PASS")

    def handshake(rid, expect):
        r, data, err = load(rid)
        if err:
            return "BLOCKED", err
        if r["status"] == "not_run":
            return "NOT_RUN", r.get("detail", "")
        if data is None:
            return "BLOCKED", "no client transcript: %s" % r.get("detail", "")
        parsed = parse_client_output(data.decode("utf-8", "replace"), r.get("client_rc"), policy)
        status = judge(parsed, expect)
        if (parsed["classification"] != r.get("classification") or parsed["group"] != r.get("group")
                or status != r["status"]):
            return "BLOCKED", "receipt for %s disagrees with its log" % rid
        if status == "blocked":
            return "BLOCKED", "client output not classifiable"
        return RES[status], "observed %s group=%s" % (parsed["classification"], parsed["group"])

    out = {}
    for rid in policy["mandatory_checks"]["global"]:
        if rid == "controls":
            res, notes = "PASS", []
            for c in policy["controls"]:
                cr, cn = handshake("control." + c["id"], c["expect"])
                if cr != "PASS":
                    res = "BLOCKED"
                    notes.append("control.%s %s (%s)" % (c["id"], cr, cn))
            out[rid] = (res, "reference", ["control." + c["id"] for c in policy["controls"]],
                        "; ".join(notes) or "all reference controls matched")
            continue
        r, _d, err = load(rid)
        if rid == "patch" and binding:
            out[rid] = ("BLOCKED", "evidence", [rid, "input"], "candidate binding: " + "; ".join(binding))
            continue
        if err:
            out[rid] = ("BLOCKED", "evidence", [rid], err)
            continue
        res = RES[r["status"]]
        if rid == "patch":
            attr = "candidate" if res == "FAIL" else "policy"
        else:
            attr = "environment"
            if res == "FAIL":
                res = "BLOCKED"
        if rid == "source" and res == "PASS":
            sp = source_binding(r, rec.get("patch"), policy, case)
            if sp:
                out[rid] = ("BLOCKED", "evidence", [rid, "patch"], "source binding: " + "; ".join(sp))
                continue
        out[rid] = (res, attr, [rid], r.get("detail", ""))

    for arm in ARMS:
        expects = {h["id"]: h["expect"] for h in policy["handshake_matrix"][arm]}
        for chk in policy["mandatory_checks"]["per_arm"]:
            rid = "%s.%s" % (arm, chk)
            if chk.startswith("hs."):
                res, note = handshake(rid, expects[chk[3:]])
                out[rid] = (res, "policy" if res == "FAIL" else "observation", [rid], note)
                continue
            r, data, err = load(rid)
            if err:
                out[rid] = ("BLOCKED", "evidence", [rid], err)
                continue
            res, note, attr = RES[r["status"]], r.get("detail", ""), "measurement"
            if chk == "identity" and res == "FAIL":
                res, attr = "BLOCKED", "environment"
            if chk in ("build", "regression") and res == "FAIL":
                if ref_pass(arm, chk):
                    attr = "candidate (reference baseline passed %s in this arm)" % chk
                else:
                    res, attr = "BLOCKED", "unattributed (no matching reference pass)"
            if chk == "startup" and res == "FAIL":
                marker = data is not None and SSL_GROUPS_ERROR.encode() in data
                if marker:
                    attr = "candidate (server log shows ssl_groups configuration error)"
                elif ref_pass(arm, "startup"):
                    attr = "candidate (reference baseline started in this arm)"
                else:
                    res, attr = "BLOCKED", "unattributed (no ssl_groups error, no reference pass)"
            out[rid] = (res, attr, [rid], note)

    order = mandatory_ids(policy)
    checks = [{"id": k, "result": out[k][0], "attribution": out[k][1],
               "evidence": out[k][2], "note": out[k][3], "required": True} for k in order]
    counts = {"mandatory": len(order)}
    for k in ("PASS", "FAIL", "BLOCKED", "NOT_RUN"):
        counts[k.lower()] = sum(1 for c in checks if c["result"] == k)
    counts["attempted"] = counts["mandatory"] - counts["not_run"]

    def first(pred):
        for c in checks:
            if pred(c):
                return c
        return None

    ident_blocked = {a for a in ARMS if out["%s.identity" % a][0] == "BLOCKED"}
    c = first(lambda c: c["id"] in ("preflight", "controls") and c["result"] != "PASS")
    if c:
        outcome, why = "BLOCKED", c
    elif out["patch"][0] == "FAIL":
        outcome, why = "REJECT", first(lambda c: c["id"] == "patch")
    else:
        c = first(lambda c: c["id"] in ("patch", "source", "integrity") and c["result"] != "PASS")
        if c:
            outcome, why = "BLOCKED", c
        else:
            c = first(lambda c: c["result"] == "FAIL" and c["id"].split(".")[0] not in ident_blocked)
            if c:
                outcome, why = "REJECT", c
            else:
                c = first(lambda c: c["result"] != "PASS")
                outcome, why = ("BLOCKED", c) if c else ("ACCEPT", None)
    if why is None:
        reason = "all %d mandatory checks PASS" % counts["mandatory"]
    else:
        reason = "%s %s: %s" % (why["id"], why["result"], why["note"] or why["attribution"])
    return {"outcome": outcome, "reason": reason, "checks": checks, "counts": counts}


# ---------------------------------------------------------------- run helpers

class Ctx(object):
    pass


def child_env(ctx, extra=None):
    env = {"PATH": CHILD_PATH, "HOME": ctx.home, "LANG": "C", "LC_ALL": "C",
           "TMPDIR": ctx.tmp, "GIT_OPTIONAL_LOCKS": "0"}
    if extra:
        env.update(extra)
    return env


def run_cmd(ctx, argv, log_path, cwd=None, timeout=600, extra_env=None, stdin_data=None,
            step=None):
    """Run argv (no shell) with the allowlisted environment; output to a private log."""
    t0 = time.time()
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    with open(log_path, "ab") as log:
        log.write(("$ %s\n" % " ".join(shlex.quote(a) for a in argv)).encode())
        log.flush()
        try:
            p = subprocess.Popen(argv, cwd=cwd, env=child_env(ctx, extra_env),
                                 stdin=subprocess.PIPE if stdin_data is not None else subprocess.DEVNULL,
                                 stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        except OSError as e:
            log.write(("cannot run: %s\n[exit error]\n" % e.strerror).encode())
            if step:
                ctx.steps.append({"step": step, "seconds": 0.0, "exit": "error"})
            return "error"
        try:
            p.communicate(stdin_data, timeout=timeout)
            rc = p.returncode
        except subprocess.TimeoutExpired:
            kill_group(p)
            rc = "timeout"
        log.write(("\n[exit %s]\n" % rc).encode())
    if step:
        ctx.steps.append({"step": step, "seconds": round(time.time() - t0, 1), "exit": str(rc)})
    return rc


def kill_group(p):
    """Stop only the process group this harness created for p."""
    for sig, wait in ((signal.SIGTERM, 10), (signal.SIGKILL, 5)):
        try:
            os.killpg(p.pid, sig)
        except (ProcessLookupError, PermissionError):
            return
        try:
            p.wait(timeout=wait)
            return
        except subprocess.TimeoutExpired:
            continue


def capture(ctx, argv, timeout=120, extra_env=None, stdin_data=None, cwd=None):
    """Run a short command; a missing program or timeout is reported, not raised."""
    try:
        p = subprocess.run(argv, cwd=cwd, env=child_env(ctx, extra_env), input=stdin_data,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    except OSError as e:
        return 127, "", "cannot run %s: %s" % (argv[0], e.strerror)
    except subprocess.TimeoutExpired:
        return 124, "", "timeout after %ss: %s" % (timeout, argv[0])
    return p.returncode, p.stdout.decode("utf-8", "replace"), p.stderr.decode("utf-8", "replace")


def sanitize(ctx, text):
    for real, token in ctx.redactions:
        text = text.replace(real, token)
    if ctx.user:
        text = re.sub(r"(?<![A-Za-z0-9_])%s(?![A-Za-z0-9_])" % re.escape(ctx.user), "$USER", text)
    return text


def sanitize_obj(ctx, obj):
    if isinstance(obj, str):
        return sanitize(ctx, obj)
    if isinstance(obj, list):
        return [sanitize_obj(ctx, x) for x in obj]
    if isinstance(obj, dict):
        return {k: sanitize_obj(ctx, v) for k, v in obj.items()}
    return obj


def read_text(path):
    try:
        with open(path, "rb") as f:
            return f.read().decode("utf-8", "replace")
    except OSError:
        return ""


def tail(text, n):
    lines = text.splitlines()
    return lines[-n:] if len(lines) > n else lines


def publish_log(ctx, rel, sections):
    """sections: list of (title, text, tail_n or None). Writes a sanitized public log."""
    out = ["# Sanitized log. Paths shown as $HOME/$WORK/$REPO/$USER; PEM blocks removed;",
           "# long outputs truncated to their last lines as marked. Full logs stay private."]
    for title, text, n in sections:
        text = re.sub(r"-----BEGIN [A-Z ]+-----.*?-----END [A-Z ]+-----",
                      "[PEM block removed]", text, flags=re.S)
        lines = text.splitlines()
        if n is not None and len(lines) > n:
            out.append("## %s (last %d of %d lines)" % (title, n, len(lines)))
            lines = lines[-n:]
        else:
            out.append("## %s" % title)
        out.extend(lines)
    data = sanitize(ctx, "\n".join(out) + "\n").encode("utf-8")
    path = os.path.join(ctx.ev_dir, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    write_new(path, data)
    return rel, sha256_bytes(data)


def receipt(ctx, rid, status, detail, log=None, **fields):
    r = {"id": rid, "status": status, "detail": detail, "log": None, "log_sha256": None}
    if log:
        r["log"], r["log_sha256"] = log
    r.update(fields)
    ctx.receipts[rid] = sanitize_obj(ctx, r)
    print("  %-22s %-8s %s" % (rid, RES[status], sanitize(ctx, detail)[:90]))
    sys.stdout.flush()


def port_free(ctx, port):
    rc, out, _ = capture(ctx, ["lsof", "-nP", "-iTCP:%d" % port, "-sTCP:LISTEN"], timeout=30)
    return rc == 1 and not out.strip()


def dyld_paths(text):
    paths = []
    for ln in text.splitlines():
        m = re.match(r"^dyld\[\d+\]: (?:<[0-9A-Fa-f-]+> )?(/.+)$", ln.strip())
        if m:
            paths.append(m.group(1))
    return paths


def lib_identity(paths, libdir_real, lib_hashes):
    """Exactly one libssl.3 and one libcrypto.3, both from the arm's own library directory."""
    res = {"problems": [], "loaded": {}, "other_ssl_images": []}
    for name in ("libssl.3.dylib", "libcrypto.3.dylib"):
        found = sorted(set(os.path.realpath(p) for p in paths if os.path.basename(p) == name))
        res["loaded"][name] = found
        if len(found) != 1:
            res["problems"].append("%s loaded %d times" % (name, len(found)))
        elif os.path.dirname(found[0]) != libdir_real:
            res["problems"].append("%s from unexpected directory %s" % (name, found[0]))
        elif sha256_file(found[0]) != lib_hashes[name]:
            res["problems"].append("%s hash differs from preflight" % name)
    res["other_ssl_images"] = sorted(set(
        p for p in paths if re.search(r"/lib(ssl|crypto)[.0-9]*\.dylib$", p)
        and os.path.basename(p) not in ("libssl.3.dylib", "libcrypto.3.dylib")))
    return res


def tree_manifest(root):
    man = {}
    for d, dirs, files in os.walk(root):
        dirs.sort()
        for fn in sorted(files + [x for x in dirs if os.path.islink(os.path.join(d, x))]):
            p = os.path.join(d, fn)
            rel = os.path.relpath(p, root)
            if os.path.islink(p):
                man[rel] = "symlink:" + os.readlink(p)
            elif os.path.isfile(p):
                man[rel] = sha256_file(p)
    return man


def manifest_digest(man):
    return sha256_bytes(canon(man).encode("utf-8"))


def git_blob(ctx, rev_path):
    p = subprocess.run(["git", "-C", ctx.pg_git, "show", rev_path], env=child_env(ctx),
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
    if p.returncode != 0:
        raise RuntimeError("git show %s failed" % rev_path)
    return p.stdout


def protected_state(ctx):
    pin = ctx.policy["upstream"]["commit"]
    st = {}
    rc, out, _ = capture(ctx, ["git", "-C", ctx.pg_git, "rev-parse", "HEAD"])
    st["head"] = out.strip() if rc == 0 else "ERROR"
    rc, out, _ = capture(ctx, ["git", "-C", ctx.pg_git, "cat-file", "-t", pin])
    st["pin_type"] = out.strip() if rc == 0 else "ERROR"
    rc, out, _ = capture(ctx, ["git", "-C", ctx.pg_git, "status", "--porcelain",
                               "--untracked-files=no"], timeout=300)
    st["tracked_modified"] = len([l for l in out.splitlines() if l.strip()]) if rc == 0 else -1
    bindir = os.path.join(ctx.pg_git, "bin")
    hashes = {}
    if os.path.isdir(bindir):
        for fn in sorted(os.listdir(bindir)):
            p = os.path.join(bindir, fn)
            if os.path.isfile(p) and not os.path.islink(p):
                hashes[fn] = sha256_file(p)
    st["installed_bin_files"] = len(hashes)
    st["installed_bin_digest"] = manifest_digest(hashes)
    return st


# ---------------------------------------------------------------- run stages

def stage_preflight(ctx):
    pol = ctx.policy
    problems, facts = [], {}
    st = protected_state(ctx)
    ctx.protected_before = st
    facts["protected_upstream"] = st
    pin = pol["upstream"]["commit"]
    if st["head"] != pin or st["pin_type"] != "commit" or st["tracked_modified"] != 0:
        problems.append("protected upstream not at pin or has tracked modifications")
    tools = {}
    for t in ("git", "tar", "make", "clang", "bison", "flex", "perl", "lsof", "otool", "ps"):
        rc, out, _ = capture(ctx, ["/usr/bin/which", t])
        tools[t] = out.strip() if rc == 0 else "MISSING"
        if rc != 0:
            problems.append("tool missing from allowlisted PATH: " + t)
    facts["tools"] = tools
    vers = {}
    for name, argv in (("clang", ["clang", "--version"]), ("make", ["make", "--version"]),
                       ("bison", ["bison", "--version"]), ("flex", ["flex", "--version"]),
                       ("perl", ["perl", "-e", "print $^V"]), ("macos", ["sw_vers", "-productVersion"]),
                       ("arch", ["uname", "-m"])):
        try:
            rc, out, _ = capture(ctx, argv)
            vers[name] = out.strip().splitlines()[0] if out.strip() else "UNKNOWN"
        except (OSError, subprocess.SubprocessError):
            vers[name] = "UNKNOWN"
    vers["python"] = sys.version.split()[0]
    facts["host"] = vers
    ctx.arm = {}
    for arm in ARMS:
        prefix = ctx.prefixes[arm]
        a = {"prefix": prefix, "prefix_real": os.path.realpath(prefix)}
        a["libdir_real"] = os.path.realpath(os.path.join(prefix, "lib"))
        hdr = read_text(os.path.join(prefix, "include", "openssl", "opensslv.h"))
        m = re.search(r'define OPENSSL_VERSION_STR "([^"]+)"', hdr)
        a["header_version"] = m.group(1) if m else None
        v = version_tuple(a["header_version"])
        spec = pol["matrix"][arm]
        if not v or not (tuple(spec["min_version"]) <= v < tuple(spec["max_version_exclusive"])):
            problems.append("%s: header version %s outside %s" % (arm, a["header_version"], spec["label"]))
        a["lib_sha256"] = {}
        for name in ("libssl.3.dylib", "libcrypto.3.dylib", "libssl.dylib"):
            p = os.path.join(prefix, "lib", name)
            if not os.path.isfile(p):
                problems.append("%s: missing %s" % (arm, name))
            elif name != "libssl.dylib":
                a["lib_sha256"][name] = sha256_file(os.path.realpath(p))
        rc, out, _ = capture(ctx, ["otool", "-L", os.path.join(prefix, "lib", "libssl.3.dylib")])
        deps = [l.strip().split(" (")[0] for l in out.splitlines()[1:] if "libcrypto" in l]
        a["libssl_libcrypto_dep"] = deps
        if len(deps) != 1 or os.path.dirname(os.path.realpath(deps[0])) != a["libdir_real"]:
            problems.append("%s: libssl does not bind libcrypto from its own prefix" % arm)
        cli = os.path.join(prefix, "bin", "openssl")
        rc, out, err = capture(ctx, [cli, "version"], extra_env={"DYLD_PRINT_LIBRARIES": "1"})
        a["cli"] = cli
        a["cli_version"] = out.strip()
        li = lib_identity(dyld_paths(err), a["libdir_real"], a["lib_sha256"]) if a["lib_sha256"] else {"problems": ["no libs"]}
        a["cli_runtime"] = li
        lv = re.search(r"\(Library: OpenSSL (\d+\.\d+\.\d+)", out)
        a["runtime_version"] = lv.group(1) if lv else None
        if li["problems"] or a["runtime_version"] != a["header_version"]:
            problems.append("%s: prefix openssl CLI runtime identity mismatch %s" % (arm, li["problems"]))
        ctx.arm[arm] = a
    if ctx.arm["newer"]["libdir_real"] == ctx.arm["v30"]["libdir_real"]:
        problems.append("both arms resolve to the same library directory")
    if not os.path.isfile(ctx.client):
        raise RuntimeError("reference client not found")
    cl = {"path": ctx.client, "real": os.path.realpath(ctx.client), "sha256": sha256_file(ctx.client)}
    rc, out, err = capture(ctx, [ctx.client, "version"], extra_env={"DYLD_PRINT_LIBRARIES": "1"})
    cl["version"] = out.strip()
    cl["runtime"] = lib_identity(dyld_paths(err), ctx.arm["newer"]["libdir_real"],
                                 ctx.arm["newer"]["lib_sha256"])
    if cl["runtime"]["problems"]:
        problems.append("reference client does not load the newer-arm libraries")
    ctx.client_info = cl
    facts["reference_client"] = cl
    facts["arms"] = ctx.arm
    ports = [pol["matrix"][a]["server_port"] for a in ARMS] + [c["port"] for c in pol["controls"]]
    busy = [p for p in ports if not port_free(ctx, p)]
    if busy:
        problems.append("ports in use: %s" % busy)
    facts["ports"] = ports
    sock_len = len(os.path.join(ctx.run_dir, "tmp", "pg_regress-XXXXXX", ".s.PGSQL.55555"))
    if sock_len > 100:
        problems.append("socket path too long (%d)" % sock_len)
    facts["child_env_keys"] = sorted(child_env(ctx).keys())
    facts["credential_like_names_in_parent"] = sorted(k for k in os.environ if CRED_NAME.search(k))
    facts["credential_like_names_in_child"] = sorted(k for k in child_env(ctx) if CRED_NAME.search(k))
    ctx.env_facts.update(facts)
    lines = ["problems: %s" % (problems or "none"), canon(sanitize_obj(ctx, facts))]
    log = publish_log(ctx, "logs/preflight.txt", [("preflight", "\n".join(lines), None)])
    receipt(ctx, "preflight", "fail" if problems else "pass",
            "; ".join(problems) or "pin, prefixes, client, ports and tools verified", log)
    return not problems


def stage_certs(ctx):
    tc = ctx.policy["test_certificates"]
    pin = ctx.policy["upstream"]["commit"]
    d = os.path.join(ctx.run_dir, "certs")
    os.makedirs(d, mode=0o700)
    ctx.certs = {}
    blobs = {}
    for key, mode in (("server_cert", 0o644), ("server_key", 0o600), ("ca_cert", 0o644)):
        data = git_blob(ctx, "%s:%s" % (pin, tc[key]))
        p = os.path.join(d, os.path.basename(tc[key]))
        write_new(p, data, mode)
        ctx.certs[key] = p
        rc, out, _ = capture(ctx, ["git", "-C", ctx.pg_git, "rev-parse", "%s:%s" % (pin, tc[key])])
        blobs[tc[key]] = out.strip()
    ctx.env_facts["test_certificate_blobs"] = blobs


def s_client(ctx, port, offer, starttls, log_path):
    argv = [ctx.client, "s_client", "-connect", "127.0.0.1:%d" % port]
    if starttls:
        argv += ["-starttls", "postgres"]
    argv += ["-tls1_3", "-groups", offer, "-CAfile", ctx.certs["ca_cert"],
             "-verify_hostname", ctx.policy["test_certificates"]["expected_peer_name"],
             "-verify_return_error"]
    p = subprocess.Popen(argv, env=child_env(ctx), stdin=subprocess.DEVNULL,
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True)
    try:
        out, _ = p.communicate(timeout=30)
        rc = p.returncode
    except subprocess.TimeoutExpired:
        kill_group(p)
        out, rc = b"", None
    text = out.decode("utf-8", "replace")
    with open(log_path, "wb") as f:
        f.write(("$ %s\n" % " ".join(shlex.quote(a) for a in argv)).encode() + out
                + ("\n[exit %s]\n" % rc).encode())
    return rc, text, argv


def wait_listen(ctx, pid, port, seconds):
    end = time.time() + seconds
    while time.time() < end:
        rc, out, _ = capture(ctx, ["lsof", "-nP", "-a", "-p", str(pid), "-iTCP:%d" % port,
                                   "-sTCP:LISTEN"], timeout=30)
        if rc == 0 and out.strip():
            return True
        time.sleep(0.3)
    return False


def stage_controls(ctx):
    ok = True
    for c in ctx.policy["controls"]:
        rid = "control." + c["id"]
        arm = ctx.arm[c["server_arm"]]
        plog = os.path.join(ctx.priv, "controls", c["id"] + ".log")
        os.makedirs(os.path.dirname(plog), exist_ok=True)
        if not port_free(ctx, c["port"]):
            receipt(ctx, rid, "blocked", "port %d busy" % c["port"])
            ok = False
            continue
        sargv = [arm["cli"], "s_server", "-accept", "127.0.0.1:%d" % c["port"], "-naccept", "1",
                 "-tls1_3", "-groups", c["server_groups"], "-cert", ctx.certs["server_cert"],
                 "-key", ctx.certs["server_key"], "-quiet"]
        slog = open(plog + ".server", "wb")
        srv = subprocess.Popen(sargv, env=child_env(ctx), stdin=subprocess.PIPE, stdout=slog,
                               stderr=subprocess.STDOUT, start_new_session=True)
        ctx.processes.append({"what": "control s_server %s" % c["id"], "pid": srv.pid})
        try:
            if not wait_listen(ctx, srv.pid, c["port"], 10):
                receipt(ctx, rid, "blocked", "control server did not listen")
                ok = False
                continue
            rc, text, _ = s_client(ctx, c["port"], c["offer"], False, plog)
        finally:
            try:
                srv.stdin.close()
            except OSError:
                pass
            try:
                srv.wait(timeout=5)
            except subprocess.TimeoutExpired:
                kill_group(srv)
            slog.close()
            ctx.processes[-1]["stopped"] = srv.poll() is not None
        parsed = parse_client_output(text, rc, ctx.policy)
        status = judge(parsed, c["expect"])
        ok = ok and status == "pass"
        log = publish_log(ctx, "logs/controls/%s.txt" % c["id"], [
            ("server: openssl s_server (%s arm) -groups %s" % (c["server_arm"], c["server_groups"]), "", None),
            ("client output", read_text(plog), None)])
        receipt(ctx, rid, status, "server_groups=%s offer=%s -> %s %s" % (
            c["server_groups"], c["offer"], parsed["classification"], parsed["group"]), log,
            client_rc=rc, classification=parsed["classification"], group=parsed["group"],
            offer=c["offer"], server_groups=c["server_groups"], server_arm=c["server_arm"])
    return ok


def stage_patch_candidate(ctx, original):
    """External input: validate and apply the snapshot bytes written at run start."""
    pol = ctx.policy
    info = ctx.candidate["info"]
    fields = {"fixture": None, "input_origin": info["origin"], "derived_from": info["derived_from"],
              "patch_sha256": info["sha256"], "snapshot": info["snapshot"]}
    ctx.patch_info = dict(info, kind="external")
    try:
        with open(os.path.join(ctx.ev_dir, info["snapshot"]), "rb") as f:
            raw = f.read(pol["patch_policy"]["max_patch_bytes"] + 1)
    except OSError as e:
        raw = None
        why = "snapshot not readable: %s" % e.strerror
    if raw is not None and (raw != ctx.candidate["bytes"] or sha256_bytes(raw) != info["sha256"]):
        why, raw = "snapshot differs from the bytes read at run start", None
    if raw is None:
        log = publish_log(ctx, "logs/patch.txt", [("patch input", why, None)])
        receipt(ctx, "patch", "blocked", why, log, **fields)
        return False
    fields["snapshot_sha256"] = sha256_bytes(raw)
    origin_line = "external input (origin %s%s), snapshot %s, %d bytes, SHA-256 %s" % (
        info["origin"], ", exact copy of fixture %s" % info["derived_from"] if info["derived_from"] else "",
        info["snapshot"], len(raw), info["sha256"])
    try:
        tpath, patched, diff = validate_and_apply(raw, original, pol)
    except PatchError as e:
        log = publish_log(ctx, "logs/patch.txt", [("patch input", origin_line, None),
                                                  ("patch validation", "REJECTED: %s" % e, None)])
        receipt(ctx, "patch", "fail", "patch rejected by policy: %s" % e, log, **fields)
        return False
    ctx.patched = (tpath, patched)
    log = publish_log(ctx, "logs/patch.txt", [
        ("patch input", origin_line, None),
        ("patch validation", "snapshot validated: single allowed file, edits within lines %s, "
         "added lines match policy patterns, exact context, no change outside region" % (
             pol["patch_policy"]["allowed_files"][tpath]["editable_lines"]), None),
        ("resulting source diff (harness-computed)", "\n".join(diff), None)])
    receipt(ctx, "patch", "pass", "external input (origin %s) validated and applied in memory" % info["origin"],
            log, patched_sha256=sha256_bytes(patched.encode("utf-8")), **fields)
    return True


def stage_patch(ctx):
    pol = ctx.policy
    fixture = pol["cases"][ctx.case]["fixture"]
    path = "src/include/libpq/libpq.h"
    original = git_blob(ctx, "%s:%s" % (pol["upstream"]["commit"], path)).decode("utf-8")
    ctx.patch_info = None
    if pol["cases"][ctx.case].get("external_input"):
        return stage_patch_candidate(ctx, original)
    if fixture is None:
        ctx.patched = None
        log = publish_log(ctx, "logs/patch.txt", [("patch", "case baseline: no patch applied", None)])
        receipt(ctx, "patch", "pass", "no patch (baseline)", log, fixture=None)
        return True
    fpath = os.path.join(REPO, pol["fixtures"][fixture]["path"])
    with open(fpath, "rb") as f:
        raw = f.read()
    ctx.patch_info = {"fixture": fixture, "path": pol["fixtures"][fixture]["path"],
                      "sha256": sha256_bytes(raw), "meaning": pol["fixtures"][fixture]["meaning"]}
    try:
        tpath, patched, diff = validate_and_apply(raw, original, pol)
    except PatchError as e:
        log = publish_log(ctx, "logs/patch.txt", [("patch validation", "REJECTED: %s" % e, None)])
        receipt(ctx, "patch", "fail", "patch rejected by policy: %s" % e, log, fixture=fixture)
        return False
    ctx.patched = (tpath, patched)
    log = publish_log(ctx, "logs/patch.txt", [
        ("patch validation", "fixture %s validated: single allowed file, edits within lines %s, "
         "added lines match policy patterns, exact context, no change outside region" % (
             fixture, pol["patch_policy"]["allowed_files"][tpath]["editable_lines"]), None),
        ("resulting source diff (harness-computed)", "\n".join(diff), None)])
    receipt(ctx, "patch", "pass", "fixture %s validated and applied in memory" % fixture, log,
            fixture=fixture, patch_sha256=ctx.patch_info["sha256"],
            patched_sha256=sha256_bytes(patched.encode("utf-8")))
    return True


def stage_source(ctx):
    pol = ctx.policy
    pin = pol["upstream"]["commit"]
    rel = "src/include/libpq/libpq.h"
    lines, problems, facts, written = [], [], {}, {}
    for arm in ARMS:
        src = os.path.join(ctx.run_dir, "src-" + arm)
        os.makedirs(src)
        plog = os.path.join(ctx.priv, arm, "export.log")
        os.makedirs(os.path.dirname(plog), exist_ok=True)
        with open(plog, "wb") as log:
            g = subprocess.Popen(["git", "-C", ctx.pg_git, "archive", "--format=tar", pin],
                                 env=child_env(ctx), stdout=subprocess.PIPE, stderr=log)
            t = subprocess.Popen(["tar", "-x", "-f", "-", "-C", src], env=child_env(ctx),
                                 stdin=g.stdout, stdout=log, stderr=log)
            g.stdout.close()
            trc, grc = t.wait(timeout=600), g.wait(timeout=600)
        if grc != 0 or trc != 0:
            problems.append("%s: export failed (git %s, tar %s)" % (arm, grc, trc))
            continue
        target = os.path.join(src, rel)
        if sha256_file(target) != pol["patch_policy"]["allowed_files"][rel]["sha256"]:
            problems.append("%s: exported %s hash differs from pin" % (arm, rel))
            continue
        before = tree_manifest(src)
        if ctx.patched is not None:
            with open(target, "wb") as f:
                f.write(ctx.patched[1].encode("utf-8"))
        after = tree_manifest(src)
        written[arm] = sha256_file(target)
        changed = sorted(k for k in set(before) | set(after) if before.get(k) != after.get(k))
        expected = [rel] if ctx.patched is not None else []
        if changed != expected:
            problems.append("%s: changed files %s, expected %s" % (arm, changed, expected))
        facts[arm] = {"files": len(before), "export_digest": manifest_digest(before),
                      "candidate_digest": manifest_digest(after), "changed_files": changed}
        ctx.arm[arm]["src"] = src
        ctx.arm[arm]["candidate_manifest_digest"] = manifest_digest(after)
        lines.append("%s: %d files, export digest %s, changed %s" % (
            arm, len(before), facts[arm]["export_digest"], changed))
    if len(facts) == 2 and facts["newer"]["export_digest"] != facts["v30"]["export_digest"]:
        problems.append("the two exports differ")
    rc, out, _ = capture(ctx, ["git", "-C", ctx.pg_git, "rev-parse", pin + "^{tree}"])
    facts["tree"] = out.strip()
    want = (sha256_bytes(ctx.patched[1].encode("utf-8")) if ctx.patched is not None
            else pol["patch_policy"]["allowed_files"][rel]["sha256"])
    for arm, h in sorted(written.items()):
        lines.append("%s: %s SHA-256 after writing %s" % (arm, rel, h))
        if h != want:
            problems.append("%s: %s after writing differs from the validated result" % (arm, rel))
    ctx.env_facts["source"] = facts
    log = publish_log(ctx, "logs/source.txt", [("fresh exports per arm", "\n".join(
        lines + ["problems: %s" % (problems or "none")]), None)])
    receipt(ctx, "source", "fail" if problems else "pass",
            "; ".join(problems) or "fresh export per arm; only the allowed file differs from the pin",
            log, patched_file_sha256=written if len(written) == len(ARMS) else None)
    return not problems


def stage_arm(ctx, arm):
    """Build, regression, identity, startup and handshakes for one arm."""
    pol = ctx.policy
    a = ctx.arm[arm]
    pdir = os.path.join(ctx.priv, arm)
    build = os.path.join(ctx.run_dir, "build-" + arm)
    prefix = os.path.join(ctx.run_dir, "prefix-" + arm)
    data = os.path.join(ctx.run_dir, "data-" + arm)
    os.makedirs(build)
    port = pol["matrix"][arm]["server_port"]
    hs_ids = ["hs." + h["id"] for h in pol["handshake_matrix"][arm]]
    ident = {"arm": arm}

    def not_run(ids, why):
        for i in ids:
            receipt(ctx, "%s.%s" % (arm, i), "not_run", "not run: " + why)

    # build
    osp = a["prefix"]
    steps = [("configure", [os.path.join(a["src"], "configure"), "--prefix=" + prefix]
              + pol["configure_args"] + ["CPPFLAGS=-I%s/include" % osp, "LDFLAGS=-L%s/lib" % osp], 1800),
             ("make", ["make", "-j", str(ctx.jobs)], 3600),
             ("install", ["make", "install"], 1200)]
    sections, brc = [], 0
    for name, argv, to in steps:
        lp = os.path.join(pdir, name + ".log")
        brc = run_cmd(ctx, argv, lp, cwd=build, timeout=to, step="%s.%s" % (arm, name))
        sections.append(("%s (exit %s)" % (name, brc), read_text(lp), 40))
        if brc != 0:
            break
    a["configure_argv"] = steps[0][1]
    log = publish_log(ctx, "logs/%s/build.txt" % arm, sections)
    if brc != 0:
        st = "blocked" if brc in ("timeout", "error") else "fail"
        receipt(ctx, arm + ".build", st, "%s exit %s" % (sections[-1][0].split()[0], brc), log)
        not_run(["identity", "regression", "startup"] + hs_ids, "build did not complete")
        return
    receipt(ctx, arm + ".build", "pass", "configure, make, make install exit 0", log)

    # static identity: headers and linkage
    probs = []
    bindir = os.path.join(prefix, "bin")
    rc, cc, _ = capture(ctx, [os.path.join(bindir, "pg_config"), "--cc"])
    rc2, cppf, _ = capture(ctx, [os.path.join(bindir, "pg_config"), "--cppflags"])
    ccv, cppv = shlex.split(cc.strip()), shlex.split(cppf.strip())
    ident["pg_config_cc"], ident["pg_config_cppflags"] = cc.strip(), cppf.strip()
    src_in = b"#include <openssl/opensslv.h>\n"
    _, dm, _ = capture(ctx, ccv + cppv + ["-E", "-dM", "-x", "c", "-"], stdin_data=src_in)
    m = re.search(r'#define OPENSSL_VERSION_STR "([^"]+)"', dm)
    ident["compile_header_version"] = m.group(1) if m else None
    _, pre, _ = capture(ctx, ccv + cppv + ["-E", "-x", "c", "-"], stdin_data=src_in)
    hp = sorted(set(re.findall(r'^# \d+ "([^"]*/openssl/opensslv\.h)"', pre, re.M)))
    ident["compile_header_path"] = hp
    inc_real = os.path.realpath(os.path.join(osp, "include", "openssl"))
    if ident["compile_header_version"] != a["header_version"]:
        probs.append("compile-time header version %s" % ident["compile_header_version"])
    if len(hp) != 1 or os.path.dirname(os.path.realpath(hp[0])) != inc_real:
        probs.append("opensslv.h resolved outside the arm prefix: %s" % hp)
    _, otl, _ = capture(ctx, ["otool", "-L", os.path.join(bindir, "postgres")])
    linked = [l.strip().split(" (")[0] for l in otl.splitlines()[1:] if "libssl" in l or "libcrypto" in l]
    ident["postgres_linked"] = linked
    lk = lib_identity(linked, a["libdir_real"], a["lib_sha256"])
    probs += ["linkage: " + p for p in lk["problems"]]

    # regression
    lp = os.path.join(pdir, "check.log")
    rrc = run_cmd(ctx, ["make", "check"], lp, cwd=build, timeout=3600, step=arm + ".regression")
    text = read_text(lp)
    summ = [l for l in text.splitlines() if re.search(r"tests? (passed|failed)|All \d+ tests", l)]
    secs = [("make check (exit %s)" % rrc, text, 60)]
    diffs = os.path.join(build, "src", "test", "regress", "regression.diffs")
    if rrc != 0 and os.path.isfile(diffs):
        secs.append(("regression.diffs (first lines)", "\n".join(read_text(diffs).splitlines()[:150]), None))
    log = publish_log(ctx, "logs/%s/regression.txt" % arm, secs)
    receipt(ctx, arm + ".regression", "pass" if rrc == 0 else ("blocked" if rrc in ("timeout", "error") else "fail"),
            (summ[-1].strip() if summ else "make check exit %s" % rrc), log)

    # cluster, runtime identity via dyld on our own binary
    lp = os.path.join(pdir, "initdb.log")
    irc = run_cmd(ctx, [os.path.join(bindir, "initdb"), "-D", data, "-A", "trust", "-N",
                        "-E", "UTF8", "--no-locale", "--no-instructions"], lp, timeout=600,
                  step=arm + ".initdb")
    initdb_text = read_text(lp)
    started = False
    pid = None
    server_log = os.path.join(pdir, "server.log")
    try:
        if irc == 0:
            for key, fn in (("server_cert", "server.crt"), ("server_key", "server.key")):
                with open(ctx.certs[key], "rb") as f:
                    write_new(os.path.join(data, fn), f.read(), 0o600)
            s = pol["server_settings"]
            conf = ("\n# gate settings\nlisten_addresses = '%s'\nport = %d\n"
                    "unix_socket_directories = '%s'\nssl = %s\nssl_cert_file = '%s'\n"
                    "ssl_key_file = '%s'\n") % (s["listen_addresses"], port, ctx.sock, s["ssl"],
                                               s["ssl_cert_file"], s["ssl_key_file"])
            with open(os.path.join(data, "postgresql.conf"), "a") as f:
                f.write(conf)
            rc, out, err = capture(ctx, [os.path.join(bindir, "postgres"), "-D", data, "-C", "ssl_groups"],
                                   extra_env={"DYLD_PRINT_LIBRARIES": "1"})
            ident["compiled_default_ssl_groups"] = out.strip() if rc == 0 else None
            dy = lib_identity(dyld_paths(err), a["libdir_real"], a["lib_sha256"])
            ident["dyld_runtime"] = dy
            probs += ["dyld: " + p for p in dy["problems"]]
            if rc != 0:
                probs.append("postgres -C ssl_groups exit %s" % rc)
        else:
            probs.append("initdb exit %s" % irc)

        # startup
        if irc == 0:
            if not port_free(ctx, port):
                receipt(ctx, arm + ".startup", "blocked", "port %d busy before start" % port)
            else:
                lp = os.path.join(pdir, "pg_ctl_start.log")
                src_ = run_cmd(ctx, [os.path.join(bindir, "pg_ctl"), "-D", data, "-l", server_log,
                                     "-w", "-t", "60", "start"], lp, timeout=120, step=arm + ".start")
                pidf = os.path.join(data, "postmaster.pid")
                if os.path.isfile(pidf):
                    try:
                        pid = int(read_text(pidf).splitlines()[0])
                        ctx.processes.append({"what": "postmaster %s" % arm, "pid": pid})
                    except (ValueError, IndexError):
                        pid = None
                listening = pid is not None and src_ == 0 and wait_listen(ctx, pid, port, 15)
                started = listening
                slog_text = read_text(server_log)
                log = publish_log(ctx, "logs/%s/startup.txt" % arm, [
                    ("initdb", initdb_text, 15), ("pg_ctl start", read_text(lp), 20),
                    ("server log", slog_text, 40)])
                if started:
                    receipt(ctx, arm + ".startup", "pass", "server listening on 127.0.0.1:%d with ssl=on" % port, log)
                else:
                    receipt(ctx, arm + ".startup", "fail",
                            "server did not start (ssl_groups error in log: %s)" % (SSL_GROUPS_ERROR in slog_text),
                            log, ssl_groups_error=SSL_GROUPS_ERROR in slog_text)
        else:
            log = publish_log(ctx, "logs/%s/startup.txt" % arm, [("initdb", initdb_text, 30)])
            receipt(ctx, arm + ".startup", "blocked", "initdb failed", log)

        # process runtime identity
        if started:
            rc, out, _ = capture(ctx, ["lsof", "-nP", "-p", str(pid), "-Fn"], timeout=60)
            mapped = [l[1:] for l in out.splitlines() if l.startswith("n/")]
            pr = lib_identity(mapped, a["libdir_real"], a["lib_sha256"])
            ident["process_runtime"] = pr
            probs += ["process: " + p for p in pr["problems"]]
        else:
            ident["process_runtime"] = "not run: server not started"
        log = publish_log(ctx, "logs/%s/identity.txt" % arm, [("identity", canon(sanitize_obj(ctx, ident)), None)])
        ctx.env_facts.setdefault("arm_identity", {})[arm] = ident
        receipt(ctx, arm + ".identity", "fail" if probs else "pass",
                "; ".join(probs) or "headers, linkage and runtime-loaded libraries match the %s arm" % arm,
                log, compiled_default_ssl_groups=ident.get("compiled_default_ssl_groups"))

        # handshakes
        for h in pol["handshake_matrix"][arm]:
            rid = "%s.hs.%s" % (arm, h["id"])
            if not started:
                receipt(ctx, rid, "not_run", "not run: server not started")
                continue
            lp = os.path.join(pdir, "hs-%s.log" % h["id"])
            rc, text, _ = s_client(ctx, port, h["offer"], True, lp)
            parsed = parse_client_output(text, rc, pol)
            status = judge(parsed, h["expect"])
            log = publish_log(ctx, "logs/%s/hs-%s.txt" % (arm, h["id"]), [("client output", read_text(lp), None)])
            receipt(ctx, rid, status, "offer=%s -> %s %s" % (h["offer"], parsed["classification"], parsed["group"]),
                    log, client_rc=rc, classification=parsed["classification"], group=parsed["group"],
                    offer=h["offer"], expect=h["expect"])
    finally:
        stop_server(ctx, arm, bindir, data, pid)


def stop_server(ctx, arm, bindir, data, pid):
    if pid is None:
        return
    pidf = os.path.join(data, "postmaster.pid")
    rec = {"what": "stop postmaster %s" % arm, "pid": pid}
    cur = None
    if os.path.isfile(pidf):
        try:
            cur = int(read_text(pidf).splitlines()[0])
        except (ValueError, IndexError):
            cur = None
    rc, cmd, _ = capture(ctx, ["ps", "-p", str(pid), "-o", "command="])
    rec["command_before_stop"] = cmd.strip()
    rec["pidfile_matches"] = cur == pid
    if cur == pid:
        run_cmd(ctx, [os.path.join(bindir, "pg_ctl"), "-D", data, "-w", "-t", "60", "stop", "-m", "fast"],
                os.path.join(ctx.priv, arm, "pg_ctl_stop.log"), timeout=120, step=arm + ".stop")
    end = time.time() + 15
    while True:
        rc, stat, _ = capture(ctx, ["ps", "-p", str(pid), "-o", "stat="])
        gone = not stat.strip() or stat.strip().startswith("Z")
        if gone or time.time() > end:
            break
        time.sleep(0.3)
    rec["stopped"] = gone
    ctx.processes.append(rec)


def stage_integrity(ctx):
    problems = []
    files, ident = gate_hashes()
    if ident != ctx.gate_identity:
        problems.append("gate or policy files changed during the run")
    if sha256_file(ctx.client) != ctx.client_info["sha256"]:
        problems.append("reference client binary changed")
    for arm in ARMS:
        a = ctx.arm[arm]
        for name, h in a["lib_sha256"].items():
            if sha256_file(os.path.realpath(os.path.join(a["prefix"], "lib", name))) != h:
                problems.append("%s %s changed" % (arm, name))
    after = protected_state(ctx)
    if after != ctx.protected_before:
        problems.append("protected upstream state changed")
    leftovers = [p for p in ctx.processes if "stopped" in p and not p["stopped"]]
    if leftovers:
        problems.append("owned processes still running: %s" % [p["pid"] for p in leftovers])
    ctx.env_facts["protected_upstream_after"] = after
    log = publish_log(ctx, "logs/integrity.txt", [("end-of-run identity", canon(sanitize_obj(ctx, {
        "gate_identity_start": ctx.gate_identity, "gate_identity_end": ident,
        "protected_before": ctx.protected_before, "protected_after": after,
        "owned_processes": ctx.processes, "problems": problems})), None)])
    receipt(ctx, "integrity", "fail" if problems else "pass",
            "; ".join(problems) or "gate, policy, client, libraries and protected tree unchanged", log)


def reference_from_raw(ref_id, raw):
    try:
        v = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None
    if not isinstance(v, dict) or v.get("case") != "baseline" or v.get("run_id") != ref_id:
        return None
    arm_results = {a: {} for a in ARMS}
    for c in v.get("checks", []):
        if not isinstance(c, dict) or not isinstance(c.get("id"), str):
            return None
        parts = c["id"].split(".")
        if len(parts) == 2 and parts[0] in ARMS and parts[1] in ("build", "regression", "startup"):
            arm_results[parts[0]][parts[1]] = c.get("result")
    return {"run_id": ref_id, "verdict_sha256": sha256_bytes(raw),
            "gate_identity": v.get("gate_identity"), "arm_results": arm_results}


def read_reference_raw(ref_id):
    """Raw verdict.json of a baseline run under EVIDENCE_ROOT, or None. Refuses non-baseline ids."""
    if not full(r"baseline-[0-9]{2}", ref_id):
        return None
    try:
        with open(os.path.join(EVIDENCE_ROOT, ref_id, "verdict.json"), "rb") as f:
            return f.read()
    except OSError:
        return None


def load_reference(ctx, ref_id):
    raw = read_reference_raw(ref_id)
    return None if raw is None else reference_from_raw(ref_id, raw)


def finalize(ctx):
    pol = ctx.policy
    for rid in mandatory_ids(pol):
        if rid not in ctx.receipts and rid != "controls":
            receipt(ctx, rid, "not_run", "not run: " + ctx.stop_reason)
    for c in pol["controls"]:
        if "control." + c["id"] not in ctx.receipts:
            receipt(ctx, "control." + c["id"], "not_run", "not run: " + ctx.stop_reason)
    obs = {"schema": "shaar.gate.observations/1", "run_id": ctx.run_id, "case": ctx.case,
           "gate_identity": ctx.gate_identity, "reference": ctx.reference, "receipts": ctx.receipts}
    if ctx.candidate is not None:
        obs["schema"] = "shaar.gate.observations/2"
        obs["input"] = ctx.candidate["info"]

    def read_log(rel):
        p = os.path.join(ctx.ev_dir, rel)
        try:
            with open(p, "rb") as f:
                return f.read()
        except OSError:
            return None
    ev = evaluate(obs, pol, read_log, fixture_hashes(ctx.gate_files, pol), read_reference_raw,
                  load_pinned_header(ctx.pg_git, pol) if ctx.candidate is not None else None)
    gate_files, _ = gate_hashes()
    verdict = build_verdict(ctx.run_id, ctx.case, ctx.gate_identity, ctx.gate_files, pol,
                            ctx.patch_info, ctx.reference, ev)
    env = sanitize_obj(ctx, dict(ctx.env_facts, schema="shaar.gate.environment/1", run_id=ctx.run_id,
                                 case=ctx.case, gate_files=ctx.gate_files, gate_identity=ctx.gate_identity,
                                 upstream=pol["upstream"], patch=ctx.patch_info, repo_head=ctx.repo_head,
                                 configure=dict((a, ctx.arm.get(a, {}).get("configure_argv")) for a in ARMS)
                                 if getattr(ctx, "arm", None) else None))
    acct = sanitize_obj(ctx, {"schema": "shaar.gate.accounting/1", "run_id": ctx.run_id,
                              "started_utc": ctx.started, "finished_utc": utc_now(),
                              "elapsed_seconds": round(time.time() - ctx.t0, 1), "steps": ctx.steps,
                              "model_calls": 0, "jobs": ctx.jobs, "owned_processes": ctx.processes,
                              "stop_reason": ctx.stop_reason or None})
    write_new(os.path.join(ctx.ev_dir, "observations.json"), canon(obs))
    write_new(os.path.join(ctx.ev_dir, "verdict.json"), canon(verdict))
    write_new(os.path.join(ctx.ev_dir, "environment.json"), canon(env))
    write_new(os.path.join(ctx.ev_dir, "accounting.json"), canon(acct))
    c = ev["counts"]
    print("\nGATE %s  run=%s case=%s" % (verdict["outcome"], ctx.run_id, ctx.case))
    print("reason: %s" % sanitize(ctx, ev["reason"]))
    print("mandatory=%d pass=%d fail=%d blocked=%d not_run=%d attempted=%d" % (
        c["mandatory"], c["pass"], c["fail"], c["blocked"], c["not_run"], c["attempted"]))
    print("gate_identity=%s elapsed_s=%s" % (ctx.gate_identity, acct["elapsed_seconds"]))
    return 0


def build_verdict(run_id, case, gate_identity, gate_files, pol, patch_info, reference, ev):
    claim = None
    if ev["outcome"] == "ACCEPT":
        claim = ("Hybrid post-quantum key exchange (X25519MLKEM768) verified for the tested "
                 "configurations on this machine; classical fallback and OpenSSL 3.0 classical "
                 "compatibility observed. Server authentication remains classical (RSA test certificate).")
    schema, patch = "shaar.gate.verdict/1", None
    if patch_info is not None and patch_info.get("kind") == "external":
        schema = "shaar.gate.verdict/2"
        patch = {"fixture": None, "sha256": patch_info["sha256"],
                 "input": {k: patch_info[k] for k in ("origin", "derived_from", "snapshot", "bytes")}}
    elif patch_info is not None:
        patch = {"fixture": patch_info["fixture"], "sha256": patch_info["sha256"]}
    return {"schema": schema, "run_id": run_id, "case": case,
            "outcome": ev["outcome"], "reason": ev["reason"], "checks": ev["checks"],
            "counts": ev["counts"], "gate_identity": gate_identity, "gate_files": gate_files,
            "policy_sha256": gate_files["gate/policy.json"],
            "upstream_commit": pol["upstream"]["commit"],
            "patch": patch,
            "reference_run": reference, "claim": claim,
            "decided_by": "gate/check.py evaluate() from receipts, logs and policy; no model involved"}


def cmd_run(args):
    pol = load_policy()
    err = check_run_args(args, pol)
    if err:
        sys.exit("refused before any work: " + err)
    dy = sorted(k for k in os.environ if k.startswith("DYLD_"))
    if dy:
        sys.exit("refusing to run with DYLD_* variables set: %s" % dy)
    ctx = Ctx()
    ctx.policy, ctx.case, ctx.run_id = pol, args.case, args.run_id
    ctx.home = os.path.realpath(os.path.expanduser("~"))
    ctx.user = os.path.basename(ctx.home)
    ctx.pg_git = os.path.realpath(args.pg_git)
    ctx.prefixes = {"newer": os.path.abspath(args.newer_prefix), "v30": os.path.abspath(args.old_prefix)}
    ctx.client = os.path.abspath(args.client)
    work_root = os.path.realpath(args.work_root)
    for p in [work_root, ctx.pg_git] + list(ctx.prefixes.values()):
        if not SAFE_PATH.match(p):
            sys.exit("path has unsupported characters: %s" % p)
    pgdata = os.path.realpath(args.protected_pgdata)
    repo_real = os.path.realpath(REPO)
    for protected in (ctx.pg_git, pgdata, repo_real):
        if work_root == protected or work_root.startswith(protected + os.sep) or \
                protected.startswith(work_root + os.sep):
            sys.exit("work root overlaps a protected or repository path")
    ctx.run_dir = os.path.join(work_root, args.run_id)
    ctx.ev_dir = os.path.join(EVIDENCE_ROOT, args.run_id)
    if os.path.lexists(ctx.run_dir) or os.path.lexists(ctx.ev_dir):
        sys.exit("refusing to reuse run id %s (work or evidence directory exists)" % args.run_id)
    ctx.gate_files, ctx.gate_identity = gate_hashes()
    ctx.reference = None
    if args.reference_run:
        ctx.reference = load_reference(ctx, args.reference_run)
        if ctx.reference is None:
            sys.exit("reference run %s not found or not a baseline verdict" % args.reference_run)
        if ctx.reference["gate_identity"] != ctx.gate_identity:
            sys.exit("reference run %s has gate identity %s; this gate is %s. A reference must be a "
                     "baseline under the same identity." % (args.reference_run, ctx.reference["gate_identity"],
                                                            ctx.gate_identity))
    ctx.candidate = None
    if pol["cases"][args.case].get("external_input"):
        try:
            ctx.candidate = prepare_candidate(args, pol, ctx.gate_files,
                                              [repo_real, work_root, ctx.pg_git, pgdata])
        except InputError as e:
            sys.exit("refused before any work: %s" % e)
        print("candidate input: %d bytes, SHA-256 %s, origin %s%s" % (
            ctx.candidate["info"]["bytes"], ctx.candidate["info"]["sha256"], args.origin,
            " (exact copy of fixture %s)" % args.derived_from if args.derived_from else ""))
    os.makedirs(work_root, mode=0o700, exist_ok=True)
    os.mkdir(ctx.run_dir, 0o700)
    for sub in ("tmp", "sock", "private-logs"):
        os.mkdir(os.path.join(ctx.run_dir, sub), 0o700)
    os.makedirs(os.path.join(ctx.ev_dir, "logs"))
    if ctx.candidate is not None:
        write_new(os.path.join(ctx.ev_dir, ctx.candidate["info"]["snapshot"]), ctx.candidate["bytes"], 0o444)
    ctx.tmp, ctx.sock = os.path.join(ctx.run_dir, "tmp"), os.path.join(ctx.run_dir, "sock")
    ctx.priv = os.path.join(ctx.run_dir, "private-logs")
    ctx.redactions = sorted({(ctx.run_dir, "$WORK/" + args.run_id), (work_root, "$WORK"),
                             (REPO, "$REPO"), (ctx.home, "$HOME")}, key=lambda x: -len(x[0]))
    ctx.receipts, ctx.steps, ctx.processes, ctx.env_facts = {}, [], [], {}
    ctx.arm, ctx.patch_info, ctx.patched = {}, None, None
    if ctx.candidate is not None:
        ctx.patch_info = dict(ctx.candidate["info"], kind="external")
    ctx.jobs = args.jobs or os.cpu_count() or 4
    ctx.t0, ctx.started, ctx.stop_reason = time.time(), utc_now(), ""
    rc, out, _ = capture(ctx, ["git", "-C", REPO, "rev-parse", "HEAD"])
    ctx.repo_head = out.strip()
    print("gate run %s case=%s identity=%s" % (ctx.run_id, ctx.case, ctx.gate_identity))
    try:
        if not stage_preflight(ctx):
            ctx.stop_reason = "preflight failed"
        else:
            stage_certs(ctx)
            if not stage_controls(ctx):
                ctx.stop_reason = "reference controls failed"
            elif not stage_patch(ctx):
                ctx.stop_reason = "patch rejected by policy"
            elif not stage_source(ctx):
                ctx.stop_reason = "source export failed"
            else:
                for arm in ARMS:
                    print("[%s arm]" % arm)
                    stage_arm(ctx, arm)
    except KeyboardInterrupt:
        ctx.stop_reason = "interrupted"
    except Exception as e:  # recorded, not hidden
        ctx.stop_reason = "harness error: %s: %s" % (type(e).__name__, e)
        print("harness error: %s" % sanitize(ctx, str(e)))
    if hasattr(ctx, "protected_before") and hasattr(ctx, "client_info") and len(ctx.arm) == 2:
        try:
            stage_integrity(ctx)
        except Exception as e:
            receipt(ctx, "integrity", "blocked", "integrity check error: %s" % e)
    return finalize(ctx)


# ---------------------------------------------------------------- evaluate / negative control

def load_run(run_id):
    pol = load_policy()
    if not full(pol["run_id_pattern"], run_id):
        sys.exit("invalid run id")
    d = os.path.join(EVIDENCE_ROOT, run_id)
    if os.path.islink(d) or not os.path.isfile(os.path.join(d, "observations.json")):
        sys.exit("no evidence for run %s" % run_id)
    with open(os.path.join(d, "observations.json"), "rb") as f:
        obs = json.loads(f.read().decode("utf-8"))
    with open(os.path.join(d, "verdict.json"), "rb") as f:
        verdict_raw = f.read()
    case = pol["cases"].get(obs.get("case"))
    if obs.get("run_id") != run_id or case is None or run_id.split("-")[0] != case["run_id_prefix"]:
        sys.exit("observations for %s name run %r case %r, which do not match the directory" % (
            run_id, obs.get("run_id"), obs.get("case")))

    def read_log(rel):
        if rel.startswith("/") or ".." in rel.split("/"):
            return None
        try:
            with open(os.path.join(d, rel), "rb") as f:
                return f.read()
        except OSError:
            return None
    return d, obs, verdict_raw, read_log


def candidate_pinfo(obs):
    """Verdict patch fields for an external input, taken from the observations (checked by evaluate)."""
    inp = obs.get("input")
    if not isinstance(inp, dict):
        return None
    return {"kind": "external", "sha256": inp.get("sha256"), "origin": inp.get("origin"),
            "derived_from": inp.get("derived_from"), "snapshot": inp.get("snapshot"), "bytes": inp.get("bytes")}


def cmd_evaluate(args):
    pol = load_policy()
    _d, obs, verdict_raw, read_log = load_run(args.run_id)
    old = json.loads(verdict_raw.decode("utf-8"))
    gate_files, ident = gate_hashes()
    external = pol["cases"][obs["case"]].get("external_input")
    header = load_pinned_header(getattr(args, "pg_git", None), pol) if external else None
    ev = evaluate(obs, pol, read_log, fixture_hashes(gate_files, pol), read_reference_raw, header)
    print("RECOMPUTATION from saved evidence (no build, no handshake, no network); not a new run.")
    if ident != old.get("gate_identity"):
        print("NOTE: current gate identity %s differs from the run's %s" % (ident, old.get("gate_identity")))
    if external and header is None:
        print("NOTE: no authenticated pinned header (pass --pg-git); the candidate snapshot cannot be re-applied")
    if external:
        pinfo = candidate_pinfo(obs)
    else:
        patch = old.get("patch")
        pinfo = None if patch is None else {"fixture": patch["fixture"], "sha256": patch["sha256"]}
    new = build_verdict(obs["run_id"], obs["case"], old.get("gate_identity"), old.get("gate_files"),
                        pol, pinfo, obs.get("reference"), ev)
    same = canon(new).encode("utf-8") == verdict_raw
    print("recomputed outcome: %s (%s)" % (ev["outcome"], ev["reason"]))
    print("verdict.json %s" % ("MATCHES recomputation" if same else "DIFFERS from recomputation"))
    return 0 if same else 1


def candidate_variants(obs, read_log, read_ref):
    """Synthetic in-memory tamperings of an external-input run's evidence."""
    out = []

    def copy():
        return json.loads(json.dumps(obs))

    snap = (obs.get("input") or {}).get("snapshot", "candidate.patch")

    def drop_snapshot(r):
        return None if r == snap else read_log(r)

    def edit_snapshot(r):
        data = read_log(r)
        return data + b" \n" if (r == snap and data is not None) else data
    out.append(("missing snapshot %s" % snap, obs, drop_snapshot, read_ref))
    out.append(("edited snapshot %s" % snap, obs, edit_snapshot, read_ref))
    for name, fn in (
            ("input sha256 edited", lambda o: o["input"].update(sha256="0" * 64)),
            ("input size edited", lambda o: o["input"].update(bytes=(o["input"].get("bytes") or 0) + 1)),
            ("origin claimed as model", lambda o: o["input"].update(origin="model")),
            ("origin switched to external", lambda o: o["input"].update(origin="external")),
            ("derived_from switched fixture", lambda o: o["input"].update(
                derived_from="hybrid-unconditional" if o["input"].get("derived_from") != "hybrid-unconditional"
                else "hybrid-versioned")),
            ("input block removed", lambda o: o.pop("input", None)),
            ("patch receipt claims a fixture", lambda o: o["receipts"]["patch"].update(fixture="hybrid-versioned")),
            ("patch receipt hash edited", lambda o: o["receipts"]["patch"].update(patch_sha256="f" * 64)),
            ("source per-arm hash edited", lambda o: o["receipts"]["source"].update(
                patched_file_sha256={"newer": "0" * 64, "v30": "0" * 64})),
            ("source per-arm hash removed", lambda o: o["receipts"]["source"].pop("patched_file_sha256", None)),
            ("reference removed", lambda o: o.update(reference=None)),
            ("reference identity edited", lambda o: o["reference"].update(gate_identity="0" * 64)
             if isinstance(o.get("reference"), dict) else None)):
        o = copy()
        try:
            fn(o)
        except (KeyError, TypeError, AttributeError):
            pass
        out.append((name, o, read_log, read_ref))

    def edited_ref(rid):
        raw = read_ref(rid)
        return raw + b" " if raw is not None else None
    out.append(("reference verdict bytes edited", obs, read_log, edited_ref))
    sub = copy()
    s = sha256_bytes(SUBSTITUTE_PATCH)
    if isinstance(sub.get("input"), dict):
        sub["input"].update(sha256=s, bytes=len(SUBSTITUTE_PATCH))
    if isinstance(sub.get("receipts", {}).get("patch"), dict):
        sub["receipts"]["patch"].update(patch_sha256=s, snapshot_sha256=s)
    out.append(("substituted valid patch, digests updated", sub,
                lambda r: SUBSTITUTE_PATCH if r == snap else read_log(r), read_ref))
    return out


def cmd_negative_control(args):
    pol = load_policy()
    d, obs, verdict_raw, read_log = load_run(args.run_id)
    before = tree_manifest(d)
    gate_files, _ident = gate_hashes()
    fx = fixture_hashes(gate_files, pol)
    external = pol["cases"][obs["case"]].get("external_input")
    header = load_pinned_header(getattr(args, "pg_git", None), pol) if external else None
    base = evaluate(obs, pol, read_log, fx, read_reference_raw, header)["outcome"]
    target = "newer.hs.mixed"
    print("SYNTHETIC in-memory copies of run %s; original files are not modified." % args.run_id)
    if external and header is None:
        print("NOTE: no authenticated pinned header (pass --pg-git); candidate base cannot be ACCEPT")
    print("base outcome: %s" % base)
    variants = []
    o1 = json.loads(json.dumps(obs))
    o1["receipts"].pop(target, None)
    variants.append(("missing receipt %s" % target, o1, read_log))
    o2 = json.loads(json.dumps(obs))
    if target in o2["receipts"]:
        o2["receipts"][target]["group"] = "X25519" if o2["receipts"][target].get("group") != "X25519" else "P-256"
    variants.append(("edited receipt %s (group field)" % target, o2, read_log))
    rel = (obs["receipts"].get(target) or {}).get("log")

    def tampered(r):
        data = read_log(r)
        return data + b"tampered\n" if (r == rel and data is not None) else data
    variants.append(("edited log for %s" % target, obs, tampered))
    variants = [(n, o, rl, read_reference_raw) for n, o, rl in variants]
    if pol["cases"][obs["case"]].get("external_input"):
        variants += candidate_variants(obs, read_log, read_reference_raw)
    ok = True
    for name, o, rl, rr in variants:
        out = evaluate(o, pol, rl, fx, rr, header)
        good = out["outcome"] != "ACCEPT"
        ok = ok and good
        print("  %-45s -> %-8s %s" % (name, out["outcome"], "OK (not ACCEPT)" if good else "FAILED CONTROL"))
    after = open(os.path.join(EVIDENCE_ROOT, args.run_id, "verdict.json"), "rb").read()
    unchanged = after == verdict_raw and tree_manifest(d) == before
    print("variants: %d" % len(variants))
    print("original evidence files unchanged: %s" % unchanged)
    if base != "ACCEPT":
        print("note: base outcome is not ACCEPT, so this control shows only that tampering cannot create ACCEPT")
    print("NEGATIVE CONTROL %s" % ("PASS" if ok and unchanged else "FAIL"))
    return 0 if ok and unchanged else 1


# ---------------------------------------------------------------- selftest

def synthetic_obs(pol):
    """Build a labeled synthetic all-pass observation set with in-memory logs."""
    logs = {}
    rec = {}

    def add(rid, status, text=None, **f):
        r = {"id": rid, "status": status, "detail": "synthetic", "log": None, "log_sha256": None}
        if text is not None:
            data = text.encode()
            r["log"], r["log_sha256"] = "logs/%s.txt" % rid, sha256_bytes(data)
            logs[r["log"]] = data
        r.update(f)
        rec[rid] = r

    def ok_text(group):
        line = {"X25519MLKEM768": "Negotiated TLS1.3 group: X25519MLKEM768",
                "X25519": "Peer Temp Key: X25519, 253 bits",
                "P-256": "Peer Temp Key: ECDH, prime256v1, 256 bits"}[group]
        return ("SYNTHETIC\n%s\nVerification: OK\nVerified peername: %s\nProtocol: TLSv1.3\n" %
                (line, pol["test_certificates"]["expected_peer_name"]))
    fail_text = "SYNTHETIC\nerror: ssl/tls alert handshake failure: SSL alert number 40\n"

    def hs(rid, expect):
        if expect["result"] == "ok":
            g = (expect.get("group_in") or [expect.get("group")])[0]
            add(rid, "pass", ok_text(g), client_rc=0, classification="ok", group=g)
        else:
            add(rid, "pass", fail_text, client_rc=1, classification="tls_failure", group=None)
    for g in ("preflight", "patch", "source", "integrity"):
        add(g, "pass", "synthetic")
    for c in pol["controls"]:
        hs("control." + c["id"], c["expect"])
    for arm in ARMS:
        for chk in ("identity", "build", "regression", "startup"):
            add("%s.%s" % (arm, chk), "pass", "synthetic")
        for h in pol["handshake_matrix"][arm]:
            hs("%s.hs.%s" % (arm, h["id"]), h["expect"])
    obs = {"schema": "synthetic", "run_id": "selftest", "case": "hybrid-versioned",
           "gate_identity": "g", "reference": None, "receipts": rec}
    return obs, logs


def synthetic_candidate(pol, header):
    """Labeled synthetic external-input run: scripted copy of the versioned fixture, with a
    synthetic baseline reference under the same (synthetic) identity. In-memory only. The
    patched-header hashes are the real result of applying the fixture to the pinned header."""
    obs, logs = synthetic_obs(pol)
    gate_files, _ = gate_hashes()
    fx = fixture_hashes(gate_files, pol)
    with open(os.path.join(REPO, pol["fixtures"]["hybrid-versioned"]["path"]), "rb") as f:
        snap = f.read()
    sha = sha256_bytes(snap)
    patched = sha256_bytes(validate_and_apply(snap, header, pol)[1].encode("utf-8"))
    ref_checks = [{"id": "%s.%s" % (a, c), "result": "PASS"} for a in ARMS for c in ("build", "regression", "startup")]
    ref_raw = canon({"case": "baseline", "run_id": "baseline-99", "gate_identity": "g",
                     "checks": ref_checks, "schema": "synthetic"}).encode()
    obs.update(case="candidate", run_id="candidate-90", schema="synthetic",
               reference=reference_from_raw("baseline-99", ref_raw),
               input={"snapshot": "candidate.patch", "sha256": sha, "bytes": len(snap),
                      "origin": "scripted", "derived_from": "hybrid-versioned"})
    obs["receipts"]["patch"].update(fixture=None, input_origin="scripted", derived_from="hybrid-versioned",
                                    patch_sha256=sha, snapshot_sha256=sha, snapshot="candidate.patch",
                                    patched_sha256=patched)
    obs["receipts"]["source"]["patched_file_sha256"] = {a: patched for a in ARMS}
    logs["candidate.patch"] = snap

    def read_ref(rid):
        return ref_raw if rid == "baseline-99" else None
    return obs, logs, fx, read_ref, ref_raw


def selftest_external(pol, t, header, pg_git):
    import contextlib
    import io
    global EVIDENCE_ROOT
    print("[external candidate input: arguments]")
    t("policy defines case candidate as external input", pol["cases"].get("candidate", {}).get("external_input") is True)
    t("original three cases unchanged", [pol["cases"][c].get("fixture") for c in
                                         ("baseline", "hybrid-unconditional", "hybrid-versioned")]
      == [None, "hybrid-unconditional", "hybrid-versioned"])
    for rid, ok in (("candidate-90", True), ("candidate-01", True), ("versioned-04", True),
                    ("candidate-90\n", False), ("candidate-9", False), ("candidate-100", False),
                    ("../candidate-90", False), ("candidate-90/..", False), ("Candidate-90", False)):
        t("run id %r %s" % (rid, "accepted" if ok else "refused"), full(pol["run_id_pattern"], rid) == ok)

    def ns(**kw):
        d = dict(case="candidate", run_id="candidate-90", patch_file="/x/in.patch", patch_sha256="a" * 64,
                 origin="scripted", derived_from="hybrid-versioned", reference_run="baseline-04")
        d.update(kw)
        return argparse.Namespace(**d)
    none4 = dict(patch_file=None, patch_sha256=None, origin=None, derived_from=None)
    t("args: scripted candidate-90 with digest and reference accepted", check_run_args(ns(), pol) is None)
    t("args: external candidate-01 accepted", check_run_args(ns(run_id="candidate-01", origin="external",
                                                                  derived_from=None), pol) is None)
    for name, kw in (
            ("candidate without --patch-file", dict(patch_file=None)),
            ("candidate without --patch-sha256", dict(patch_sha256=None)),
            ("uppercase digest", dict(patch_sha256="A" * 64)),
            ("short digest", dict(patch_sha256="a" * 63)),
            ("digest with newline", dict(patch_sha256="a" * 64 + "\n")),
            ("candidate without --origin", dict(origin=None)),
            ("origin 'model'", dict(origin="model")),
            ("origin 'fixture'", dict(origin="fixture")),
            ("scripted without --derived-from", dict(derived_from=None)),
            ("scripted derived from unknown fixture", dict(derived_from="hybrid-other")),
            ("external with --derived-from", dict(run_id="candidate-01", origin="external")),
            ("scripted on reserved candidate-01", dict(run_id="candidate-01")),
            ("external on scripted id candidate-90", dict(origin="external", derived_from=None)),
            ("candidate without --reference-run", dict(reference_run=None)),
            ("case candidate with run id versioned-90", dict(run_id="versioned-90")),
            ("case candidate with run id candidate-90 plus newline", dict(run_id="candidate-90\n")),
            ("baseline with --patch-file", dict(none4, case="baseline", run_id="baseline-04", reference_run=None,
                                                patch_file="/x")),
            ("versioned with --patch-sha256", dict(none4, case="hybrid-versioned", run_id="versioned-04",
                                                   patch_sha256="a" * 64)),
            ("unconditional with --origin", dict(none4, case="hybrid-unconditional", run_id="uncond-04",
                                                 origin="scripted")),
            ("versioned with --derived-from", dict(none4, case="hybrid-versioned", run_id="versioned-04",
                                                   derived_from="hybrid-versioned")),
            ("baseline with --reference-run", dict(none4, case="baseline", run_id="baseline-04")),
            ("unknown case", dict(case="model")),
    ):
        t("args refused: %s" % name, check_run_args(ns(**kw), pol) is not None)
    t("args: versioned-04 with reference, no input flags accepted",
      check_run_args(ns(**dict(none4, case="hybrid-versioned", run_id="versioned-04")), pol) is None)

    print("[external candidate input: read once, snapshot]")
    limit = pol["patch_policy"]["max_patch_bytes"]
    gate_files, _ = gate_hashes()
    fx = fixture_hashes(gate_files, pol)
    with open(os.path.join(REPO, pol["fixtures"]["hybrid-versioned"]["path"]), "rb") as f:
        vbytes = f.read()
    with tempfile.TemporaryDirectory() as td:
        td = os.path.realpath(td)

        def mk(name, data):
            p = os.path.join(td, name)
            with open(p, "wb") as f:
                f.write(data)
            return p

        def refused(fn):
            try:
                fn()
                return False
            except InputError:
                return True
        reg = mk("in.patch", vbytes)
        t("regular file read once, exact bytes", read_input_once(reg, limit) == vbytes)
        os.symlink(reg, os.path.join(td, "link.patch"))
        t("symlink refused", refused(lambda: read_input_once(os.path.join(td, "link.patch"), limit)))
        os.mkdir(os.path.join(td, "dir.patch"))
        t("directory refused", refused(lambda: read_input_once(os.path.join(td, "dir.patch"), limit)))
        if hasattr(os, "mkfifo"):
            os.mkfifo(os.path.join(td, "fifo.patch"))
            t("FIFO refused without blocking", refused(lambda: read_input_once(os.path.join(td, "fifo.patch"), limit)))
        t("missing file refused", refused(lambda: read_input_once(os.path.join(td, "nope.patch"), limit)))
        t("empty file refused", refused(lambda: read_input_once(mk("empty.patch", b""), limit)))
        t("file of limit + 1 bytes refused", refused(lambda: read_input_once(mk("big.patch", b"x" * (limit + 1)), limit)))
        t("file of exactly the limit read", len(read_input_once(mk("lim.patch", b"x" * limit), limit)) == limit)

        protected = [os.path.join(td, "repo"), os.path.join(td, "work")]
        for p in protected:
            os.mkdir(p)
        good = ns(patch_file=reg, patch_sha256=sha256_bytes(vbytes))
        cand = prepare_candidate(good, pol, gate_files, protected)
        t("prepare: digest and scripted-copy check pass for exact fixture copy",
          cand["bytes"] == vbytes and cand["info"]["sha256"] == fx["hybrid-versioned"])
        t("prepare: no input path recorded", reg not in canon(cand["info"]) and td not in canon(cand["info"]))
        with open(reg, "ab") as f:
            f.write(b"+#define DEFAULT_SSL_GROUPS \"X25519\"\n")
        t("input changed after read: frozen bytes unchanged", cand["bytes"] == vbytes
          and sha256_bytes(cand["bytes"]) == cand["info"]["sha256"])
        t("prepare: changed input now refused (digest mismatch)", refused(lambda: prepare_candidate(good, pol, gate_files, protected)))
        other = mk("other.patch", vbytes.replace(b"0x30500000L", b"0x30600000L"))
        t("prepare: scripted input that differs from its fixture refused",
          refused(lambda: prepare_candidate(ns(patch_file=other, patch_sha256=sha256_file(other)), pol, gate_files, protected)))
        t("prepare: external input with matching digest accepted",
          prepare_candidate(ns(patch_file=other, patch_sha256=sha256_file(other), run_id="candidate-01",
                               origin="external", derived_from=None), pol, gate_files, protected)["info"]["origin"] == "external")
        inner = os.path.join(protected[0], "in.patch")
        with open(inner, "wb") as f:
            f.write(vbytes)
        t("prepare: input inside a protected or repository path refused",
          refused(lambda: prepare_candidate(ns(patch_file=inner, patch_sha256=sha256_bytes(vbytes)), pol, gate_files, protected)))
        snap = os.path.join(td, "candidate.patch")
        write_new(snap, vbytes, 0o444)
        try:
            write_new(snap, b"other", 0o444)
            t("snapshot never overwritten", False)
        except OSError:
            t("snapshot never overwritten", True)
        t("snapshot written read-only", stat.S_IMODE(os.stat(snap).st_mode) == 0o444)

    print("[external candidate input: binding in evaluate()]")
    if header is None:
        t("binding tests need the authenticated pinned header (--pg-git)", False)
        return
    obs, logs, fx, read_ref, ref_raw = synthetic_candidate(pol, header)
    rl = logs.get
    t("synthetic scripted candidate, consistent evidence -> ACCEPT",
      evaluate(obs, pol, rl, fx, read_ref, header)["outcome"] == "ACCEPT")
    t("same evidence without fixture hashes -> BLOCKED",
      evaluate(obs, pol, rl, None, read_ref, header)["outcome"] == "BLOCKED")
    t("same evidence without reference reader -> BLOCKED",
      evaluate(obs, pol, rl, fx, None, header)["outcome"] == "BLOCKED")
    t("same evidence without the pinned header -> BLOCKED",
      evaluate(obs, pol, rl, fx, read_ref, None)["outcome"] == "BLOCKED")
    t("same evidence with an altered pinned header -> BLOCKED",
      evaluate(obs, pol, rl, fx, read_ref, header.replace("prime256v1", "prime256v2", 1))["outcome"] == "BLOCKED")
    for name, o, lg, rr in candidate_variants(obs, rl, read_ref):
        t("tampered: %s -> BLOCKED" % name, evaluate(o, pol, lg, fx, rr, header)["outcome"] == "BLOCKED")

    def cmut(fn, lg=None, rr=read_ref, base=None):
        o = json.loads(json.dumps(base or obs))
        fn(o)
        return evaluate(o, pol, lg or rl, fx, rr, header)

    def external(o):
        o.update(run_id="candidate-01")
        o["input"].update(origin="external", derived_from=None)
        o["receipts"]["patch"].update(input_origin="external", derived_from=None)
    t("origin external on candidate-90 without derived_from -> BLOCKED",
      cmut(lambda o: o["input"].update(origin="external", derived_from=None))["outcome"] == "BLOCKED")
    t("external origin on candidate-01, no derived_from -> ACCEPT", cmut(external)["outcome"] == "ACCEPT")
    t("input block on a fixture case -> BLOCKED", cmut(lambda o: o.update(case="hybrid-versioned"))["outcome"] == "BLOCKED")
    t("snapshot that no longer parses while receipt PASS -> BLOCKED", cmut(
        lambda o: (o["input"].update(sha256=sha256_bytes(b"junk\n"), bytes=5),
                   o["receipts"]["patch"].update(patch_sha256=sha256_bytes(b"junk\n"),
                                                 snapshot_sha256=sha256_bytes(b"junk\n"))),
        lambda r: b"junk\n" if r == "candidate.patch" else logs.get(r))["outcome"] == "BLOCKED")

    print("[external candidate input: snapshot re-applied to the pinned header]")
    sub, ssha = SUBSTITUTE_PATCH, sha256_bytes(SUBSTITUTE_PATCH)
    sub_result = sha256_bytes(validate_and_apply(sub, header, pol)[1].encode("utf-8"))
    t("substitute patch is policy-valid and yields a different header",
      sub_result != obs["receipts"]["patch"]["patched_sha256"])
    ext = json.loads(json.dumps(obs))
    external(ext)
    sub_log = lambda r: sub if r == "candidate.patch" else logs.get(r)  # noqa: E731

    def substitute(o):
        o["input"].update(sha256=ssha, bytes=len(sub))
        o["receipts"]["patch"].update(patch_sha256=ssha, snapshot_sha256=ssha)
    out = cmut(substitute, sub_log, base=ext)
    t("QC case: snapshot replaced by a valid 'none' patch, input and receipt digests updated, "
      "compiled-header evidence unchanged -> BLOCKED",
      out["outcome"] == "BLOCKED" and "differs from the patch receipt" in out["checks"][2]["note"])
    print("      patch check note: %s" % out["checks"][2]["note"][:150])
    out = cmut(lambda o: (substitute(o), o["receipts"]["patch"].update(patched_sha256=sub_result)), sub_log, base=ext)
    t("same, receipt result also updated, exported headers unchanged -> BLOCKED",
      out["outcome"] == "BLOCKED" and "exported header differs" in out["checks"][2]["note"])
    out = cmut(lambda o: (substitute(o), o["receipts"]["patch"].update(patched_sha256=sub_result),
                          o["receipts"]["source"].update(patched_file_sha256={a: sub_result for a in ARMS})),
               sub_log, base=ext)
    t("fully consistent substituted evidence -> binding holds (synthetic observations ACCEPT)",
      out["outcome"] == "ACCEPT")
    out = cmut(lambda o: o["receipts"]["source"].update(patched_file_sha256={"newer": obs["receipts"]["patch"]["patched_sha256"],
                                                                             "v30": sub_result}), base=ext)
    t("one arm's exported header differs from the re-applied result -> BLOCKED", out["outcome"] == "BLOCKED")
    out = cmut(lambda o: (o["receipts"]["patch"].update(patched_sha256=sub_result),
                          o["receipts"]["source"].update(patched_file_sha256={a: sub_result for a in ARMS})), base=ext)
    t("receipt and exports agree with each other but not with the snapshot -> BLOCKED", out["outcome"] == "BLOCKED")

    bad = SUBSTITUTE_PATCH.replace(b'"none"\n #else', b'"X448"\n #else')
    bsha = sha256_bytes(bad)
    bad_log = lambda r: bad if r == "candidate.patch" else logs.get(r)  # noqa: E731

    def policy_reject(o, snap_sha=bsha, n=len(bad)):
        o["input"].update(sha256=snap_sha, bytes=n)
        o["receipts"]["patch"].update(status="fail", patch_sha256=snap_sha, snapshot_sha256=snap_sha)
        o["receipts"]["patch"].pop("patched_sha256")
        for k in mandatory_ids(pol):
            if k not in ("preflight", "controls", "patch", "integrity"):
                o["receipts"][k].update(status="not_run", log=None, log_sha256=None)
    t("candidate fails patch policy, re-applied snapshot also fails -> REJECT",
      cmut(policy_reject, bad_log, base=ext)["outcome"] == "REJECT")
    t("candidate fails patch policy, snapshot missing -> BLOCKED",
      cmut(policy_reject, lambda r: None if r == "candidate.patch" else logs.get(r), base=ext)["outcome"] == "BLOCKED")
    t("receipt says FAIL but the re-applied snapshot passes the policy -> BLOCKED",
      cmut(lambda o: policy_reject(o, obs["input"]["sha256"], obs["input"]["bytes"]), base=ext)["outcome"] == "BLOCKED")

    def build_fail(o):
        o["receipts"]["v30.build"]["status"] = "fail"
    t("candidate build fail, same-identity reference passed build -> REJECT", cmut(build_fail)["outcome"] == "REJECT")
    t("candidate build fail, reference identity differs -> BLOCKED", cmut(
        lambda o: (build_fail(o), o["reference"].update(gate_identity="other")))["outcome"] == "BLOCKED")
    vobs, vlogs = synthetic_obs(pol)
    vobs["reference"] = reference_from_raw("baseline-99", ref_raw)
    vobs["receipts"]["v30.build"]["status"] = "fail"
    t("fixture build fail, reference verdict intact -> REJECT",
      evaluate(vobs, pol, vlogs.get, fx, read_ref)["outcome"] == "REJECT")
    t("fixture build fail, reference verdict bytes changed -> BLOCKED",
      evaluate(vobs, pol, vlogs.get, fx, lambda rid: ref_raw + b" ")["outcome"] == "BLOCKED")
    vobs["receipts"]["v30.build"]["status"] = "pass"
    vobs["receipts"]["source"]["patched_file_sha256"] = {"newer": "0" * 64, "v30": "0" * 64}
    vobs["receipts"]["patch"]["patched_sha256"] = "1" * 64
    t("fixture source per-arm hash differs from validated result -> BLOCKED",
      evaluate(vobs, pol, vlogs.get, fx, read_ref)["outcome"] == "BLOCKED")
    vobs["receipts"]["source"].pop("patched_file_sha256")
    t("fixture receipt without per-arm hashes (older format) still evaluates -> ACCEPT",
      evaluate(vobs, pol, vlogs.get, fx, read_ref)["outcome"] == "ACCEPT")
    t("reference reader refuses non-baseline and traversal ids",
      read_reference_raw("../baseline-03") is None and read_reference_raw("versioned-03") is None
      and read_reference_raw("baseline-03\n") is None)
    ev = evaluate(obs, pol, rl, fx, read_ref)
    v = build_verdict("candidate-90", "candidate", "g", gate_files, pol, candidate_pinfo(obs), obs["reference"], ev)
    t("candidate verdict: schema /2, no fixture claim, input origin recorded",
      v["schema"] == "shaar.gate.verdict/2" and v["patch"]["fixture"] is None
      and v["patch"]["input"] == {"origin": "scripted", "derived_from": "hybrid-versioned",
                                  "snapshot": "candidate.patch", "bytes": obs["input"]["bytes"]})
    vf = build_verdict("versioned-90", "hybrid-versioned", "g", gate_files, pol,
                       {"fixture": "hybrid-versioned", "sha256": "s"}, None, ev)
    t("fixture verdict shape unchanged (schema /1, fixture and sha256 only)",
      vf["schema"] == "shaar.gate.verdict/1" and vf["patch"] == {"fixture": "hybrid-versioned", "sha256": "s"})

    print("[external candidate input: evaluate and negative-control on a temporary evidence tree]")
    saved_root = EVIDENCE_ROOT
    with tempfile.TemporaryDirectory() as td:
        try:
            EVIDENCE_ROOT = os.path.join(os.path.realpath(td), "gate-runs")
            run = os.path.join(EVIDENCE_ROOT, "candidate-90")
            os.makedirs(os.path.join(EVIDENCE_ROOT, "baseline-99"))
            write_new(os.path.join(EVIDENCE_ROOT, "baseline-99", "verdict.json"), ref_raw)
            for rel, data in logs.items():
                os.makedirs(os.path.dirname(os.path.join(run, rel)), exist_ok=True)
                write_new(os.path.join(run, rel), data)
            gf, gi = gate_hashes()
            sobs = json.loads(json.dumps(obs))
            sobs["gate_identity"] = gi
            ref = json.loads(ref_raw.decode())
            ref["gate_identity"] = gi
            ref_raw2 = canon(ref).encode()
            os.chmod(os.path.join(EVIDENCE_ROOT, "baseline-99", "verdict.json"), 0o644)
            with open(os.path.join(EVIDENCE_ROOT, "baseline-99", "verdict.json"), "wb") as f:
                f.write(ref_raw2)
            sobs["reference"] = reference_from_raw("baseline-99", ref_raw2)
            ev = evaluate(sobs, pol, lambda r: logs.get(r), fx, read_reference_raw, header)
            vraw = canon(build_verdict("candidate-90", "candidate", gi, gf, pol, candidate_pinfo(sobs),
                                       sobs["reference"], ev)).encode()
            write_new(os.path.join(run, "observations.json"), canon(sobs))
            write_new(os.path.join(run, "verdict.json"), vraw)
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc_e = cmd_evaluate(argparse.Namespace(run_id="candidate-90", pg_git=pg_git))
                rc_n = cmd_negative_control(argparse.Namespace(run_id="candidate-90", pg_git=pg_git))
                rc_e0 = cmd_evaluate(argparse.Namespace(run_id="candidate-90", pg_git=None))
            text = buf.getvalue()
            t("temporary run outcome ACCEPT before controls", ev["outcome"] == "ACCEPT")
            t("evaluate on saved candidate evidence MATCHES", rc_e == 0 and "MATCHES recomputation" in text)
            t("evaluate of a candidate ACCEPT without --pg-git -> DIFFERS (fails closed)", rc_e0 == 1)
            t("negative-control on candidate run: every variant not ACCEPT, files unchanged",
              rc_n == 0 and "NEGATIVE CONTROL PASS" in text and "FAILED CONTROL" not in text)
            os.chmod(os.path.join(run, "verdict.json"), 0o644)
            with open(os.path.join(run, "verdict.json"), "wb") as f:
                f.write(vraw.replace(b'"origin": "scripted"', b'"origin": "external"'))
            with contextlib.redirect_stdout(io.StringIO()):
                rc_e2 = cmd_evaluate(argparse.Namespace(run_id="candidate-90", pg_git=pg_git))
            t("evaluate with an edited verdict origin -> DIFFERS", rc_e2 == 1)
            os.rename(run, os.path.join(EVIDENCE_ROOT, "candidate-91"))
            try:
                with contextlib.redirect_stdout(io.StringIO()):
                    load_run("candidate-91")
                t("evidence whose run id differs from its directory refused", False)
            except SystemExit:
                t("evidence whose run id differs from its directory refused", True)
        finally:
            EVIDENCE_ROOT = saved_root


def cmd_selftest(args):
    pol = load_policy()
    results = []

    def t(name, cond):
        results.append((name, bool(cond)))
        print("  %-62s %s" % (name, "PASS" if cond else "FAIL"))

    print("[policy]")
    t("run id pattern accepts baseline-01", full(pol["run_id_pattern"], "baseline-01"))
    t("run id pattern rejects ../x", not full(pol["run_id_pattern"], "../x"))
    t("no absolute machine paths in policy", ("/" + "Users/") not in open(POLICY_PATH).read()
      and "/usr/local" not in open(POLICY_PATH).read())

    print("[patch policy against the pinned header]")
    original = None
    if args.pg_git:
        p = subprocess.run(["git", "-C", args.pg_git, "show", "%s:src/include/libpq/libpq.h" %
                            pol["upstream"]["commit"]], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           env={"PATH": CHILD_PATH, "GIT_OPTIONAL_LOCKS": "0",
                                "HOME": os.path.expanduser("~")})
        if p.returncode == 0:
            original = p.stdout.decode("utf-8")
    t("pinned libpq.h readable and hash matches policy", original is not None and sha256_bytes(
        original.encode()) == pol["patch_policy"]["allowed_files"]["src/include/libpq/libpq.h"]["sha256"])
    if original is not None:
        fx = {}
        for name, meta in pol["fixtures"].items():
            raw = open(os.path.join(REPO, meta["path"]), "rb").read()
            fx[name] = raw
            try:
                _p, patched, diff = validate_and_apply(raw, original, pol)
                t("fixture %s validates and applies" % name, True)
                print("\n".join("      " + d for d in diff))
            except PatchError as e:
                t("fixture %s validates and applies (%s)" % (name, e), False)
        good = fx["hybrid-versioned"].decode()
        neg = [
            ("traversal path", good.replace("a/src/include", "a/../src/include").replace("b/src/include", "b/../src/include")),
            ("absolute path", good.replace("--- a/src/include/libpq/libpq.h", "--- a//etc/passwd").replace("+++ b/src/include/libpq/libpq.h", "+++ b//etc/passwd")),
            ("file not allowlisted", good.replace("src/include/libpq/libpq.h", "src/test/ssl/t/001_ssltests.pl")),
            ("binary patch marker", good + "GIT binary patch\n"),
            ("symlink mode header", "diff --git a/src/include/libpq/libpq.h b/src/include/libpq/libpq.h\nnew mode 120000\n" + good),
            ("index line with symlink mode", "diff --git a/src/include/libpq/libpq.h b/src/include/libpq/libpq.h\nindex d15073a..1234567 120000\n" + good),
            ("new file from /dev/null", good.replace("--- a/src/include/libpq/libpq.h", "--- /dev/null")),
            ("second file section", good + "--- a/src/include/libpq/libpq.h\n+++ b/src/include/libpq/libpq.h\n"),
            ("removes line outside region", good.replace("@@ -135,7 +135,12 @@\n #endif\n", "@@ -135,7 +135,11 @@\n-#endif\n")),
            ("added line not allowed", good.replace("+#include <openssl/opensslv.h>", "+#include <stdlib.h>")),
            ("group name not allowed", good.replace('"X25519MLKEM768:X25519:prime256v1"', '"X448:X25519"')),
            ("context mismatch", good.replace(" #define DEFAULT_SSL_GROUPS \"none\"", " #define DEFAULT_SSL_GROUPS \"nope\"")),
            ("hunk count mismatch", good.replace("@@ -135,7 +135,12 @@", "@@ -135,7 +135,13 @@")),
            ("CRLF line endings", good.replace("\n", "\r\n")),
            ("no newline marker", good + "\\ No newline at end of file\n"),
            ("empty patch", ""),
        ]
        for name, text in neg:
            try:
                validate_and_apply(text.encode(), original, pol)
                t("rejects: %s" % name, False)
            except PatchError as e:
                t("rejects: %s (%s)" % (name, str(e)[:40]), True)
        try:
            validate_and_apply(good.encode(), original.replace("prime256v1", "prime256v2", 1), pol)
            t("rejects: target file hash differs", False)
        except PatchError:
            t("rejects: target file hash differs", True)

    print("[client output parser; vectors copied from discovery output]")
    pn = pol["test_certificates"]["expected_peer_name"]
    v_h = ("CONNECTED(00000003)\nNegotiated TLS1.3 group: X25519MLKEM768\nVerification: OK\n"
           "Verified peername: %s\nProtocol: TLSv1.3\n" % pn)
    v_x = ("CONNECTION ESTABLISHED\nProtocol version: TLSv1.3\nVerification: OK\nVerified peername: %s\n"
           "Peer Temp Key: X25519, 253 bits\nDONE\n" % pn)
    v_p = v_x.replace("Peer Temp Key: X25519, 253 bits", "Peer Temp Key: ECDH, prime256v1, 256 bits")
    v_f = ("Connecting to 127.0.0.1\nC027EF4AF87F0000:error:0A000410:SSL routines:ssl3_read_bytes:ssl/tls "
           "alert handshake failure:ssl/record/rec_layer_s3.c:918:SSL alert number 40\n")
    t("hybrid line -> ok X25519MLKEM768", parse_client_output(v_h, 0, pol)["group"] == "X25519MLKEM768")
    t("X25519 temp key -> ok X25519", parse_client_output(v_x, 0, pol)["group"] == "X25519")
    t("prime256v1 temp key -> ok P-256", parse_client_output(v_p, 0, pol)["group"] == "P-256")
    t("alert 40, rc 1 -> tls_failure", parse_client_output(v_f, 1, pol)["classification"] == "tls_failure")
    v_fn = ("Connecting to 127.0.0.1\nC027EF4AF87F0000:error:0A000410:SSL routines:ssl3_read_bytes:ssl/tls "
            "alert handshake failure:ssl/record/rec_layer_s3.c:918:SSL alert number 40\nCONNECTED(00000003)\n"
            "---\nno peer certificate available\n---\nNo client certificate CA names sent\n"
            "Negotiated TLS1.3 group: <NULL>\n---\nVerification: OK\n---\nNew, (NONE), Cipher is (NONE)\n"
            "Protocol: TLSv1.3\nVerify return code: 0 (ok)\n")
    t("full-mode failure with '<NULL>' group -> tls_failure", parse_client_output(v_fn, 1, pol)["classification"] == "tls_failure")
    t("'<NULL>' group line beside a real group -> client_error",
      parse_client_output(v_x + "Negotiated TLS1.3 group: <NULL>\n", 0, pol)["classification"] == "client_error")
    t("success text with rc 1 -> client_error", parse_client_output(v_h, 1, pol)["classification"] == "client_error")
    t("two group lines -> client_error", parse_client_output(v_h + "Peer Temp Key: X25519, 253 bits\n", 0, pol)["classification"] == "client_error")
    t("wrong peer name -> client_error", parse_client_output(v_h.replace(pn, "other.test"), 0, pol)["classification"] == "client_error")
    t("no group line -> client_error", parse_client_output("Verification: OK\nProtocol: TLSv1.3\n", 0, pol)["classification"] == "client_error")
    t("timeout (rc None) -> client_error", parse_client_output("", None, pol)["classification"] == "client_error")

    print("[verdict logic on labeled synthetic observations]")
    obs, logs = synthetic_obs(pol)
    rl = logs.get
    t("all synthetic receipts pass -> ACCEPT", evaluate(obs, pol, rl)["outcome"] == "ACCEPT")

    def mut(fn, lg=None):
        o = json.loads(json.dumps(obs))
        fn(o)
        return evaluate(o, pol, lg or rl)["outcome"]
    t("missing handshake receipt -> BLOCKED", mut(lambda o: o["receipts"].pop("newer.hs.mixed")) == "BLOCKED")
    t("receipt group edited -> BLOCKED", mut(lambda o: o["receipts"]["newer.hs.mixed"].update(group="X25519")) == "BLOCKED")
    t("log edited -> BLOCKED", mut(lambda o: None, lambda r: (logs.get(r) or b"") + (b"x" if r == "logs/newer.hs.mixed.txt" else b"")) == "BLOCKED")
    xt = ("SYNTHETIC\nPeer Temp Key: X25519, 253 bits\nVerification: OK\nVerified peername: %s\nProtocol: TLSv1.3\n" % pn).encode()

    def wrong_group(o):
        o["receipts"]["newer.hs.mixed"].update(status="fail", group="X25519", log_sha256=sha256_bytes(xt))
    t("hybrid expected, X25519 observed -> REJECT", mut(wrong_group, lambda r: xt if r == "logs/newer.hs.mixed.txt" else logs.get(r)) == "REJECT")
    t("control blocked -> BLOCKED", mut(lambda o: o["receipts"]["control.c1"].update(status="blocked")) == "BLOCKED")
    t("preflight fail -> BLOCKED", mut(lambda o: o["receipts"]["preflight"].update(status="fail")) == "BLOCKED")
    t("patch fail -> REJECT", mut(lambda o: o["receipts"]["patch"].update(status="fail")) == "REJECT")
    t("build fail, no reference -> BLOCKED", mut(lambda o: o["receipts"]["v30.build"].update(status="fail")) == "BLOCKED")

    def ref_build(o):
        o["receipts"]["v30.build"]["status"] = "fail"
        o["reference"] = {"gate_identity": "g", "arm_results": {"v30": {"build": "PASS"}}}
    t("build fail, matching reference pass -> REJECT", mut(ref_build) == "REJECT")

    def ref_other(o):
        ref_build(o)
        o["reference"]["gate_identity"] = "other"
    t("build fail, reference with other identity -> BLOCKED", mut(ref_other) == "BLOCKED")
    sl = b"FATAL:  could not set group names specified in ssl_groups: x\n"

    def startup_marker(o):
        o["receipts"]["v30.startup"].update(status="fail", log_sha256=sha256_bytes(sl))
        for h in pol["handshake_matrix"]["v30"]:
            o["receipts"]["v30.hs." + h["id"]].update(status="not_run", log=None, log_sha256=None)
    t("startup fail with ssl_groups error -> REJECT", mut(startup_marker, lambda r: sl if r == "logs/v30.startup.txt" else logs.get(r)) == "REJECT")

    def startup_plain(o):
        startup_marker(o)
    t("startup fail without marker or reference -> BLOCKED", mut(startup_plain, lambda r: b"other\n" if r == "logs/v30.startup.txt" else logs.get(r)) == "BLOCKED")

    def ident_block(o):
        wrong_group(o)
        o["receipts"]["newer.identity"]["status"] = "fail"
    t("FAIL in arm with blocked identity -> BLOCKED", mut(ident_block, lambda r: xt if r == "logs/newer.hs.mixed.txt" else logs.get(r)) == "BLOCKED")
    t("not_run without a FAIL -> BLOCKED", mut(lambda o: o["receipts"]["v30.regression"].update(status="not_run")) == "BLOCKED")

    selftest_external(pol, t, load_pinned_header(args.pg_git, pol), args.pg_git)

    print("[child environment]")
    os.environ["MODEL_API_KEY"] = "selftest-placeholder-not-a-key"
    c = Ctx()
    c.home, c.tmp = "/h", "/t"
    keys = sorted(child_env(c).keys())
    del os.environ["MODEL_API_KEY"]
    t("child env is exactly the allowlist", keys == ["GIT_OPTIONAL_LOCKS", "HOME", "LANG", "LC_ALL", "PATH", "TMPDIR"])

    failed = [n for n, ok in results if not ok]
    print("\nSELFTEST %s: %d passed, %d failed" % ("PASS" if not failed else "FAIL",
                                                len(results) - len(failed), len(failed)))
    return 0 if not failed else 1


def cmd_identity(_args):
    files, ident = gate_hashes()
    for p in GATE_FILES:
        print("%s  %s" % (files[p], p))
    print("gate_identity=%s" % ident)
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd")
    s = sub.add_parser("selftest")
    s.add_argument("--pg-git", help="pinned PostgreSQL git checkout, read-only")
    r = sub.add_parser("run")
    r.add_argument("--case", required=True)
    r.add_argument("--run-id", required=True)
    r.add_argument("--pg-git", required=True)
    r.add_argument("--protected-pgdata", required=True, help="never touched; only checked against the work root")
    r.add_argument("--newer-prefix", required=True)
    r.add_argument("--old-prefix", required=True)
    r.add_argument("--client", required=True)
    r.add_argument("--work-root", required=True)
    r.add_argument("--reference-run", help="baseline run under the same gate identity")
    r.add_argument("--jobs", type=int)
    r.add_argument("--patch-file", help="candidate only: external patch file outside the repository")
    r.add_argument("--patch-sha256", help="candidate only: expected SHA-256 of the patch file (lowercase hex)")
    r.add_argument("--origin", help="candidate only: scripted or external (see policy external_input.origins)")
    r.add_argument("--derived-from", help="candidate, origin scripted only: fixture the input is an exact copy of")
    e = sub.add_parser("evaluate")
    e.add_argument("run_id")
    e.add_argument("--pg-git", help="pinned PostgreSQL checkout, read-only; required to re-apply a candidate snapshot")
    n = sub.add_parser("negative-control")
    n.add_argument("run_id")
    n.add_argument("--pg-git", help="pinned PostgreSQL checkout, read-only; required to re-apply a candidate snapshot")
    sub.add_parser("identity")
    args = ap.parse_args(argv)
    if args.cmd in ("evaluate", "negative-control") and not full(load_policy()["run_id_pattern"], args.run_id):
        sys.exit("invalid run id")
    fn = {"selftest": cmd_selftest, "run": cmd_run, "evaluate": cmd_evaluate,
          "negative-control": cmd_negative_control, "identity": cmd_identity}.get(args.cmd)
    if fn is None:
        ap.print_help()
        return 2
    return fn(args)


if __name__ == "__main__":
    sys.exit(main())
