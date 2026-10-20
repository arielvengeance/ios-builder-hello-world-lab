#!/usr/bin/env bash
# Fail-closed GitHub Secret Protection Gate.
#
# Scans the EXACT working-tree payload that `builder ios build` would push
# (the same git add -A / write-tree snapshot algorithm as ios-builder v0.11.0),
# plus git history, workflow YAML and ignored files. Any positive finding,
# incomplete scan or uncertain result exits non-zero.
#
# Usage:
#   scripts/secret-protection-gate.sh [--repo DIR] [--out DIR] [--gitleaks PATH]
#
# Evidence is written as JSON with REDACTED findings only. Raw scanner reports
# are parsed and deleted in the same run; secret values are never printed.

set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$(cd "$REPO/.." && pwd)/evidence"
GITLEAKS="${GITLEAKS_BIN:-/home/msyah/ios-builder-lab/tools/gitleaks-8.30.1/gitleaks}"

while [ $# -gt 0 ]; do
  case "$1" in
    --repo) REPO="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    --gitleaks) GITLEAKS="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

REPO="$(cd "$REPO" && pwd)"
mkdir -p "$OUT"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

fail() { echo "SECRET GATE: FAIL — $*" >&2; echo "{\"verdict\":\"FAIL\",\"reason\":\"$*\"}" > "$OUT/secret-gate.json"; exit 1; }

[ -x "$GITLEAKS" ] || fail "scanner not executable: $GITLEAKS"
SCANNER_VERSION="$("$GITLEAKS" version 2>/dev/null | head -1)"
[ -n "$SCANNER_VERSION" ] || fail "scanner version unavailable"

cd "$REPO"
git rev-parse --is-inside-work-tree >/dev/null 2>&1 || fail "not a git repository"

# --- 1. Exact snapshot payload (same algorithm as internal/snapshot/snapshot.go)
INDEX="$TMP/index"
export GIT_INDEX_FILE="$INDEX"
if git rev-parse -q --verify HEAD >/dev/null; then
  git read-tree HEAD
else
  git read-tree --empty
fi
git add -A
TREE="$(git write-tree)"
unset GIT_INDEX_FILE

PAYLOAD="$TMP/payload"
mkdir -p "$PAYLOAD"
git archive "$TREE" | tar -x -C "$PAYLOAD"
git ls-tree -r "$TREE" > "$TMP/payload.lst"
PAYLOAD_FILES="$(wc -l < "$TMP/payload.lst" | tr -d ' ')"

# --- 2. Forbidden payload shapes (fail closed)
FORBIDDEN="$TMP/forbidden.txt"
: > "$FORBIDDEN"
awk '$1=="120000" {print $4}' "$TMP/payload.lst" >> "$FORBIDDEN"
awk '$1=="160000" {print $4}' "$TMP/payload.lst" >> "$FORBIDDEN"
git ls-tree -r --name-only "$TREE" \
  | grep -Ei '((^|/)\.env($|\.)|(^|/)(id_rsa|id_dsa|id_ecdsa|id_ed25519|\.netrc)$|\.(pem|p12|pfx|key|mobileprovision|keystore|jks)$|(^|/)AuthKey_[A-Z0-9]+\.p8$|(^|/)(credentials|secrets)\.(json|ya?ml|txt|env)$)' \
  >> "$FORBIDDEN" || true
# Allow documented, non-secret env templates only if they contain no values.
if [ -s "$FORBIDDEN" ]; then
  sed -i -E '/\.env\.(example|sample|template)$/d' "$FORBIDDEN"
fi
if [ -s "$FORBIDDEN" ]; then
  echo "Forbidden payload paths:" >&2
  sed 's/^/  - /' "$FORBIDDEN" >&2
  fail "forbidden sensitive filename, symlink or gitlink in payload"
fi

# --- 3. Payload scan
set +e
"$GITLEAKS" dir "$PAYLOAD" --no-banner --redact --exit-code 1 \
  --report-format json --report-path "$TMP/payload.json" --timeout 300 >"$TMP/payload.log" 2>&1
PAYLOAD_RC=$?
set -e
[ -f "$TMP/payload.json" ] || echo '[]' > "$TMP/payload.json"

# --- 4. Working-tree scan (includes ignored files; build outputs excluded)
WORK="$TMP/work"
mkdir -p "$WORK"
tar -C "$REPO" --exclude=.git --exclude=dist --exclude=build --exclude=DerivedData -cf - . \
  | tar -x -C "$WORK"
set +e
"$GITLEAKS" dir "$WORK" --no-banner --redact --exit-code 1 \
  --report-format json --report-path "$TMP/work.json" --timeout 300 >"$TMP/work.log" 2>&1
WORK_RC=$?
set -e
[ -f "$TMP/work.json" ] || echo '[]' > "$TMP/work.json"

# --- 5. Git history scan
HIST_RC=0
HISTORY_COMMITS="0"
if git rev-parse -q --verify HEAD >/dev/null; then
  HISTORY_COMMITS="$(git rev-list --count --all)"
  set +e
  "$GITLEAKS" git "$REPO" --log-opts=--all --no-banner --redact --exit-code 1 \
    --report-format json --report-path "$TMP/history.json" --timeout 300 >"$TMP/history.log" 2>&1
  HIST_RC=$?
  set -e
  [ -f "$TMP/history.json" ] || echo '[]' > "$TMP/history.json"
else
  echo '[]' > "$TMP/history.json"
fi

# --- 6. Workflow YAML is in the payload and explicitly scanned
WORKFLOW_RC=0
if compgen -G ".github/workflows/*.yml" >/dev/null || compgen -G ".github/workflows/*.yaml" >/dev/null; then
  set +e
  "$GITLEAKS" dir .github/workflows --no-banner --redact --exit-code 1 \
    --report-format json --report-path "$TMP/workflows.json" --timeout 120 >"$TMP/workflows.log" 2>&1
  WORKFLOW_RC=$?
  set -e
else
  echo '[]' > "$TMP/workflows.json"
fi

# --- 7. Ignored files: record, and prove they are outside the payload
git ls-files --others --ignored --exclude-standard > "$TMP/ignored.lst" || true
IGNORED_COUNT="$(wc -l < "$TMP/ignored.lst" | tr -d ' ')"
: > "$TMP/ignored_in_payload.lst"
while IFS= read -r f; do
  [ -n "$f" ] || continue
  if git ls-tree -r --name-only "$TREE" | grep -Fxq "$f"; then echo "$f" >> "$TMP/ignored_in_payload.lst"; fi
done < "$TMP/ignored.lst"
[ -s "$TMP/ignored_in_payload.lst" ] && fail "ignored file included in snapshot payload"

# --- 8. Sanitized evidence (no secret values)
set +e
python3 - "$TMP" "$OUT/secret-gate.json" "$SCANNER_VERSION" "$TREE" "$PAYLOAD_FILES" \
  "$HISTORY_COMMITS" "$IGNORED_COUNT" "$PAYLOAD_RC" "$WORK_RC" "$HIST_RC" "$WORKFLOW_RC" <<'PY'
import json, os, sys, datetime
tmp, out, version, tree, payload_files, commits, ignored, prc, wrc, hrc, wfrc = sys.argv[1:]

def findings(path):
    if not os.path.exists(path):
        return None
    try:
        data = json.load(open(path))
    except Exception:
        return None
    if data is None:
        return []
    return [{"rule": d.get("RuleID"), "file": d.get("File"), "line": d.get("StartLine")}
            for d in data]

reports = {
    "payload": findings(os.path.join(tmp, "payload.json")),
    "working_tree": findings(os.path.join(tmp, "work.json")),
    "history": findings(os.path.join(tmp, "history.json")),
    "workflows": findings(os.path.join(tmp, "workflows.json")),
}
rcs = {"payload": int(prc), "working_tree": int(wrc), "history": int(hrc), "workflows": int(wfrc)}
uncertain = any(v is None for v in reports.values())
positive = sum(len(v or []) for v in reports.values()) > 0
ok = not uncertain and not positive and all(rc == 0 for rc in rcs.values())

summary = {
    "gate": "github-secret-protection",
    "verdict": "PASS" if ok else "FAIL",
    "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "scanner": {"name": "gitleaks", "version": version},
    "scope": {
        "repo": os.getcwd(),
        "exact_snapshot_tree_sha": tree,
        "payload_files": int(payload_files),
        "history_commits": int(commits),
        "ignored_files_outside_payload": int(ignored),
        "workflow_yaml_scanned": True,
    },
    "scan_scope": ["exact_snapshot_payload", "working_tree", "git_history_all_refs", "github_actions_workflows", "ignored_file_containment"],
    "exit_codes": rcs,
    "findings_redacted": reports,
    "positive_findings": positive,
    "incomplete_scans": uncertain,
    "policy": "FAIL CLOSED: any finding, incomplete scan or uncertain result blocks commit/push/dispatch",
}
json.dump(summary, open(out, "w"), indent=2)
print(json.dumps({"verdict": summary["verdict"], "tree": tree, "files": payload_files,
                  "findings": sum(len(v or []) for v in reports.values()),
                  "scanner": version}, indent=2))
sys.exit(0 if ok else 1)
PY
RC=$?
set -e
rm -f "$TMP"/*.json
if [ $RC -ne 0 ]; then
  echo "SECRET GATE: FAIL — see $OUT/secret-gate.json (findings are redacted)" >&2
  exit 1
fi
echo "SECRET GATE: PASS — exact payload tree $TREE is clean"
