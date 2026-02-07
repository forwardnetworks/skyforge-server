#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CHECKS_DIR="$ROOT_DIR/skyforge/policy_reports_assets/checks"
CATALOG_YAML="$CHECKS_DIR/catalog.yaml"

if [[ ! -f "$CATALOG_YAML" ]]; then
  echo "policy reports: missing catalog: $CATALOG_YAML" >&2
  exit 1
fi

echo "policy reports: validating embedded .nqe checks"

fail=0

## 1) Basic sanity: files exist + contain @query
while IFS= read -r -d '' f; do
  # Allow library-only helpers with no @query.
  if [[ "$(basename "$f")" == *"-lib.nqe" ]]; then
    continue
  fi
  if ! rg -q '@query' "$f"; then
    echo "ERROR: missing @query in: $f" >&2
    fail=1
  fi
done < <(find "$CHECKS_DIR" -maxdepth 1 -name '*.nqe' -print0)

## 2) Catalog params must match query signature params (best-effort).
## We keep this YAML parsing intentionally simple (catalog is intentionally simple).
##
## Output format (tab-separated):
##   checkId<TAB>param1,param2,...
tmp_params="$(mktemp)"
awk '
  function trim(s) { sub(/^[[:space:]]+/, "", s); sub(/[[:space:]]+$/, "", s); return s }
  BEGIN { in_check=0; in_params=0; check=""; params="" }
  /^[[:space:]]*- id:/ {
    # flush previous check
    if (check != "") {
      print check "\t" params
    }
    in_check=1
    in_params=0
    params=""
    check=$0
    sub(/^[[:space:]]*- id:[[:space:]]*/, "", check)
    gsub(/"/, "", check)
    check=trim(check)
    next
  }
  /^[[:space:]]*params:[[:space:]]*$/ { if (in_check) { in_params=1 } next }
  /^[[:space:]]*- name:/ {
    if (in_check && in_params) {
      n=$0
      sub(/^[[:space:]]*- name:[[:space:]]*/, "", n)
      gsub(/"/, "", n)
      n=trim(n)
      if (n != "") {
        if (params == "") params=n
        else params=params "," n
      }
    }
    next
  }
  /^[ \t]*- id:/ { next }
  # Any other top-level check entry ends params collection when indentation resets
  /^[^[:space:]]/ { in_params=0; next }
  END { if (check != "") print check "\t" params }
' "$CATALOG_YAML" > "$tmp_params"

extract_sig_param_lines() {
  # Extract parameter identifiers within the @query signature.
  # Supports single-line and multi-line signatures.
  local file="$1"
  perl -0777 -ne '
    if (/\@query\s*\n\s*[A-Za-z_][A-Za-z0-9_]*\s*\((.*?)\)\s*=/ms) {
      my $args = $1;
      while ($args =~ /([A-Za-z_][A-Za-z0-9_]*)\s*:/g) {
        print "$1\n";
      }
    }
  ' "$file" \
    | tr -d "\r" \
    | sed 's/^[[:space:]]*//; s/[[:space:]]*$//' \
    | sed '/^[[:space:]]*$/d' \
    | sort -u
}

while IFS=$'\t' read -r check_id param_csv; do
  [[ -z "$check_id" ]] && continue
  [[ -z "$param_csv" ]] && continue

  file="$CHECKS_DIR/$check_id"
  if [[ ! -f "$file" ]]; then
    echo "ERROR: catalog references missing .nqe: $check_id" >&2
    fail=1
    continue
  fi

  sig_lines="$(extract_sig_param_lines "$file")"
  sig_csv="$(echo "$sig_lines" | tr '\n' ',' | sed 's/,$//')"

  IFS=',' read -r -a cat_arr <<< "$param_csv"
  for p in "${cat_arr[@]}"; do
    p="$(printf '%s' "$p" | tr -d '\r' | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')"
    [[ -z "$p" ]] && continue
    if ! echo "$sig_lines" | grep -Fxq "$p"; then
      echo "ERROR: $check_id: catalog param '$p' not found in query signature" >&2
      echo "  signature params: ${sig_csv:-<none>}" >&2
      fail=1
    fi
  done
done < "$tmp_params"

rm -f "$tmp_params"

## 3) Optional: full semantic validation via nqe-lsp-validate (if available).
## Requires:
##   - NQE_LSP_SCHEMA_PATH: path to nqe-schema.json
##   - NQE_LSP_EXPORT_ZIP: path to queries.zip
if command -v nqe-lsp-validate >/dev/null 2>&1; then
  if [[ -n "${NQE_LSP_SCHEMA_PATH:-}" && -n "${NQE_LSP_EXPORT_ZIP:-}" ]]; then
    echo "policy reports: running nqe-lsp-validate"
    nqe-lsp-validate \
      --schema "$NQE_LSP_SCHEMA_PATH" \
      --export-zip "$NQE_LSP_EXPORT_ZIP" \
      "$CHECKS_DIR"/*.nqe
  else
    echo "policy reports: nqe-lsp-validate found, but NQE_LSP_SCHEMA_PATH/NQE_LSP_EXPORT_ZIP not set; skipping semantic validation"
  fi
else
  echo "policy reports: nqe-lsp-validate not found; skipping semantic validation"
fi

if [[ "$fail" -ne 0 ]]; then
  echo "policy reports: validation failed" >&2
  exit 1
fi

echo "policy reports: validation OK"
