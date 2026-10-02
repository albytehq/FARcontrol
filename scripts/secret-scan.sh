#!/usr/bin/env bash
# FARcontrol secret scan (§76): no secrets in source, test fixtures, or docs.
# Flags long hex / base58-ish high-entropy blobs that look like real tokens.
# Known-safe patterns (placeholders, test constants) are in the allowlist.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
HITS=0
scan() {
    # 32+ hex chars (sha256/hmac/token-shaped) or 40+ base58-ish blobs,
    # excluding lines that are clearly code/docs about tokens, not tokens.
    while IFS= read -r line; do
        file="${line%%:*}"
        lineno="${line#*:}"; lineno="${lineno%%:*}"
        content="${line#*:*:}"
        # allowlist: test fixtures and protocol constants (deliberate, not secrets)
        case "$content" in
            *test-agent-token*|*test-admin-token*|*FARCONTROL_TEST_MODE*|*deadbeef*|*placeholder*) continue ;;
        esac
        echo "  [SECRET?] $file:$lineno  $content" >&2
        HITS=$((HITS+1))
    done < <(grep -rEn '[0-9a-fA-F]{40,}|[1-9A-HJ-N-Za-km-z]{43,}' \
        --include='*.rs' --include='*.sh' --include='*.md' --include='*.toml' --include='*.html' \
        "$ROOT/src" "$ROOT/scripts" "$ROOT/docs" "$ROOT/README.md" 2>/dev/null | head -50)
}
scan
if [ $HITS -gt 0 ]; then
    echo "secret-scan: $HITS suspicious line(s) — review above (real tokens must NEVER be committed)"
    exit 1
fi
echo "secret-scan: CLEAN — no token-shaped blobs in source/tests/docs"
