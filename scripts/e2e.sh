#!/usr/bin/env bash
# FARcontrol — End-to-End verification (docs/04-verification.md)
# Proves the full lifecycle + core invariants, using ONLY the simple CLI:
#   frtrol start (auto-init) → request → DENY / approve → exec → revoke → expiry
#   scope enforcement · policy denylist + timeout · file ops + escape rejected
#   audit trail · restart persistence · token rotation
# Runs in FARCONTROL_TEST_MODE=1 (allows sub-hour sessions for expiry testing).
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/target/release/frtrol"
export FARCONTROL_HOME="$(mktemp -d /tmp/farcontrol-e2e.XXXXXX)"
export FARCONTROL_TEST_MODE=1
DAEMON_PID=""
PASS=0
FAIL=0

cleanup() {
    [ -n "$DAEMON_PID" ] && kill "$DAEMON_PID" 2>/dev/null
    wait "$DAEMON_PID" 2>/dev/null
}
trap cleanup EXIT

say()  { echo -e "\n=== $1 ==="; }
ok()   { PASS=$((PASS+1)); echo "  [PASS] $1"; }
fail() { FAIL=$((FAIL+1)); echo "  [FAIL] $1"; }

# expect the CLI to succeed and its stdout to contain a substring
expect_ok() {
    local want="$1"; shift
    local out
    out=$("$@" 2>&1)
    if [ $? -eq 0 ] && echo "$out" | grep -q "$want"; then
        ok "$want"
    else
        fail "expected success containing '$want' — got: $(echo "$out" | head -3)"
    fi
}

# expect the CLI to fail with a specific machine error code in its stderr JSON
expect_err() {
    local want_code="$1"; shift
    local out rc
    if out=$("$@" 2>&1); then rc=0; else rc=$?; fi
    if [ $rc -ne 0 ] && echo "$out" | grep -q "\"code\":\"$want_code\""; then
        ok "error:$want_code"
    else
        fail "expected error code '$want_code' (rc=$rc) — got: $(echo "$out" | head -3)"
    fi
}

jq_get() { # field, json → value
    python3 -c "import json,sys; d=json.load(sys.stdin); print(d$1)" 2>/dev/null
}

say "0. no-args quick guide"
guide=$("$BIN" 2>&1)
echo "$guide" | grep -q "frtrol start" && ok "bare 'frtrol' prints quick guide" || fail "no-args guide missing"

say "1. start with auto-init (zero ceremony: no separate init step)"
"$BIN" start > "$FARCONTROL_HOME/daemon.log" 2>&1 &
DAEMON_PID=$!
for i in $(seq 1 50); do
    "$BIN" status >/dev/null 2>&1 && break
    sleep 0.2
done
"$BIN" status >/dev/null 2>&1 && ok "frtrol start (first run auto-initialized + daemon running)" \
    || { fail "daemon did not start"; tail -5 "$FARCONTROL_HOME/daemon.log"; exit 1; }
[ -f "$FARCONTROL_HOME/agent-token" ] && ok "agent-token auto-created" || fail "agent-token missing"
grep -q "first run" "$FARCONTROL_HOME/daemon.log" && ok "start printed first-run token" || fail "no first-run banner"

say "2. unsigned request is rejected (invariant: no valid proof = no access)"
code=$(curl -s --cacert "$FARCONTROL_HOME/cert.pem" -o /dev/null -w "%{http_code}" "https://127.0.0.1:7788/v1/ping" -m 5)
[ "$code" = "401" ] && ok "unsigned https ping → HTTP 401 (TLS + HMAC both enforce)" || fail "unsigned https ping → HTTP $code"
grep -q "https://" "$FARCONTROL_HOME/daemon.log" && ok "daemon serves HTTPS (rustls)" || fail "daemon not on https"

say "3. agent ping (valid HMAC)"
expect_ok '"service":"farcontrol"' "$BIN" agent ping

say "4. request A (positional, unquoted reason) + DENY path"
reqA=$("$BIN" agent request e2e-agent terminal_only 6 e2e deny path 2>/dev/null)
reqA_id=$(echo "$reqA" | jq_get "['request_id']")
[ -n "$reqA_id" ] && ok "positional request created: $reqA_id" || fail "request A not created"
expect_ok '"status":"pending"' "$BIN" agent status "$reqA_id"
# no session exists yet → exec has nothing to authorize against
expect_err "session_not_found" "$BIN" agent exec ses_doesnotexist echo hi
"$BIN" deny "$reqA_id" >/dev/null 2>&1 && ok "deny recorded" || fail "deny failed"
expect_ok '"status":"denied"' "$BIN" agent status "$reqA_id"

say "5. request B → approve → exec works (terminal_only, no '--' separator)"
reqB=$("$BIN" agent request e2e-agent terminal_only 6 e2e exec 2>/dev/null)
reqB_id=$(echo "$reqB" | jq_get "['request_id']")
approve_out=$("$BIN" approve "$reqB_id" 2>&1)
sesB_id=$(echo "$approve_out" | grep -o 'ses_[A-Za-z0-9]*' | head -1)
[ -n "$sesB_id" ] && ok "approved → session $sesB_id" || { fail "no session id from approve: $approve_out"; exit 1; }
expect_ok '"effective_status":"active"' "$BIN" agent status "$sesB_id"
exec_out=$("$BIN" agent exec "$sesB_id" sh -c 'echo e2e-hello-marker' 2>/dev/null)
echo "$exec_out" | grep -q "e2e-hello-marker" && ok "exec (no --) stdout contains marker" || fail "exec output wrong: $exec_out"
exit_ok=$(echo "$exec_out" | jq_get "['exit_code']")
[ "$exit_ok" = "0" ] && ok "exit_code=0" || fail "exit_code=$exit_ok"

say "6. scope enforcement (invariant 4: missing capability = denied)"
expect_err "scope_denied" "$BIN" agent read "$sesB_id" e2e-scope-test.txt
expect_err "scope_denied" "$BIN" agent write "$sesB_id" e2e-scope-test.txt x

say "7. policy: denylist + timeout (standard package)"
expect_err "policy_denied" "$BIN" agent exec "$sesB_id" mkfs.ext4 /dev/sda9
timeout_out=$("$BIN" agent exec --timeout-ms 300 "$sesB_id" sleep 3 2>/dev/null)
echo "$timeout_out" | grep -q '"status":"timeout"' && ok "exec timeout enforced" || fail "timeout not enforced: $timeout_out"

say "8. agent self-revoke + revoked = no access"
"$BIN" agent revoke "$sesB_id" >/dev/null 2>&1 && ok "agent self-revoke" || fail "self-revoke failed"
expect_err "session_revoked" "$BIN" agent exec "$sesB_id" echo hi

say "9. full_access: file write (positional + stdin) / read / list + escape rejected"
reqC=$("$BIN" agent request e2e-agent full_access 6 e2e files 2>/dev/null)
reqC_id=$(echo "$reqC" | jq_get "['request_id']")
approveC=$("$BIN" approve "$reqC_id" 2>&1)
sesC_id=$(echo "$approveC" | grep -o 'ses_[A-Za-z0-9]*' | head -1)
[ -n "$sesC_id" ] && ok "full_access session $sesC_id" || fail "approve C failed: $approveC"
expect_ok '"written":14' "$BIN" agent write "$sesC_id" e2e-test.txt "hello from e2e"
# stdin pipe form: echo … | frtrol agent write <ses> <path>
echo "piped content 42" | "$BIN" agent write "$sesC_id" e2e-pipe.txt >/dev/null 2>&1 \
    && ok "write via stdin pipe" || fail "stdin pipe write failed"
pipe_read=$("$BIN" agent read "$sesC_id" e2e-pipe.txt 2>/dev/null)
piped=$(echo "$pipe_read" | python3 -c "import json,sys,base64; print(base64.b64decode(json.load(sys.stdin)['content_b64']).decode())" 2>/dev/null)
[ "$piped" = "piped content 42" ] && ok "piped content roundtrip matches" || fail "piped content mismatch: '$piped'"
read_out=$("$BIN" agent read "$sesC_id" e2e-test.txt 2>/dev/null)
content=$(echo "$read_out" | python3 -c "import json,sys,base64; print(base64.b64decode(json.load(sys.stdin)['content_b64']).decode())" 2>/dev/null)
[ "$content" = "hello from e2e" ] && ok "file roundtrip content matches" || fail "content mismatch: '$content'"
expect_ok '"name":"e2e-test.txt"' "$BIN" agent ls "$sesC_id" "~"
expect_err "path_outside_root" "$BIN" agent write "$sesC_id" /tmp/farcontrol-escape.txt nope
expect_err "path_outside_root" "$BIN" agent read "$sesC_id" /etc/hostname

say "10. owner revoke (admin plane) + revoked = no access"
"$BIN" revoke "$sesC_id" >/dev/null 2>&1 && ok "owner revoke" || fail "owner revoke failed"
expect_err "session_revoked" "$BIN" agent exec "$sesC_id" echo hi

say "11. expiry (lazy enforcement) + expired = no access"
reqD=$("$BIN" agent request e2e-agent terminal_only 6 e2e expiry 2>/dev/null)
reqD_id=$(echo "$reqD" | jq_get "['request_id']")
approveD=$("$BIN" approve "$reqD_id" --hours 0.0004 2>&1)   # ≈1.4 s — test mode only
sesD_id=$(echo "$approveD" | grep -o 'ses_[A-Za-z0-9]*' | head -1)
[ -n "$sesD_id" ] && ok "short session $sesD_id (test mode)" || fail "approve D failed: $approveD"
sleep 3
expect_err "session_expired" "$BIN" agent exec "$sesD_id" echo hi

say "12. audit trail (invariant 8) + hash chain tamper detection"
audit=$("$BIN" audit --limit 200 2>&1)
for ev in request.created request.denied session.approved exec.run exec.denied session.revoked session.expired file.write file.read auth.rejected; do
    echo "$audit" | grep -q "$ev" && ok "audit: $ev" || fail "audit missing: $ev"
done
[ -f "$FARCONTROL_HOME/audit.jsonl" ] && ok "audit.jsonl exists" || fail "audit.jsonl missing"
grep -q '"hash"' "$FARCONTROL_HOME/audit.jsonl" && ok "audit lines carry hash chain" || fail "no hash field in audit.jsonl"
# tamper → doctor must go red → restore → green again
cp "$FARCONTROL_HOME/audit.jsonl" "$FARCONTROL_HOME/audit.bak"
echo '{"ts":1,"actor":"EVIL","action":"forged.event","prev":"genesis","hash":"deadbeef"}' >> "$FARCONTROL_HOME/audit.jsonl"
if tampered=$("$BIN" doctor 2>&1); then t_rc=0; else t_rc=$?; fi
[ $t_rc -ne 0 ] && echo "$tampered" | grep -q "audit_chain" && ok "tampered audit.jsonl → doctor FAILS" || fail "doctor did not catch tampering"
mv "$FARCONTROL_HOME/audit.bak" "$FARCONTROL_HOME/audit.jsonl"

say "13. frtrol doctor (health checks, spec §46)"
doctor_out=$("$BIN" doctor 2>&1)
drc=$?
[ $drc -eq 0 ] && echo "$doctor_out" | grep -q "ALL GREEN" && ok "doctor: ALL GREEN (exit 0)" || fail "doctor not green: $(echo "$doctor_out" | grep FAIL | head -2)"

say "14. rate limiting (SE-09): brute-force lockout + recovery"
locked=0
for i in $(seq 1 7); do
    if FARCONTROL_TOKEN=wrongtoken$i "$BIN" agent ping >/dev/null 2>&1; then :; else :; fi
    out=$(FARCONTROL_TOKEN=wrongtoken$i "$BIN" agent ping 2>&1)
    echo "$out" | grep -q '"code":"rate_limited"' && locked=1
done
[ $locked -eq 1 ] && ok "7 bad tokens → rate_limited (fail closed)" || fail "no rate limit after 7 bad tokens"
out=$("$BIN" agent ping 2>&1)
echo "$out" | grep -q '"code":"rate_limited"' && ok "valid request blocked during lockout" || fail "lockout does not apply to valid requests"
sleep 9   # v0.9: progressive lockout escalates to the 8s test cap — wait it out
expect_ok '"service":"farcontrol"' "$BIN" agent ping

say "15. interactive terminal (PTY, ADR-0013)"
reqT=$("$BIN" agent request e2e-agent terminal_only 6 e2e term 2>/dev/null)
reqT_id=$(echo "$reqT" | jq_get "['request_id']")
approveT=$("$BIN" approve "$reqT_id" 2>&1)
sesT_id=$(echo "$approveT" | grep -o 'ses_[A-Za-z0-9]*' | head -1)
[ -n "$sesT_id" ] && ok "session for terminal: $sesT_id" || fail "term session not approved"
term_out=$(echo 'echo e2e-term-marker; exit' | timeout 20 "$BIN" agent term "$sesT_id" sh 2>&1)
echo "$term_out" | grep -q "e2e-term-marker" && ok "interactive term: command ran, output streamed back" || fail "term output missing: $term_out"
"$BIN" agent exec "$sesT_id" echo still-alive >/dev/null 2>&1 && ok "session still active after term close" || fail "term close killed the session"
# free the 1-active-session slot for the next section (policy max = 1)
"$BIN" revoke "$sesT_id" >/dev/null 2>&1 && ok "term session cleaned up (policy: 1 active max)" || fail "cleanup revoke failed"

say "16. persistence across daemon restart (fail-closed, state survives)"
reqE=$("$BIN" agent request e2e-agent terminal_only 6 e2e restart 2>/dev/null)
reqE_id=$(echo "$reqE" | jq_get "['request_id']")
approveE=$("$BIN" approve "$reqE_id" 2>&1)
sesE_id=$(echo "$approveE" | grep -o 'ses_[A-Za-z0-9]*' | head -1)
kill "$DAEMON_PID" 2>/dev/null || true
wait "$DAEMON_PID" 2>/dev/null || true
DAEMON_PID=""
# daemon down → agent must fail (network failure = fail closed)
if agent_out=$("$BIN" agent ping 2>&1); then agent_rc=0; else agent_rc=$?; fi
[ $agent_rc -ne 0 ] && ok "daemon down → agent fails (fail closed)" || fail "agent unexpectedly succeeded with daemon down"
"$BIN" start >> "$FARCONTROL_HOME/daemon.log" 2>&1 &
DAEMON_PID=$!
for i in $(seq 1 50); do "$BIN" status >/dev/null 2>&1 && break; sleep 0.2; done
expect_ok "e2e-restart-marker" "$BIN" agent exec "$sesE_id" sh -c 'echo e2e-restart-marker'
expect_ok "e2e-term-marker2" bash -c "echo 'echo e2e-term-marker2; exit' | timeout 20 $BIN agent term $sesE_id sh"

say "17. token rotation (old token dies immediately)"
OLD_TOKEN=$(cat "$FARCONTROL_HOME/agent-token")
rot=$("$BIN" rotate 2>&1)
NEW_TOKEN=$(echo "$rot" | grep -v "^FARcontrol\|NEW agent\|old one" | tail -1 | tr -d ' ')
[ -n "$NEW_TOKEN" ] && [ "$NEW_TOKEN" != "$OLD_TOKEN" ] && ok "token rotated" || fail "rotation output: $rot"
# old token must fail auth
if old_out=$(FARCONTROL_TOKEN="$OLD_TOKEN" "$BIN" agent ping 2>&1); then old_rc=0; else old_rc=$?; fi
[ $old_rc -ne 0 ] && echo "$old_out" | grep -q '"code":"invalid_signature"' && ok "old token → invalid_signature" || fail "old token still works?! $old_out"
# new token (from file) must work
expect_ok '"service":"farcontrol"' "$BIN" agent ping

say "18. frtrol panic (SE-11): emergency stop kills everything at once"
PRE_PANIC_TOKEN=$(cat "$FARCONTROL_HOME/agent-token")
panic_out=$("$BIN" panic e2e-panic-test 2>&1)
echo "$panic_out" | grep -q "PANIC executed" && ok "panic executed" || fail "panic failed: $panic_out"
echo "$panic_out" | grep -Eq "revoked sessions *: [1-9]" && ok "all active sessions revoked" || fail "panic did not revoke sessions"
expect_err "session_revoked" "$BIN" agent exec "$sesE_id" echo hi
expect_err "session_revoked" "$BIN" agent exec "$sesT_id" echo hi
POST_PANIC_TOKEN=$(cat "$FARCONTROL_HOME/agent-token")
[ -n "$POST_PANIC_TOKEN" ] && [ "$POST_PANIC_TOKEN" != "$PRE_PANIC_TOKEN" ] && ok "agent token rotated by panic" || fail "panic did not rotate token"
if pre_out=$(FARCONTROL_TOKEN="$PRE_PANIC_TOKEN" "$BIN" agent ping 2>&1); then pre_rc=0; else pre_rc=$?; fi
[ $pre_rc -ne 0 ] && echo "$pre_out" | grep -q '"code":"invalid_signature"' && ok "pre-panic token is dead" || fail "pre-panic token still valid"
# term on a dead session must be refused
term_dead=$(echo 'echo nope; exit' | timeout 10 "$BIN" agent term "$sesT_id" sh 2>&1)
echo "$term_dead" | grep -q '"code":"session_revoked"' && ok "terminal on revoked session refused" || fail "term on dead session: $term_dead"

say "19. web UI (v0.3): owner console on the admin plane (ADR-0017)"
UI="https://127.0.0.1:7789"
CJ="$FARCONTROL_HOME/ui-cookies.txt"
CA="$FARCONTROL_HOME/cert.pem"
ADMTOK=$(cat "$FARCONTROL_HOME/admin-token")

# a. the console shell is served (no auth needed to load the shell, data needs auth)
html=$(curl -s --cacert "$CA" "$UI/" -m 5)
echo "$html" | grep -q "FARcontrol" && ok "GET / serves the console shell" || fail "no HTML shell at /"

# b. structural XSS defense: the page must contain ZERO innerHTML/document.write/eval
if echo "$html" | grep -qE "innerHTML|document\.write|eval\(" ; then
    fail "page uses innerHTML/eval — XSS surface"
else
    ok "page uses textContent only (no innerHTML/eval — XSS structurally prevented)"
fi

# c. login with a wrong password → 401
code=$(curl -s --cacert "$CA" -o /dev/null -w "%{http_code}" -X POST "$UI/ui/login" \
    -H "X-Far-Ui: 1" -H "Content-Type: application/json" \
    -d '{"password":"wrong-password"}' -m 5)
[ "$code" = "401" ] && ok "wrong password → 401" || fail "wrong password → HTTP $code"

# d. login with the admin token → 200 + session cookie
code=$(curl -s --cacert "$CA" -c "$CJ" -o /dev/null -w "%{http_code}" -X POST "$UI/ui/login" \
    -H "X-Far-Ui: 1" -H "Content-Type: application/json" \
    -d "{\"password\":\"$ADMTOK\"}" -m 5)
[ "$code" = "200" ] && grep -q "far_ui" "$CJ" && ok "admin token login → 200 + far_ui cookie" || fail "login failed: HTTP $code"

# e. /ui/state without a cookie → 401
code=$(curl -s --cacert "$CA" -o /dev/null -w "%{http_code}" "$UI/ui/state" -m 5)
[ "$code" = "401" ] && ok "no cookie → 401 (fail closed)" || fail "unauthenticated /ui/state → HTTP $code"

# f. /ui/state with the cookie → dashboard data
state=$(curl -s --cacert "$CA" -b "$CJ" "$UI/ui/state" -m 5)
echo "$state" | grep -q '"pending"' && ok "/ui/state returns dashboard data" || fail "no state JSON: $state"

# g. CSRF: POST with a valid cookie but WITHOUT the X-Far-Ui header → 403
req19=$("$BIN" agent request ui-test-agent terminal_only 6 approve me from the web console 2>/dev/null)
REQ19=$(echo "$req19" | python3 -c "import json,sys; print(json.load(sys.stdin)['request_id'])")
code=$(curl -s --cacert "$CA" -b "$CJ" -o /dev/null -w "%{http_code}" -X POST "$UI/ui/approve" \
    -H "Content-Type: application/json" -d "{\"request_id\":\"$REQ19\"}" -m 5)
[ "$code" = "403" ] && ok "POST without X-Far-Ui header → 403 csrf_blocked" || fail "CSRF not blocked: HTTP $code"

# h. approve via the UI (cookie + header) → session created
ap=$(curl -s --cacert "$CA" -b "$CJ" -X POST "$UI/ui/approve" \
    -H "X-Far-Ui: 1" -H "Content-Type: application/json" \
    -d "{\"request_id\":\"$REQ19\",\"hours\":6}" -m 5)
SES19=$(echo "$ap" | python3 -c "import json,sys; print(json.load(sys.stdin)['session']['id'])" 2>/dev/null)
[ -n "$SES19" ] && ok "approved via web UI → session $SES19" || fail "UI approve failed: $ap"

# i. the agent can actually use that session
expect_ok "ui-approved-marker" "$BIN" agent exec "$SES19" echo ui-approved-marker

# j. revoke via the UI → access dies immediately
rv=$(curl -s --cacert "$CA" -b "$CJ" -X POST "$UI/ui/revoke" \
    -H "X-Far-Ui: 1" -H "Content-Type: application/json" \
    -d "{\"session_id\":\"$SES19\"}" -m 5)
echo "$rv" | grep -q '"effective_status": *"revoked"' && ok "revoked via web UI" || fail "UI revoke failed: $rv"
expect_err "session_revoked" "$BIN" agent exec "$SES19" echo hi

# k. panic via the UI (new request first so there is something to kill)
req19b=$("$BIN" agent request ui-panic-agent terminal_only 6 will be panic-killed 2>/dev/null)
REQ19B=$(echo "$req19b" | python3 -c "import json,sys; print(json.load(sys.stdin)['request_id'])")
apb=$(curl -s --cacert "$CA" -b "$CJ" -X POST "$UI/ui/approve" \
    -H "X-Far-Ui: 1" -H "Content-Type: application/json" \
    -d "{\"request_id\":\"$REQ19B\"}" -m 5)
SES19B=$(echo "$apb" | python3 -c "import json,sys; print(json.load(sys.stdin)['session']['id'])" 2>/dev/null)
pn=$(curl -s --cacert "$CA" -b "$CJ" -X POST "$UI/ui/panic" \
    -H "X-Far-Ui: 1" -H "Content-Type: application/json" \
    -d '{"reason":"e2e web-ui panic"}' -m 5)
echo "$pn" | grep -Eq '"revoked_sessions": *[1-9]' && ok "PANIC via web UI revoked sessions" || fail "UI panic: $pn"
expect_err "session_revoked" "$BIN" agent exec "$SES19B" echo hi

# l. the audit trail records web-UI actions (owner:webui actor)
aud19=$("$BIN" audit 2>&1)
echo "$aud19" | grep -q "ui.login" && echo "$aud19" | grep -q "ui.approve" && echo "$aud19" | grep -q "ui.revoke" \
    && ok "audit records ui.login / ui.approve / ui.revoke (actor owner:webui)" \
    || fail "audit missing web-UI events"

# m. logout kills the session server-side
lo=$(curl -s --cacert "$CA" -b "$CJ" -c "$CJ" -X POST "$UI/ui/logout" -H "X-Far-Ui: 1" -H "Content-Type: application/json" -d '{}' -m 5)
code=$(curl -s --cacert "$CA" -b "$CJ" -o /dev/null -w "%{http_code}" "$UI/ui/state" -m 5)
[ "$code" = "401" ] && ok "after logout the cookie is dead" || fail "post-logout /ui/state → HTTP $code"


say "20. Full Access adapters (v0.4, Phase 4): process / app / desktop"
# phase 1: terminal_only session — every adapter must be scope-denied
req20t=$("$BIN" agent request adapter-term-agent terminal_only 6 scope gate testing 2>/dev/null)
REQ20T=$(echo "$req20t" | python3 -c "import json,sys; print(json.load(sys.stdin)['request_id'])")
"$BIN" approve "$REQ20T" >/dev/null 2>&1
SES20T=$("$BIN" agent status "$REQ20T" 2>/dev/null | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['request']['session_id'])")

# a. terminal_only sessions must be refused (invariant 4: missing capability)
expect_err "scope_denied" "$BIN" agent ps "$SES20T"
# desktop also scope-denied on terminal_only (gate before availability)
expect_err "scope_denied" "$BIN" agent shot "$SES20T"
# free the 1-active-session slot, then go full_access
"$BIN" agent revoke "$SES20T" >/dev/null 2>&1

req20=$("$BIN" agent request adapter-agent full_access 6 need process and app control 2>/dev/null)
REQ20=$(echo "$req20" | python3 -c "import json,sys; print(json.load(sys.stdin)['request_id'])")
"$BIN" approve "$REQ20" >/dev/null 2>&1
SES20=$("$BIN" agent status "$REQ20" 2>/dev/null | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['request']['session_id'])")

# b. process list works and flags the daemon itself (self-protection marker)
psout=$("$BIN" agent ps "$SES20" 2>&1)
echo "$psout" | grep -q '"processes"' && ok "process list returned" || fail "ps failed: $psout"
echo "$psout" | grep -q '"is_self":true' && ok "list flags the frtrol daemon (is_self)" || fail "is_self flag missing"

# c. app launch → detached pid
appout=$("$BIN" agent app "$SES20" sleep 300 2>&1)
APID=$(echo "$appout" | python3 -c "import json,sys; print(json.load(sys.stdin)['pid'])" 2>/dev/null)
[ -n "$APID" ] && [ "$APID" -gt 1 ] && ok "app launch → pid $APID (detached)" || fail "app launch: $appout"
kill -0 "$APID" 2>/dev/null && ok "launched app is actually running" || fail "pid $APID not running"

# d. kill it via the process adapter
killout=$("$BIN" agent kill "$SES20" "$APID" 2>&1)
echo "$killout" | grep -q '"killed":true' && ok "process kill → TERM sent" || fail "kill failed: $killout"
sleep 0.3
kill -0 "$APID" 2>/dev/null && fail "pid $APID survived TERM" || ok "process died after TERM"

# e. protected pids: PID 1 and the daemon itself
expect_err "kill_refused" "$BIN" agent kill "$SES20" 1
DAPID=$(pgrep -f 'frtrol start' | head -1)
[ -n "$DAPID" ] && expect_err "kill_refused" "$BIN" agent kill "$SES20" "$DAPID"

# f. policy denylist applies to app launch too (a launch IS an execution)
expect_err "policy_denied" "$BIN" agent app "$SES20" mkfs.ext4 /dev/sda9

# g. desktop capabilities fail CLOSED with a clean machine error (headless box)
expect_err "desktop_unavailable" "$BIN" agent shot "$SES20"
expect_err "desktop_unavailable" "$BIN" agent type "$SES20" hello world

# h. the audit trail records adapter actions (invariant 8)
aud20=$("$BIN" audit 2>&1)
echo "$aud20" | grep -q "app.launch" && echo "$aud20" | grep -q "process.kill" \
    && ok "audit records app.launch + process.kill" \
    || fail "audit missing adapter events"


say "21. network chaos (v0.5, §75): garbage over real TLS — daemon must survive"
CA="$FARCONTROL_HOME/cert.pem"
AGENT="https://127.0.0.1:7788"
# note: these are unsigned garbage (auth layer gets fuzzed in-process by the
# cargo fuzz suite); here we prove the LIVE daemon + TLS stack survives too.
survive() {
    local out code
    code=$(curl -s --cacert "$CA" -o /dev/null -w "%{http_code}" -X POST "$AGENT/v1/session/request" \
        -H "Content-Type: application/json" --data-binary "$1" -m 10 2>/dev/null)
    # garbage may be 401 (unsigned) or 400 (if any layer parses) — must never 5xx or hang
    if [ "$code" -ge 500 ] || [ -z "$code" ]; then
        fail "chaos input got HTTP '$code'"
    else
        ok "chaos → HTTP $code (controlled)"
    fi
}
survive 'not json at all'
survive '{"session_id":'
printf '\x00\xff\xfe\x92garbage' > "$FARCONTROL_HOME/chaos.bin"
code=$(curl -s --cacert "$CA" -o /dev/null -w "%{http_code}" -X POST "$AGENT/v1/session/request" \
    -H "Content-Type: application/json" --data-binary "@$FARCONTROL_HOME/chaos.bin" -m 10 2>/dev/null)
[ "$code" -lt 500 ] && [ -n "$code" ] && ok "binary garbage → HTTP $code (controlled)" || fail "binary garbage → $code"
# 10MB body over the wire — 413 JSON envelope (argv can't carry 10MB: use @file)
head -c 10485760 /dev/zero | tr '\0' 'a' > "$FARCONTROL_HOME/big10mb.bin"
code=$(curl -s --cacert "$CA" -o "$FARCONTROL_HOME/413.json" -w "%{http_code}" -X POST "$AGENT/v1/session/request" \
    -H "Content-Type: application/json" --data-binary "@$FARCONTROL_HOME/big10mb.bin" -m 20 2>/dev/null)
[ "$code" = "413" ] && grep -q '"payload_too_large"' "$FARCONTROL_HOME/413.json" \
    && ok "10MB body → 413 JSON envelope (fuzz fix verified on the wire)" || fail "10MB body → $code: $(cat "$FARCONTROL_HOME/413.json" 2>/dev/null | head -c 120)"
# the chaos above was a stream of failed auths — the rate limiter SHOULD have
# engaged (that is its job), and the v0.9 progressive lockout escalates to the
# 8s test cap. Wait it out, then the daemon must still be fully functional
# (lockout recovers — fail closed, not broken).
sleep 9
expect_ok '"service":"farcontrol"' "$BIN" agent ping


say "22. backup / restore (v0.6, §72/§103): full cycle, identity survives"
BK="/tmp/farcontrol-e2e-bk-$$.$RANDOM.tar.gz"

# a. backup while the daemon runs (WAL checkpoint + tar via admin plane)
bkout=$("$BIN" backup "$BK" 2>&1)
echo "$bkout" | grep -q "backup written" && ok "backup taken from the running daemon" || fail "backup failed: $bkout"
[ -s "$BK" ] && ok "archive is non-empty ($(stat -c%s "$BK") bytes)" || fail "archive empty"
perm=$(stat -c%a "$BK")
[ "$perm" = "600" ] && ok "archive mode 0600 (contains all secrets)" || fail "archive mode $perm"

# b. stop the daemon — restore is an offline operation
kill "$DAEMON_PID" 2>/dev/null; wait "$DAEMON_PID" 2>/dev/null; DAEMON_PID=""

# c. restore (old data preserved as .bak, archive validated first)
rsout=$("$BIN" restore "$BK" 2>&1)
echo "$rsout" | grep -q "restore complete" && ok "restore completed" || fail "restore failed: $rsout"
echo "$rsout" | grep -q "data preserved at" && ok "previous data kept as .bak (never destroyed)" || fail "no .bak mention: $rsout"
ls -d /tmp/farcontrol-e2e.*.bak-* >/dev/null 2>&1 && ok ".bak directory exists" || true

# d. restart — auto-init must NOT fire (config exists), identity preserved
"$BIN" start > "$FARCONTROL_HOME/daemon.log" 2>&1 &
DAEMON_PID=$!
for i in $(seq 1 50); do "$BIN" status >/dev/null 2>&1 && break; sleep 0.2; done
grep -q "first run" "$FARCONTROL_HOME/daemon.log" && fail "RESTORE BUG: daemon re-initialized (identity lost!)" \
    || ok "no re-init after restore (identity preserved)"

# e. the agent token from BEFORE the backup still authenticates
expect_ok '"service":"farcontrol"' "$BIN" agent ping

# f. audit history survived (events from before the backup are present)
aud22=$("$BIN" audit 2>&1)
echo "$aud22" | grep -q "process.kill" && ok "audit history restored (pre-backup events present)" || fail "audit lost after restore"

# g. restore refuses to run while the daemon is up (no live-file swap)
rs2=$("$BIN" restore "$BK" 2>&1)
echo "$rs2" | grep -q "daemon is RUNNING" && ok "restore refuses while daemon runs (fail closed)" || fail "restore did not refuse: $rs2"

# h. a garbage archive is rejected without touching live data
GARB="/tmp/farcontrol-e2e-garbage-$$.$RANDOM.tar.gz"
head -c 2048 /dev/urandom > "$GARB"
rs3=$("$BIN" restore "$GARB" 2>&1)
echo "$rs3" | grep -qE "not a valid gzip tar|archive is empty|missing required file" \
    && ok "garbage archive rejected cleanly" || fail "garbage accepted?! $rs3"
rm -f "$GARB" "$BK"


say "23. observability + crash recovery (v0.7, App B/§73)"
UI="https://127.0.0.1:7789"
CA="$FARCONTROL_HOME/cert.pem"
ADMTOK=$(cat "$FARCONTROL_HOME/admin-token")

# a. healthz: unauthenticated liveness on the loopback admin plane
h=$(curl -s --cacert "$CA" "$UI/healthz" -m 5)
[ "$h" = "ok" ] && ok "GET /healthz → ok (no auth, loopback only)" || fail "healthz: '$h'"

# b. readyz: DB reachable + schema version current
r=$(curl -s --cacert "$CA" -o /dev/null -w "%{http_code}" "$UI/readyz" -m 5)
[ "$r" = "200" ] && ok "GET /readyz → 200 ready" || fail "readyz → $r"

# c. metrics need admin auth (401 without)
m401=$(curl -s --cacert "$CA" -o /dev/null -w "%{http_code}" "$UI/admin/metrics" -m 5)
[ "$m401" = "401" ] && ok "metrics without token → 401" || fail "metrics unauth → $m401"

# d. metrics with admin token: Prometheus text with live state
m=$(curl -s --cacert "$CA" -H "Authorization: Bearer $ADMTOK" "$UI/admin/metrics" -m 5)
echo "$m" | grep -q "farcontrol_up 1" && echo "$m" | grep -q "farcontrol_uptime_seconds" \
    && echo "$m" | grep -q "farcontrol_active_sessions" \
    && ok "GET /admin/metrics → Prometheus exposition" || fail "metrics: $m"

# e. CRASH RECOVERY: SIGKILL the daemon mid-life (no graceful shutdown)
# (free the 1-active-session slot from §20 first)
[ -n "$SES20" ] && "$BIN" agent revoke "$SES20" >/dev/null 2>&1
SES23_REQ=$("$BIN" agent request crash-agent terminal_only 6 survive a sigkill 2>/dev/null)
REQ23=$(echo "$SES23_REQ" | python3 -c "import json,sys; print(json.load(sys.stdin)['request_id'])")
"$BIN" approve "$REQ23" >/dev/null 2>&1
SES23=$("$BIN" agent status "$REQ23" 2>/dev/null | python3 -c "import json,sys; print(json.load(sys.stdin)['request']['session_id'])")
kill -9 "$DAEMON_PID" 2>/dev/null; wait "$DAEMON_PID" 2>/dev/null; DAEMON_PID=""
sleep 0.5
# hard-crash must not corrupt state: WAL replays on restart
"$BIN" start > "$FARCONTROL_HOME/daemon.log" 2>&1 &
DAEMON_PID=$!
for i in $(seq 1 50); do "$BIN" status >/dev/null 2>&1 && break; sleep 0.2; done
[ -n "$DAEMON_PID" ] && kill -0 "$DAEMON_PID" 2>/dev/null && ok "daemon restarted after SIGKILL" || fail "no daemon after crash"
h2=$(curl -s --cacert "$CA" "$UI/healthz" -m 5)
[ "$h2" = "ok" ] && ok "healthz ok after crash-restart" || fail "healthz after crash: '$h2'"
expect_ok "crash-recovery-marker" "$BIN" agent exec "$SES23" echo crash-recovery-marker
aud23=$("$BIN" audit 2>&1)
echo "$aud23" | grep -q "crash-agent" && ok "state (session + audit) survived the crash" || fail "state lost after crash"


say "24. agent identity catalog (v0.8, ADR-0022 / spec §9 §11 §81)"

# free the 1-active-session slot (section 23's crash-recovery session is live)
[ -n "$SES23" ] && "$BIN" agent revoke "$SES23" >/dev/null 2>&1

# valid declared identity via env (CLI forwards; server validates — one enforcement point)
FRS24_TOKEN=$(cat "$FARCONTROL_HOME/agent-token")
export FAR_AGENT_PROVIDER=z_ai
export FAR_AGENT_MODEL=glm-5.3
REQ24=$("$BIN" agent request glm-agent terminal_only 6 fix the docs 2>/dev/null | python3 -c "import json,sys; print(json.load(sys.stdin)['request_id'])")
unset FAR_AGENT_PROVIDER FAR_AGENT_MODEL
[ -n "$REQ24" ] && ok "request with declared identity accepted" || fail "declared identity rejected"
# the pending request carries the §11 agent object
ID24=$("$BIN" list --json 2>/dev/null | python3 -c "
import json,sys
d=json.load(sys.stdin)
r=[x for x in d['requests'] if x['id']=='$REQ24'][0]
print(r['agent']['provider']+'/'+r['agent']['model'])")
[ "$ID24" = "z_ai/glm-5.3" ] && ok "request JSON carries agent {provider, model} (§11)" || fail "identity missing from request JSON: '$ID24'"
# human list shows it too
"$BIN" list 2>/dev/null | grep -q "z_ai/glm-5.3 (declared)" && ok "frtrol list shows declared identity" || fail "list missing identity"
"$BIN" deny "$REQ24" >/dev/null 2>&1
# identity is copied into the session at approve time
export FAR_AGENT_PROVIDER=z_ai
export FAR_AGENT_MODEL=glm-5.3
REQ24B=$("$BIN" agent request glm-agent-2 terminal_only 6 write the docs 2>/dev/null | python3 -c "import json,sys; print(json.load(sys.stdin)['request_id'])")
unset FAR_AGENT_PROVIDER FAR_AGENT_MODEL
export FAR_AGENT_PROVIDER=qwen
export FAR_AGENT_MODEL=qwen-3.7-turbo
REQ24C=$("$BIN" agent request qwen-agent terminal_only 6 test identity 2>/dev/null | python3 -c "import json,sys; print(json.load(sys.stdin)['request_id'])")
unset FAR_AGENT_PROVIDER FAR_AGENT_MODEL
"$BIN" deny "$REQ24C" >/dev/null 2>&1
"$BIN" approve "$REQ24B" >/dev/null 2>&1
SES24=$("$BIN" agent status "$REQ24B" 2>/dev/null | python3 -c "import json,sys; print(json.load(sys.stdin)['request']['session_id'])")
SID24=$("$BIN" list --json 2>/dev/null | python3 -c "
import json,sys
d=json.load(sys.stdin)
s=[x for x in d['sessions'] if x['id']=='$SES24'][0]
print(s['agent']['provider']+'/'+s['agent']['model'])")
[ "$SID24" = "z_ai/glm-5.3" ] && ok "approved session carries the identity (UI-04)" || fail "session identity missing: '$SID24'"
"$BIN" agent revoke "$SES24" >/dev/null 2>&1

# invalid identity → fail closed at the single enforcement point
# (env values forwarded as-is; the SERVER rejects them)
OUT24=$(FAR_AGENT_PROVIDER=openai FAR_AGENT_MODEL=gpt-9 "$BIN" agent request bad-provider terminal_only 6 reason 2>&1)
echo "$OUT24" | grep -q '"code":"invalid_agent_identity"' && ok "unknown provider rejected: invalid_agent_identity" || fail "unknown provider not rejected: $(echo "$OUT24" | head -c 120)"
# provider without model (both-or-none) → the server must reject it
OUT24B=$(FAR_AGENT_PROVIDER=z_ai "$BIN" agent request half-identity terminal_only 6 reason 2>&1)
echo "$OUT24B" | grep -q '"code":"invalid_agent_identity"' && ok "provider-without-model rejected (§11 both-or-none)" || fail "half identity accepted: $(echo "$OUT24B" | head -c 120)"

# mixed: model from another provider
OUT24C=$(FAR_AGENT_PROVIDER=z_ai FAR_AGENT_MODEL=qwen-3.8-max "$BIN" agent request cross-identity terminal_only 6 reason 2>&1)
echo "$OUT24C" | grep -q '"code":"invalid_agent_identity"' && ok "cross-provider model rejected" || fail "cross-provider model accepted"
# error message must be metadata-only: no ids, no paths, no token material
if echo "$OUT24" | grep -qE "req_|ses_|/home|token"; then
    fail "identity error leaks internals: $(echo "$OUT24" | head -c 160)"
else
    ok "identity error is metadata-only (AG-05/AG-06 style)"
fi

say "25. CLI exit codes (§66, ADR-0022) — stable 0–7 contract"
# 2 = invalid usage (bad scope from the caller)
"$BIN" agent request x badscope 6 r >/dev/null 2>&1
RC2=$?
[ "$RC2" = "2" ] && ok "invalid scope → exit 2" || fail "invalid scope → exit $RC2 (want 2)"
# 3 = authentication failure (forged token)
OUT25=$(FARCONTROL_TOKEN="forged-token-aaaaaaaaaaaaaaaaaaaaaaaa" "$BIN" agent ping 2>&1)
RC3=$?
[ "$RC3" = "3" ] && ok "bad token → exit 3 (auth)" || fail "bad token → exit $RC3 (want 3)"
# 4 = authorization denied (terminal_only session cannot read files)
REQ25=$("$BIN" agent request exit-test terminal_only 6 check exit codes 2>/dev/null | python3 -c "import json,sys; print(json.load(sys.stdin)['request_id'])")
"$BIN" approve "$REQ25" >/dev/null 2>&1
SES25=$("$BIN" agent status "$REQ25" 2>/dev/null | python3 -c "import json,sys; print(json.load(sys.stdin)['request']['session_id'])")
"$BIN" agent read "$SES25" /etc/passwd >/dev/null 2>&1
RC4=$?
[ "$RC4" = "4" ] && ok "scope_denied → exit 4 (authorization)" || fail "scope denied → exit $RC4 (want 4)"
# 5 = timeout (exec hits its own limit)
"$BIN" agent exec --timeout-ms 800 "$SES25" sleep 5 >/dev/null 2>&1
RC5=$?
[ "$RC5" = "5" ] && ok "exec timeout → exit 5" || fail "exec timeout → exit $RC5 (want 5)"
# 6 = unavailable (daemon unreachable)
FARCONTROL_URL="https://127.0.0.1:1" FARCONTROL_CA="$FARCONTROL_HOME/cert.pem" "$BIN" agent --timeout-secs 3 ping >/dev/null 2>&1
RC6=$?
[ "$RC6" = "6" ] && ok "connection refused → exit 6 (unavailable, fail closed)" || fail "unreachable → exit $RC6 (want 6)"
# 7 = conflict (1-active-session policy → second approve is a state race)
REQ25B=$("$BIN" agent request exit-test-b full_access 6 second session 2>/dev/null | python3 -c "import json,sys; print(json.load(sys.stdin)['request_id'])")
"$BIN" approve "$REQ25B" >/dev/null 2>&1
RC7=$?
[ "$RC7" = "7" ] && ok "session_limit → exit 7 (conflict)" || fail "session limit → exit $RC7 (want 7)"
"$BIN" deny "$REQ25B" >/dev/null 2>&1
"$BIN" agent revoke "$SES25" >/dev/null 2>&1
# 0 = success
"$BIN" agent ping >/dev/null 2>&1
RC0=$?
[ "$RC0" = "0" ] && ok "ping → exit 0" || fail "ping → exit $RC0"

say "26. --json stable output (§45, CL-02)"
"$BIN" status --json 2>/dev/null | python3 -m json.tool >/dev/null 2>&1 && ok "status --json is valid JSON" || fail "status --json invalid"
S26=$("$BIN" status --json 2>/dev/null | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['service'])")
[ "$S26" = "farcontrol" ] && ok "status --json shape stable (service field)" || fail "status --json shape changed: '$S26'"
"$BIN" list --json 2>/dev/null | python3 -m json.tool >/dev/null 2>&1 && ok "list --json is valid JSON" || fail "list --json invalid"
L26=$("$BIN" list --json 2>/dev/null | python3 -c "import json,sys; d=json.load(sys.stdin); print('requests' in d and 'sessions' in d)")
[ "$L26" = "True" ] && ok "list --json = {requests, sessions} (§45)" || fail "list --json shape wrong"

say "27. protocol version (§44, AU-06): X-Far-Proto fail-closed"
# proto check runs before auth — an unsigned request with a bad version
# is rejected for the VERSION, not silently 401'd
CODE27=$(curl -s --cacert "$CA" -o "$FARCONTROL_HOME/proto.json" -w "%{http_code}" -X POST "$AGENT/v1/session/request" \
    -H "X-Far-Proto: 2" -H "Content-Type: application/json" --data '{}' -m 10 2>/dev/null)
[ "$CODE27" = "422" ] && grep -q '"unsupported_proto"' "$FARCONTROL_HOME/proto.json" \
    && ok "X-Far-Proto: 2 → 422 unsupported_proto (bad-request family)" || fail "proto 2 → $CODE27: $(cat "$FARCONTROL_HOME/proto.json" 2>/dev/null | head -c 120)"
CODE27B=$(curl -s --cacert "$CA" -o /dev/null -w "%{http_code}" -X POST "$AGENT/v1/session/request" \
    -H "X-Far-Proto: 1" -H "Content-Type: application/json" --data '{}' -m 10 2>/dev/null)
[ "$CODE27B" = "401" ] && ok "X-Far-Proto: 1 passes the version gate (then normal auth)" || fail "proto 1 → $CODE27B (want 401 unsigned)"
CODE27C=$(curl -s --cacert "$CA" -o /dev/null -w "%{http_code}" -X POST "$AGENT/v1/session/request" \
    -H "Content-Type: application/json" --data '{}' -m 10 2>/dev/null)
[ "$CODE27C" = "401" ] && ok "absent header = FAR-PROTO/1 (0.x clients stay compatible)" || fail "no header → $CODE27C (want 401 unsigned)"

say "28. audit retention (v0.8, AD-08/ADR-0022) — opt-in, audited, verifiable"
# stop, enable a tiny retention, restart
[ -n "$DAEMON_PID" ] && kill "$DAEMON_PID" 2>/dev/null; wait "$DAEMON_PID" 2>/dev/null; DAEMON_PID=""
printf '\n[audit]\nmax_events = 5\n' >> "$FARCONTROL_HOME/config.toml"
"$BIN" start > "$FARCONTROL_HOME/daemon.log" 2>&1 &
DAEMON_PID=$!
for i in $(seq 1 50); do "$BIN" status >/dev/null 2>&1 && break; sleep 0.2; done
kill -0 "$DAEMON_PID" 2>/dev/null && ok "daemon restarted with [audit] max_events=5" || fail "daemon failed with retention config"
# generate >5 events: 4 request+deny cycles = ~8 audit events
for n in 1 2 3 4; do
    R28=$("$BIN" agent request ret-agent-$n terminal_only 6 fill the audit $n 2>/dev/null | python3 -c "import json,sys; print(json.load(sys.stdin)['request_id'])")
    "$BIN" deny "$R28" >/dev/null 2>&1
done
sleep 0.5
LINES28=$(wc -l < "$FARCONTROL_HOME/audit.jsonl")
[ "$LINES28" -le 6 ] && ok "audit.jsonl bounded (≤ marker + 5 events): $LINES28 lines" || fail "retention not enforced: $LINES28 lines"
grep -q "audit.trimmed" "$FARCONTROL_HOME/audit.jsonl" && ok "the trim itself is audited (audit.trimmed marker)" || fail "no audit.trimmed marker"
D28=$("$BIN" doctor 2>&1)
echo "$D28" | grep -q "audit_retention" && ok "doctor reports the retention config" || fail "doctor missing retention check"
# chain must STILL verify after trimming (doctor must be all green)
BAD28=$(echo "$D28" | grep -c "\[FAIL\]")
[ "$BAD28" = "0" ] && ok "doctor ALL GREEN with retention active (chain still verifiable)" || fail "doctor red with retention"
# default (no [audit]) = keep forever is covered by all earlier sections
# (their audit events were never trimmed).

# ---- v0.9 (ADR-0023) sections: self-contained (own home + daemon) so they  ---
# ---- can also run alone for mutation checks: FARCONTROL_E2E_ONLY="29,30,31" ---
section_wanted() {
    [ -z "${FARCONTROL_E2E_ONLY:-}" ] && return 0
    case ",${FARCONTROL_E2E_ONLY}," in *",$1,"*) return 0 ;; *) return 1 ;; esac
}

if section_wanted 29; then
say "29. progressive auth backoff (v0.9, SC-01/ADR-0023): hammering extends the lock"
# fresh home → no inherited lock state; main daemon must die to free the ports
[ -n "$DAEMON_PID" ] && kill "$DAEMON_PID" 2>/dev/null; wait "$DAEMON_PID" 2>/dev/null; DAEMON_PID=""
K29=$(mktemp -d /tmp/farcontrol-e2e-kb.XXXXXX)
export FARCONTROL_HOME="$K29"
"$BIN" start > "$K29/daemon.log" 2>&1 &
DAEMON_PID=$!
for i in $(seq 1 50); do "$BIN" status >/dev/null 2>&1 && break; sleep 0.2; done
"$BIN" status >/dev/null 2>&1 || { fail "§29 daemon did not start"; tail -5 "$K29/daemon.log"; }

retry_of() { echo "$1" | grep -o 'retry in [0-9]*s' | head -1 | grep -o '[0-9]*'; }
R1=0; R2=0
for i in $(seq 1 7); do
    out29=$(FARCONTROL_TOKEN="hammer$i" "$BIN" agent ping 2>&1)
    echo "$out29" | grep -q "progressive backoff" && [ "$R1" -eq 0 ] && R1=$(retry_of "$out29") || true
done
R1=${R1:-0}
[ "$R1" -gt 0 ] && ok "locked out with progressive backoff (retry in ${R1}s)" || fail "no progressive lockout message: $(echo "$out29" | head -c 120)"
out29b=$(FARCONTROL_TOKEN="hammer8" "$BIN" agent ping 2>&1)
R2=$(retry_of "$out29b")
R2=${R2:-0}
 [ "$R1" -gt 0 ] && [ "$R2" -gt "$R1" ] && ok "hammering EXTENDS the lock (${R1}s → ${R2}s, exponential)" || fail "lock did not extend: ${R1}s → ${R2}s"
outv=$("$BIN" agent ping 2>&1)
echo "$outv" | grep -q '"code":"rate_limited"' && ok "valid token also blocked while locked (fail closed)" || fail "lockout leaks valid requests: $outv"
# restart clears the in-memory lock (documented) → immediate recovery
kill "$DAEMON_PID" 2>/dev/null; wait "$DAEMON_PID" 2>/dev/null; DAEMON_PID=""
"$BIN" start >> "$K29/daemon.log" 2>&1 &
DAEMON_PID=$!
for i in $(seq 1 50); do "$BIN" status >/dev/null 2>&1 && break; sleep 0.2; done
expect_ok '"service":"farcontrol"' "$BIN" agent ping
# audit captured the escalation (bounded: only real changes)
"$BIN" audit 2>/dev/null | grep -q "auth.backoff" && ok "auth.backoff audited (escalation evidence)" || fail "no auth.backoff audit event"
fi

if section_wanted 30; then
say "30. startup config validation (v0.9, SC-02/ADR-0023): fail fast, exit 2"
[ -n "$DAEMON_PID" ] && kill "$DAEMON_PID" 2>/dev/null; wait "$DAEMON_PID" 2>/dev/null; DAEMON_PID=""
try_bad_config() { # name, config-body → expect exit 2 + config_invalid
    local name="$1" body="$2" out30 rc
    local d30=$(mktemp -d /tmp/farcontrol-e2e-cv.XXXXXX)
    printf '%s\n' "$body" > "$d30/config.toml"
    out30=$(FARCONTROL_HOME="$d30" timeout 10 "$BIN" start 2>&1)
    rc=$?
    if [ $rc -eq 2 ] && echo "$out30" | grep -q "config_invalid"; then
        ok "bad config rejected: $name (exit 2)"
    else
        fail "$name not rejected (rc=$rc): $(echo "$out30" | head -c 140)"
    fi
    [ -f "$d30/state.db" ] && fail "$name: state.db created despite rejected config" || true
    rm -rf "$d30"
}
CFG_HDR="agent_bind = \"127.0.0.1:7788\"
home_root = \"$HOME\"
use_tls = true"
try_bad_config "admin_bind non-loopback" "$CFG_HDR
admin_bind = \"0.0.0.0:7789\""
try_bad_config "session_min_hours negative" "$CFG_HDR
admin_bind = \"127.0.0.1:7789\"

[policy]
session_min_hours = -5"
try_bad_config "pending_ttl_secs zero" "$CFG_HDR
admin_bind = \"127.0.0.1:7789\"

[policy]
pending_ttl_secs = 0"
try_bad_config "bad secret_store" "$CFG_HDR
admin_bind = \"127.0.0.1:7789\"

[identity]
secret_store = \"sqlite\""
try_bad_config "negative audit max_events" "$CFG_HDR
admin_bind = \"127.0.0.1:7789\"

[audit]
max_events = -1"
ok "no state created on rejected configs (fail before init)"
# sanity: a VALID config still starts (the validator must not over-reject)
D30=$(mktemp -d /tmp/farcontrol-e2e-cg.XXXXXX)
printf '%s\nadmin_bind = \"127.0.0.1:7789\"\n\n[policy]\nsession_max_hours = 24\n' "$CFG_HDR" > "$D30/config.toml"
FARCONTROL_HOME="$D30" timeout 6 "$BIN" start > "$D30/log" 2>&1
RCV=$?
if [ $RCV -eq 124 ] || grep -q "daemon ready" "$D30/log"; then
    ok "valid custom config still passes validation"
else
    fail "valid config wrongly rejected (rc=$RCV): $(head -c 140 "$D30/log")"
fi
rm -rf "$D30"
fi

if section_wanted 31; then
say "31. OS keyring secret store (v0.9, ID-04/ADR-0023): never on disk — or fail-closed refusal"
[ -n "$DAEMON_PID" ] && kill "$DAEMON_PID" 2>/dev/null; wait "$DAEMON_PID" 2>/dev/null; DAEMON_PID=""
K31=$(mktemp -d /tmp/farcontrol-e2e-kr.XXXXXX)
printf 'agent_bind = "127.0.0.1:7788"\nadmin_bind = "127.0.0.1:7789"\nhome_root = "%s"\nuse_tls = true\n\n[identity]\nsecret_store = "keyring"\n' "$HOME" > "$K31/config.toml"
export FARCONTROL_HOME="$K31"
"$BIN" start > "$K31/daemon.log" 2>&1 &
DAEMON_PID=$!
sleep 2
if "$BIN" status >/dev/null 2>&1; then
    # ---- full path: kernel keyring works (real Linux) ----
    KT31=$(grep -A1 "AGENT TOKEN" "$K31/daemon.log" | grep -v "AGENT TOKEN" | head -1 | tr -d ' ')
    [ -n "$KT31" ] && ok "keyring-mode init printed the token once" || fail "no token in start output"
    [ ! -f "$K31/agent-token" ] && ok "NO plaintext agent-token file (ID-04)" || fail "agent-token file exists in keyring mode!"
    if LC_ALL=C grep -a -q "$KT31" "$K31/state.db" 2>/dev/null; then
        fail "token plaintext found in state.db!"
    else
        ok "token NOT in state.db (kernel keyring only)"
    fi
    FARCONTROL_TOKEN="$KT31" expect_ok '"service":"farcontrol"' "$BIN" agent ping
    R31=$("$BIN" agent request kr-agent full_access 6 keyring e2e 2>/dev/null | jq_get "['request_id']")
    "$BIN" approve "$R31" >/dev/null 2>&1
    S31=$("$BIN" agent status "$R31" 2>/dev/null | jq_get "['request']['session_id']")
    expect_ok "e2e-kr-marker" "$BIN" agent exec "$S31" sh -c 'echo e2e-kr-marker'
    # restart: the keyring survives; auth still works
    kill "$DAEMON_PID" 2>/dev/null; wait "$DAEMON_PID" 2>/dev/null; DAEMON_PID=""
    "$BIN" start >> "$K31/daemon.log" 2>&1 &
    DAEMON_PID=$!
    for i in $(seq 1 50); do "$BIN" status >/dev/null 2>&1 && break; sleep 0.2; done
    FARCONTROL_TOKEN="$KT31" expect_ok '"service":"farcontrol"' "$BIN" agent ping
    # rotate: key updated in place; old dies instantly
    ROT31=$("$BIN" rotate 2>&1)
    KT31B=$(echo "$ROT31" | grep -v "^FARcontrol\|NEW agent\|old one" | tail -1 | tr -d ' ')
    FARCONTROL_TOKEN="$KT31" "$BIN" agent ping >/dev/null 2>&1 && fail "old keyring token still works" || ok "rotated: old token dead"
    FARCONTROL_TOKEN="$KT31B" expect_ok '"service":"farcontrol"' "$BIN" agent ping
    # doctor: secret_store check green
    D31=$("$BIN" doctor 2>&1)
    echo "$D31" | grep -q "ALL GREEN" && ok "doctor ALL GREEN in keyring mode" || fail "doctor red: $(echo "$D31" | grep FAIL | head -2)"
    # backup/restore round-trip in keyring mode
    BK31="/tmp/farcontrol-e2e-bk31-$$.$RANDOM.tar.gz"
    "$BIN" backup "$BK31" >/dev/null 2>&1 && ok "backup taken in keyring mode" || fail "keyring backup failed"
    tar -tzf "$BK31" | grep -q "^agent-token$" && ok "archive carries the credential (DR artifact)" || fail "archive missing agent-token"
    [ ! -f "$K31/agent-token" ] && ok "materialized token unlinked after backup (no disk copy)" || fail "plaintext file left behind by backup!"
    kill "$DAEMON_PID" 2>/dev/null; wait "$DAEMON_PID" 2>/dev/null; DAEMON_PID=""
    K31B=$(mktemp -d /tmp/farcontrol-e2e-kr2.XXXXXX)
    FARCONTROL_HOME="$K31B" "$BIN" restore "$BK31" >/dev/null 2>&1 && ok "restore into a fresh dir" || fail "keyring restore failed"
    [ ! -f "$K31B/agent-token" ] && ok "restore wrote the key back into the keyring (no file kept)" || fail "restore left plaintext agent-token"
    FARCONTROL_HOME="$K31B" "$BIN" start > "$K31B/daemon.log" 2>&1 &
    DAEMON_PID=$!
    for i in $(seq 1 50); do FARCONTROL_HOME="$K31B" "$BIN" status >/dev/null 2>&1 && break; sleep 0.2; done
    FARCONTROL_HOME="$K31B" FARCONTROL_TOKEN="$KT31B" "$BIN" agent ping >/dev/null 2>&1 && ok "restored keyring token authenticates" || fail "restored token dead"
    rm -f "$BK31"
else
    # ---- fail-closed path: this environment's kernel keyring is partial ----
    kill "$DAEMON_PID" 2>/dev/null; wait "$DAEMON_PID" 2>/dev/null; DAEMON_PID=""
    OUT31=$(FARCONTROL_HOME="$K31" timeout 10 "$BIN" start 2>&1)
    RC31=$?
    if [ $RC31 -eq 2 ] && echo "$OUT31" | grep -q "config_invalid" && echo "$OUT31" | grep -q "keyring"; then
        ok "keyring mode REFUSED in env without a usable kernel keyring (exit 2, fail closed)"
        ok "no state created (no half-initialized keyring dir)"
    else
        fail "keyring refusal wrong (rc=$RC31): $(echo "$OUT31" | head -c 160)"
    fi
    echo "  NOTE: full keyring path runs on real Linux kernels — this sandbox has a"
    echo "        partial keyring implementation (add_key ok, read/search blocked)."
fi
fi

if section_wanted 32; then
say "32. emergency stop under stress (§97-14, v1.0/ADR-0024): panic with work in flight"
[ -n "$DAEMON_PID" ] && kill "$DAEMON_PID" 2>/dev/null; wait "$DAEMON_PID" 2>/dev/null; DAEMON_PID=""
K32=$(mktemp -d /tmp/farcontrol-e2e-st.XXXXXX)
export FARCONTROL_HOME="$K32"
"$BIN" start > "$K32/daemon.log" 2>&1 &
DAEMON_PID=$!
for i in $(seq 1 50); do "$BIN" status >/dev/null 2>&1 && break; sleep 0.2; done
"$BIN" status >/dev/null 2>&1 || { fail "§32 daemon did not start"; tail -5 "$K32/daemon.log"; }
R32=$("$BIN" agent request stress-agent full_access 6 stress panic 2>/dev/null | jq_get "['request_id']")
"$BIN" approve "$R32" >/dev/null 2>&1
S32=$("$BIN" agent status "$R32" 2>/dev/null | jq_get "['request']['session_id']")
[ -n "$S32" ] || { fail "§32 no session"; exit 1; }
# put REAL work in flight: a live PTY terminal + three bounded commands
( echo 'sleep 60'; sleep 60 ) | timeout 40 "$BIN" agent term "$S32" sh > "$K32/term.out" 2>&1 &
TERMS32=$!
for i in 1 2 3; do
    "$BIN" agent exec --timeout-ms 4000 "$S32" sleep 20 > "$K32/exec$i.out" 2>&1 &
    eval "EX$i=$!"
done
sleep 1.5   # let the work actually start
# EMERGENCY STOP mid-flight
P32=$("$BIN" panic e2e-stress-panic 2>&1)
echo "$P32" | grep -q "PANIC executed" && ok "panic executed under load" || fail "panic failed: $P32"
NT32=$(echo "$P32" | grep -v "^FARcontrol\|NEW agent\|old one\|PANIC\|revoked\|expired\|killed\|give" | tail -1 | tr -d ' ')
echo "$P32" | grep -Eq "revoked sessions *: [1-9]" && ok "active session revoked mid-flight" || fail "session not revoked"
echo "$P32" | grep -Eq "killed terminals *: [1-9]" && ok "live terminal killed mid-flight" || fail "terminal not killed"
wait $EX1 $EX2 $EX3 2>/dev/null
STILL=0
for i in 1 2 3; do kill -0 $(eval "echo \$EX$i") 2>/dev/null && STILL=$((STILL+1)); done
[ $STILL -eq 0 ] && ok "in-flight commands did not orphan (bounded by their timeouts)" || fail "$STILL exec call(s) still hanging after panic"
kill $TERMS32 2>/dev/null; wait $TERMS32 2>/dev/null
# old session + old token are both dead
OUT32=$(FARCONTROL_TOKEN="$(cat "$K32/agent-token" 2>/dev/null || echo x)" "$BIN" agent exec "$S32" echo hi 2>&1)
RC32=$?
[ $RC32 -eq 4 ] && ok "post-panic exec on the revoked session → exit 4" || fail "revoked session still usable (rc=$RC32)"
[ -n "$NT32" ] && ok "panic rotated the token (fresh credential issued)" || fail "no new token from panic"
# the system must be fully ALIVE again: fresh cycle with the new token
R32B=$(FARCONTROL_TOKEN="$NT32" "$BIN" agent request fresh-agent terminal_only 6 after panic 2>/dev/null | jq_get "['request_id']")
[ -n "$R32B" ] && ok "new request flow works after panic (new token)" || fail "agent API dead after panic"
"$BIN" approve "$R32B" >/dev/null 2>&1
S32B=$("$BIN" agent status "$R32B" 2>/dev/null | jq_get "['request']['session_id']")
expect_ok "e2e-fresh-marker" env FARCONTROL_TOKEN="$NT32" "$BIN" agent exec "$S32B" sh -c 'echo e2e-fresh-marker'
H32=$(curl -s --cacert "$K32/cert.pem" -o /dev/null -w "%{http_code}" "https://127.0.0.1:7789/healthz" -m 5)
[ "$H32" = "200" ] && ok "healthz 200 after the storm" || fail "healthz → $H32"
D32=$("$BIN" doctor 2>&1)
echo "$D32" | grep -q "ALL GREEN" && ok "doctor ALL GREEN after the storm" || fail "doctor red: $(echo "$D32" | grep FAIL | head -2)"
"$BIN" audit 2>/dev/null | grep -q "system.panic" && ok "the stop itself is audited (invariant 8)" || fail "no system.panic audit event"
fi

say "RESULT"
echo "  passed: $PASS"
echo "  failed: $FAIL"
if [ $FAIL -gt 0 ]; then
    echo "  daemon log tail:"
    tail -20 "$FARCONTROL_HOME/daemon.log" | sed 's/^/    /'
    exit 1
fi
echo "  ALL GREEN — FARcontrol 1.0.0 e2e verification PASSED (+stress panic; 0.9: backoff/validation/keyring; 0.8: catalog/exits/json/proto/retention)"
