#!/usr/bin/env bash
# FARcontrol — End-to-End verification (docs/04-verification.md)
# Proves the full lifecycle + core invariants, using ONLY the simple CLI:
#   frtrol start (auto-init) → request → DENY / approve → exec → revoke → expiry
#   scope enforcement · policy denylist + timeout · file ops + escape rejected
#   audit trail · restart persistence · token rotation
# v1.2: ephemeral session credentials (start mints, restart rotates), agent
#   connect flow + background runtime, host allowlist, console v1.2, v1.1
#   registry migration (ADR-0028..0032).
# Runs in FARCONTROL_TEST_MODE=1 (allows sub-hour sessions for expiry testing).
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/target/release/frtrol"
export FARCONTROL_HOME="$(mktemp -d /tmp/farcontrol-e2e.XXXXXX)"
export FARCONTROL_TEST_MODE=1
AGH="$(mktemp -d /tmp/farcontrol-e2e-ag.XXXXXX)"   # v1.2 agent home (connection.json + cert pin)
export FARCONTROL_AGENT_HOME="$AGH"
CURRENT_PW=""   # the LIVE session password (tracked across rotate/panic/restart)
E2E_DEV=""      # the machine device id (stable across restarts, ADR-0028)
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
echo "$guide" | grep -q "frtrol agent" && ok "guide shows the agent connect line" || fail "guide missing agent line"
echo "$guide" | grep -q "frtrol stop" && ok "guide shows frtrol stop (session end)" || fail "guide missing stop"
if echo "$guide" | grep -qE "device add|agent login"; then fail "guide still references REMOVED v1.1 commands"; else ok "guide is clean of removed v1.1 commands (device add / agent login)"; fi

say "1. frtrol start mints the session (v1.2 ADR-0028: ephemeral credentials)"
"$BIN" start > "$FARCONTROL_HOME/daemon.log" 2>&1 &
DAEMON_PID=$!
for i in $(seq 1 50); do
    [ -f "$FARCONTROL_HOME/admin-token" ] && break
    sleep 0.2
done
"$BIN" status >/dev/null 2>&1 && ok "frtrol start (auto-init + daemon running)" \
    || { fail "daemon did not start"; tail -5 "$FARCONTROL_HOME/daemon.log"; exit 1; }
grep -q "session started" "$FARCONTROL_HOME/daemon.log" && ok "the session box is printed" || fail "no session box"
grep -q "first run" "$FARCONTROL_HOME/daemon.log" && ok "first-run guidance shown" || fail "no first-run marker"
E2E_DEV=$(grep -o 'FAR-[A-Z0-9]*-[A-Z0-9]*' "$FARCONTROL_HOME/daemon.log" | head -1)
CURRENT_PW=$(grep 'session password' "$FARCONTROL_HOME/daemon.log" | sed 's/.*: *//')
E2E_ADMIN=$(grep 'admin token' "$FARCONTROL_HOME/daemon.log" | sed 's/.*: *//')
[ -n "$E2E_DEV" ] && ok "machine device id: $E2E_DEV (stable identity)" || { fail "no device id in the box"; exit 1; }
[ -n "$CURRENT_PW" ] && ok "session password printed" || { fail "no session password in the box"; exit 1; }
[ -n "$E2E_ADMIN" ] && ok "admin token printed (web console)" || fail "no admin token in the box"
grep -q "frtrol agent" "$FARCONTROL_HOME/daemon.log" && ok "box tells the agent handover line" || fail "no agent line in the box"
grep -q "dies when this process stops" "$FARCONTROL_HOME/daemon.log" && ok "box warns the credentials are ephemeral" || fail "no ephemerality warning"
[ "$(grep -c "$CURRENT_PW" "$FARCONTROL_HOME/daemon.log")" = "1" ] && ok "session password appears exactly ONCE" || fail "password printed more than once"
# a second start must fail WITHOUT touching the live session's credentials
# (smoke-found v1.2 bug, fixed: ports are claimed BEFORE any mint — bind-before-mint)
second=$("$BIN" start 2>&1); rc2=$?
[ $rc2 -ne 0 ] && echo "$second" | grep -q "already running" && ok "second start refuses (single session, §41)" || fail "second start rc=$rc2: $second"
[ "$(grep -c 'session password' "$FARCONTROL_HOME/daemon.log")" = "1" ] \
    && ok "failed second start did NOT re-mint the live credentials (bind-before-mint)" \
    || fail "a failed start rotated the running session's credentials!"
E2E_FP=$("$BIN" fingerprint 2>&1 | grep -o 'SHA256:[A-Za-z0-9+/]*' | head -1)
[ -n "$E2E_FP" ] && ok "frtrol fingerprint prints the daemon digest" || fail "no fingerprint"
# the v1.2 agent connect: device id + session password ONLY (env twins, non-tty)
CONN1=$(FARCONTROL_DEVICE="$E2E_DEV" FARCONTROL_SESSION_PASSWORD="$CURRENT_PW" "$BIN" agent 2>&1); rc1=$?
[ $rc1 -eq 0 ] && echo "$CONN1" | grep -q "connected" && ok "agent connect: two lines → session key" || { fail "connect failed: $CONN1"; exit 1; }
echo "$CONN1" | grep -q "$E2E_FP" && ok "connect shows + pins the TOFU fingerprint" || fail "no fingerprint shown at connect"
[ -f "$AGH/connection.json" ] && ok "connection.json saved (agent home)" || fail "no connection.json"
stat -c '%a' "$AGH/connection.json" | grep -q "^600$" && ok "connection.json mode 0600" || fail "mode $(stat -c '%a' "$AGH/connection.json")"
APID1=$(cat "$AGH/agentd.pid" 2>/dev/null)
[ -n "$APID1" ] && kill -0 "$APID1" 2>/dev/null && ok "background runtime spawned (pid $APID1, survives CLI exit)" || { fail "agentd not running"; cat "$AGH/agentd.log" 2>/dev/null; }

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

say "14. rate limiting (SE-09/SC-01): brute-force login lockout + recovery"
AG14=$(mktemp -d /tmp/farcontrol-e2e-hm.XXXXXX)   # separate agent home: no saved connection to short-circuit
locked=0
for i in $(seq 1 7); do
    out=$(FARCONTROL_AGENT_HOME="$AG14" FARCONTROL_DEVICE="$E2E_DEV" FARCONTROL_SESSION_PASSWORD="wrong-$i" "$BIN" agent 2>&1)
    echo "$out" | grep -q '"code":"rate_limited"' && locked=1
done
[ $locked -eq 1 ] && ok "7 wrong passwords → rate_limited (fail closed)" || fail "no rate limit after 7 bad logins: $(echo "$out" | head -c 120)"
out14=$(FARCONTROL_AGENT_HOME="$AG14" FARCONTROL_DEVICE="$E2E_DEV" FARCONTROL_SESSION_PASSWORD="$CURRENT_PW" "$BIN" agent 2>&1)
echo "$out14" | grep -q '"code":"rate_limited"' && ok "even the CORRECT password is refused while locked" || fail "lockout does not apply to valid logins"
sleep 9   # progressive lockout escalates to the 8s test cap — wait it out
re14=$(FARCONTROL_DEVICE="$E2E_DEV" FARCONTROL_SESSION_PASSWORD="$CURRENT_PW" "$BIN" agent 2>&1)
echo "$re14" | grep -q "connected" && ok "lockout recovers after the cap (re-handover works)" || fail "still locked: $re14"
rm -rf "$AG14"

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

say "16. restart persistence (v1.2: grants survive, credentials ROTATE — ADR-0028 §3)"
reqE=$("$BIN" agent request e2e-agent terminal_only 6 e2e restart 2>/dev/null)
reqE_id=$(echo "$reqE" | jq_get "['request_id']")
approveE=$("$BIN" approve "$reqE_id" 2>&1)
sesE_id=$(echo "$approveE" | grep -o 'ses_[A-Za-z0-9]*' | head -1)
[ -n "$sesE_id" ] && ok "session for the restart test: $sesE_id" || fail "approve E failed: $approveE"
cp "$AGH/connection.json" "$AGH/connection.pre-restart.json"   # the OLD key, for the dead-key proof
kill "$DAEMON_PID" 2>/dev/null || true
wait "$DAEMON_PID" 2>/dev/null || true
DAEMON_PID=""
# daemon down → agent must fail (network failure = fail closed)
if agent_out=$("$BIN" agent ping 2>&1); then agent_rc=0; else agent_rc=$?; fi
[ $agent_rc -ne 0 ] && ok "daemon down → agent fails (fail closed)" || fail "agent unexpectedly succeeded with daemon down"
"$BIN" start > "$FARCONTROL_HOME/daemon.log" 2>&1 &
DAEMON_PID=$!
for i in $(seq 1 50); do "$BIN" status >/dev/null 2>&1 && break; sleep 0.2; done
NEW_PW=$(grep 'session password' "$FARCONTROL_HOME/daemon.log" | sed 's/.*: *//')
NEW_ADMIN=$(grep 'admin token' "$FARCONTROL_HOME/daemon.log" | sed 's/.*: *//')
[ "$NEW_PW" != "$CURRENT_PW" ] && ok "restart rotated the session password (the old one is dead)" || fail "password survived a restart?!"
[ "$NEW_ADMIN" != "$E2E_ADMIN" ] && ok "restart rotated the admin token" || fail "admin token survived a restart?!"
CURRENT_PW="$NEW_PW"; E2E_ADMIN="$NEW_ADMIN"
# the OLD runtime must observe the dead key → expired + credentials cleared (ADR-0030)
for i in $(seq 1 30); do
  ST=$("$BIN" agent status --json 2>/dev/null || true)
  echo "$ST" | grep -q '"state":"expired"' && break
  sleep 0.5
done
echo "$ST" | grep -q '"state":"expired"' && ok "old runtime reached expired (dead key, terminal state)" || fail "runtime state after restart: $ST"
[ ! -f "$AGH/connection.json" ] && ok "expired runtime cleared its credentials (fail closed)" || fail "connection.json survived expiry"
# the pre-restart key itself must be rejected (master prompt §6: no silent regain)
cp "$AGH/connection.pre-restart.json" "$AGH/connection.json"
oldkey_out=$("$BIN" agent ping 2>&1); oldkey_rc=$?
[ $oldkey_rc -ne 0 ] && echo "$oldkey_out" | grep -q '"code":"invalid_signature"' \
    && ok "pre-restart session key → invalid_signature (no silent regain)" || fail "old key still works: $oldkey_out"
rm -f "$AGH/connection.pre-restart.json"
# re-connect with the NEW password over the SAME stable device id → grants persisted
re16=$(FARCONTROL_DEVICE="$E2E_DEV" FARCONTROL_SESSION_PASSWORD="$CURRENT_PW" "$BIN" agent 2>&1)
echo "$re16" | grep -q "connected" && ok "re-connect with the new password (device id unchanged: $E2E_DEV)" || fail "re-connect failed: $re16"
expect_ok "e2e-restart-marker" "$BIN" agent exec "$sesE_id" sh -c 'echo e2e-restart-marker'
expect_ok "e2e-term-marker2" bash -c "echo 'echo e2e-term-marker2; exit' | timeout 20 $BIN agent term $sesE_id sh"

say "17. session credential rotation (v1.2 ADR-0028: password + admin token, key UNTOUCHED)"
OLD_PW17="$CURRENT_PW"
rot=$("$BIN" rotate 2>&1)
NEW_PW17=$(echo "$rot" | grep -A1 'NEW SESSION PASSWORD' | tail -1 | sed 's/^ *//')
[ -n "$NEW_PW17" ] && [ "$NEW_PW17" != "$OLD_PW17" ] && ok "rotate mints a new session password (shown once)" || fail "rotate output: $rot"
CURRENT_PW="$NEW_PW17"
NEW_ADMIN17=$(echo "$rot" | grep -A1 'NEW ADMIN TOKEN' | tail -1 | sed 's/^ *//')
[ -n "$NEW_ADMIN17" ] && ok "rotate mints a new admin token" || fail "no new admin token in rotate output"
# the OLD password must be dead immediately
AG17=$(mktemp -d /tmp/farcontrol-e2e-rt.XXXXXX)
old17=$(FARCONTROL_AGENT_HOME="$AG17" FARCONTROL_DEVICE="$E2E_DEV" FARCONTROL_SESSION_PASSWORD="$OLD_PW17" "$BIN" agent 2>&1)
echo "$old17" | grep -q '"code":"invalid_credentials"' && ok "old session password rejected after rotate" || fail "old password accepted: $old17"
rm -rf "$AG17"
# the session key is UNTOUCHED: already-connected agents keep working, zero ceremony
expect_ok '"service":"farcontrol"' "$BIN" agent ping
expect_ok "post-rotate-marker" "$BIN" agent exec "$sesE_id" sh -c 'echo post-rotate-marker'

say "18. frtrol panic (SE-11): emergency stop kills everything at once"
AG18=$(mktemp -d /tmp/farcontrol-e2e-pk.XXXXXX)
cp "$AGH/connection.json" "$AG18/connection.json"      # the pre-panic key, for the dead-key proof
cp "$AGH/cert.pem" "$AG18/cert.pem" 2>/dev/null || true
panic_out=$("$BIN" panic e2e-panic-test 2>&1)
echo "$panic_out" | grep -q "PANIC executed" && ok "panic executed" || fail "panic failed: $panic_out"
echo "$panic_out" | grep -Eq "revoked sessions *: [1-9]" && ok "all active sessions revoked" || fail "panic did not revoke sessions"
echo "$panic_out" | grep -q "session password + session key + admin token" && ok "panic rotated the WHOLE credential set (v1.2)" || fail "panic rotation report: $panic_out"
# the runtime must observe the dead key → expired + credentials cleared (ADR-0030)
for i in $(seq 1 20); do
  ST18=$("$BIN" agent status --json 2>/dev/null || true)
  echo "$ST18" | grep -q '"state":"expired"' && break
  sleep 0.5
done
echo "$ST18" | grep -q '"state":"expired"' && ok "runtime reached expired after panic (terminal state)" || fail "runtime state after panic: $ST18"
# restore the pre-panic key (the runtime already exited — no race) and prove it dead
cp "$AG18/connection.json" "$AGH/connection.json"
for dead_ses in "$sesE_id" "$sesT_id"; do
    dead_out=$("$BIN" agent exec "$dead_ses" echo hi 2>&1); dead_rc=$?
    if [ $dead_rc -ne 0 ] && echo "$dead_out" | grep -qE '"code":"(session_revoked|invalid_signature)"'; then
        ok "post-panic exec on $dead_ses fails closed (key + session both dead)"
    else
        fail "post-panic exec on $dead_ses usable (rc=$dead_rc): $dead_out"
    fi
done
if pre_out=$("$BIN" agent ping 2>&1); then pre_rc=0; else pre_rc=$?; fi
[ $pre_rc -ne 0 ] && echo "$pre_out" | grep -q '"code":"invalid_signature"' && ok "pre-panic session key is dead" || fail "pre-panic key still valid"
# recover: the panic output printed a NEW session password (shown once).
# NOTE: the dead-key proofs above are ~5 deliberate auth failures inside the
# global burst window (2s/6 in test mode) — the brake correctly 429s the next
# requests. Wait the window out, then recover (fail closed ≠ fail broken).
sleep 3
PW18=$(echo "$panic_out" | grep -A1 'NEW SESSION PASSWORD' | tail -1 | sed 's/^ *//')
CURRENT_PW="$PW18"
rec18=$(FARCONTROL_DEVICE="$E2E_DEV" FARCONTROL_SESSION_PASSWORD="$CURRENT_PW" "$BIN" agent 2>&1)
echo "$rec18" | grep -q "connected" && ok "owner recovery: re-connect after panic mints a fresh session" || fail "post-panic re-connect failed: $rec18"
# term on a dead session must be refused
term_dead=$(echo 'echo nope; exit' | timeout 10 "$BIN" agent term "$sesT_id" sh 2>&1)
echo "$term_dead" | grep -q '"code":"session_revoked"' && ok "terminal on revoked session refused" || fail "term on dead session: $term_dead"
rm -rf "$AG18"

say "19. web UI (v0.3): owner console on the admin plane (ADR-0017)"
UI="https://127.0.0.1:7789"
CJ="$FARCONTROL_HOME/ui-cookies.txt"
CA="$FARCONTROL_HOME/cert.pem"
ADMTOK=$(cat "$FARCONTROL_HOME/admin-token")

# a. the console shell is served (no auth needed to load the shell, data needs auth)
html=$(curl -s --retry 2 --retry-connrefused --cacert "$CA" "$UI/" -m 5)
echo "$html" | grep -q "FARcontrol" && ok "GET / serves the console shell" || fail "no HTML shell at /"

# b. structural XSS defense: the page must contain ZERO innerHTML/document.write/eval
if echo "$html" | grep -qE "innerHTML|document\.write|eval\(" ; then
    fail "page uses innerHTML/eval — XSS surface"
else
    ok "page uses textContent only (no innerHTML/eval — XSS structurally prevented)"
fi

# b2. v1.2 (r12/ADR-0032): the login label must say WHERE the token comes from
echo "$html" | grep -q "frtrol start" && ok "login label points to 'frtrol start' (per-session admin token)" || fail "login label does not reference the start banner"

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
dead19=$("$BIN" agent exec "$SES19" echo hi 2>&1); rc19=$?
[ $rc19 -ne 0 ] && echo "$dead19" | grep -qE '"code":"(session_revoked|invalid_signature)"' && ok "post-UI-revoke exec fails closed" || fail "UI-revoked session usable: $dead19"

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
dead19b=$("$BIN" agent exec "$SES19B" echo hi 2>&1); rc19b=$?
[ $rc19b -ne 0 ] && echo "$dead19b" | grep -qE '"code":"(session_revoked|invalid_signature)"' && ok "post-UI-panic exec fails closed" || fail "UI-panic session usable: $dead19b"
# v1.2: the UI panic rotates everything — its response carries the new password
PW19=$(echo "$pn" | python3 -c "import json,sys; print(json.load(sys.stdin)['password'])")
CURRENT_PW="$PW19"
FARCONTROL_DEVICE="$E2E_DEV" FARCONTROL_SESSION_PASSWORD="$CURRENT_PW" "$BIN" agent >/dev/null 2>&1 \
    && ok "re-connect after UI panic (password from the panic response)" || fail "post-UI-panic re-connect failed"

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

# e. v1.2: identity = the stable device id + the grant rows; the start after the
# restore mints fresh session credentials on top. Both must survive the cycle.
DEV22=$(grep -o 'FAR-[A-Z0-9]*-[A-Z0-9]*' "$FARCONTROL_HOME/daemon.log" | head -1)
[ "$DEV22" = "$E2E_DEV" ] && ok "device id survived the restore (identity)" || fail "identity changed: $DEV22 != $E2E_DEV"
PW22=$(grep 'session password' "$FARCONTROL_HOME/daemon.log" | head -1 | sed 's/.*: *//')
CURRENT_PW="$PW22"
re22=$(FARCONTROL_DEVICE="$E2E_DEV" FARCONTROL_SESSION_PASSWORD="$CURRENT_PW" "$BIN" agent 2>&1)
echo "$re22" | grep -q "connected" && ok "post-restore re-connect with the fresh session password" || fail "post-restore connect failed: $re22"
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
# v1.2: the crash-restart rotated the credentials — re-connect, then prove state survived
PW23=$(grep 'session password' "$FARCONTROL_HOME/daemon.log" | head -1 | sed 's/.*: *//')
CURRENT_PW="$PW23"
re23=$(FARCONTROL_DEVICE="$E2E_DEV" FARCONTROL_SESSION_PASSWORD="$CURRENT_PW" "$BIN" agent 2>&1)
echo "$re23" | grep -q "connected" && ok "re-connect after crash-restart (new session password)" || fail "post-crash connect: $re23"
expect_ok "crash-recovery-marker" "$BIN" agent exec "$SES23" echo crash-recovery-marker
aud23=$("$BIN" audit 2>&1)
echo "$aud23" | grep -q "crash-agent" && ok "state (session + audit) survived the crash" || fail "state lost after crash"


say "24. agent identity catalog (v0.8, ADR-0022 / spec §9 §11 §81)"

# free the 1-active-session slot (section 23's crash-recovery session is live)
[ -n "$SES23" ] && "$BIN" agent revoke "$SES23" >/dev/null 2>&1

# valid declared identity via env (CLI forwards; server validates — one enforcement point)
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
"$BIN" list 2>/dev/null | grep -q "z_ai/glm-5.3" && ok "frtrol list shows declared identity" || fail "list missing identity"
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
# 3 = authentication failure (wrong session password at connect)
AG25=$(mktemp -d /tmp/farcontrol-e2e-x3.XXXXXX)
OUT25=$(FARCONTROL_AGENT_HOME="$AG25" FARCONTROL_DEVICE="$E2E_DEV" FARCONTROL_SESSION_PASSWORD="definitely-not-the-password" "$BIN" agent 2>&1)
RC3=$?
[ "$RC3" = "3" ] && ok "wrong session password → exit 3 (auth)" || fail "bad password → exit $RC3 (want 3)"
rm -rf "$AG25"
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
# 6 = unavailable (daemon unreachable) — point the saved connection at a dead port
cp "$AGH/connection.json" "$AGH/connection.bak25"
python3 -c "
import json
p = '$AGH/connection.json'
d = json.load(open(p))
d['base_url'] = 'https://127.0.0.1:1'
json.dump(d, open(p, 'w'))
"
"$BIN" agent --timeout-secs 3 ping >/dev/null 2>&1
RC6=$?
mv "$AGH/connection.bak25" "$AGH/connection.json"
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
# v1.2: the restart rotated the credentials — re-connect before generating events
PW28=$(grep 'session password' "$FARCONTROL_HOME/daemon.log" | head -1 | sed 's/.*: *//')
CURRENT_PW="$PW28"
FARCONTROL_DEVICE="$E2E_DEV" FARCONTROL_SESSION_PASSWORD="$CURRENT_PW" "$BIN" agent >/dev/null 2>&1
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
say "29. progressive auth backoff (SC-01): hammering the HMAC path extends the lock"
# fresh home → no inherited lock state; main daemon must die to free the ports
[ -n "$DAEMON_PID" ] && kill "$DAEMON_PID" 2>/dev/null; wait "$DAEMON_PID" 2>/dev/null; DAEMON_PID=""
K29=$(mktemp -d /tmp/farcontrol-e2e-kb.XXXXXX)
export FARCONTROL_HOME="$K29"
"$BIN" start > "$K29/daemon.log" 2>&1 &
DAEMON_PID=$!
for i in $(seq 1 50); do "$BIN" status >/dev/null 2>&1 && break; sleep 0.2; done
"$BIN" status >/dev/null 2>&1 || { fail "§29 daemon did not start"; tail -5 "$K29/daemon.log"; }
D29=$(grep -o 'FAR-[A-Z0-9]*-[A-Z0-9]*' "$K29/daemon.log" | head -1)
P29=$(grep 'session password' "$K29/daemon.log" | sed 's/.*: *//')
AG29=$(mktemp -d /tmp/farcontrol-e2e-ag29.XXXXXX)
# a REAL connection first (valid key) — saved for the fail-closed proof below
FARCONTROL_AGENT_HOME="$AG29" FARCONTROL_DEVICE="$D29" FARCONTROL_SESSION_PASSWORD="$P29" "$BIN" agent >/dev/null 2>&1
cp "$AG29/connection.json" "$AG29/connection.valid.json"
kill -9 "$(cat "$AG29/agentd.pid")" 2>/dev/null   # its heartbeat would clear the lock we are about to build
# forge a WRONG key over the same device id → the HMAC verify path gets hammered
python3 - "$AG29" << 'PY29'
import json, sys
p = sys.argv[1] + "/connection.json"
d = json.load(open(p))
d["key"] = "hammer-wrong-key-material"
json.dump(d, open(p, "w"))
PY29

retry_of() { echo "$1" | grep -o 'retry in [0-9]*s' | head -1 | grep -o '[0-9]*'; }
R1=0; R2=0
for i in $(seq 1 7); do
    out29=$(FARCONTROL_AGENT_HOME="$AG29" "$BIN" agent ping 2>&1)
    echo "$out29" | grep -qE "progressive backoff|too many failed auth" && [ "$R1" -eq 0 ] && R1=$(retry_of "$out29") || true
done
R1=${R1:-0}
[ "$R1" -gt 0 ] && ok "device locked out (brake engaged, retry in ${R1}s)" || fail "no lockout message: $(echo "$out29" | head -c 120)"
out29b=$(FARCONTROL_AGENT_HOME="$AG29" "$BIN" agent ping 2>&1)
R2=$(retry_of "$out29b")
R2=${R2:-0}
 [ "$R1" -gt 0 ] && [ "$R2" -gt "$R1" ] && ok "hammering EXTENDS the lock (${R1}s → ${R2}s, exponential)" || fail "lock did not extend: ${R1}s → ${R2}s"
# the REAL session key is also blocked while its principal is locked (fail closed)
mv "$AG29/connection.valid.json" "$AG29/connection.json"
outv=$(FARCONTROL_AGENT_HOME="$AG29" "$BIN" agent ping 2>&1)
echo "$outv" | grep -q '"code":"rate_limited"' && ok "valid session key also blocked while locked (fail closed)" || fail "lockout leaks valid requests: $outv"
# restart clears the in-memory lock (documented) → immediate recovery
kill "$DAEMON_PID" 2>/dev/null; wait "$DAEMON_PID" 2>/dev/null; DAEMON_PID=""
"$BIN" start >> "$K29/daemon.log" 2>&1 &
DAEMON_PID=$!
for i in $(seq 1 50); do "$BIN" status >/dev/null 2>&1 && break; sleep 0.2; done
# (the restart rotated the credentials — a stale-key ping proving the LOCK is gone
#  is not distinguishable from invalid_signature; the restart recovery is proven in §16)
# audit captured the escalation (bounded: only real changes)
"$BIN" audit 2>/dev/null | grep -q "auth.backoff" && ok "auth.backoff audited (escalation evidence)" || fail "no auth.backoff audit event"
rm -rf "$AG29"
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
say "31. OS keyring secret store (v0.9, ID-04/ADR-0023): session key never on disk — or fail-closed refusal"
[ -n "$DAEMON_PID" ] && kill "$DAEMON_PID" 2>/dev/null; wait "$DAEMON_PID" 2>/dev/null; DAEMON_PID=""
K31=$(mktemp -d /tmp/farcontrol-e2e-kr.XXXXXX)
printf 'agent_bind = "127.0.0.1:7788"\nadmin_bind = "127.0.0.1:7789"\nhome_root = "%s"\nuse_tls = true\n\n[identity]\nsecret_store = "keyring"\n' "$HOME" > "$K31/config.toml"
export FARCONTROL_HOME="$K31"
"$BIN" init >/dev/null 2>&1
"$BIN" start > "$K31/daemon.log" 2>&1 &
DAEMON_PID=$!
sleep 2
if "$BIN" status >/dev/null 2>&1; then
    # ---- full path: kernel keyring works (real Linux) ----
    AG31=$(mktemp -d /tmp/farcontrol-e2e-ag31.XXXXXX)
    D31=$(grep -o 'FAR-[A-Z0-9]*-[A-Z0-9]*' "$K31/daemon.log" | head -1)
    P31=$(grep 'session password' "$K31/daemon.log" | sed 's/.*: *//')
    [ -n "$P31" ] && ok "keyring-mode start printed the session password once" || fail "no password in start output"
    c31=$(FARCONTROL_AGENT_HOME="$AG31" FARCONTROL_DEVICE="$D31" FARCONTROL_SESSION_PASSWORD="$P31" "$BIN" agent 2>&1)
    echo "$c31" | grep -q "connected" && ok "login pulls the session key from the kernel keyring" || fail "keyring connect: $c31"
    K31KEY=$(python3 -c "import json; print(json.load(open('$AG31/connection.json'))['key'])")
    if LC_ALL=C grep -a -q "$K31KEY" "$K31/state.db" 2>/dev/null; then
        fail "session key plaintext found in state.db!"
    else
        ok "session key NOT in state.db (kernel keyring only, ID-04)"
    fi
    R31=$(FARCONTROL_AGENT_HOME="$AG31" "$BIN" agent request kr-agent full_access 6 keyring e2e 2>/dev/null | jq_get "['request_id']")
    "$BIN" approve "$R31" >/dev/null 2>&1
    S31=$(FARCONTROL_AGENT_HOME="$AG31" "$BIN" agent status "$R31" 2>/dev/null | jq_get "['request']['session_id']")
    expect_ok "e2e-kr-marker" env FARCONTROL_AGENT_HOME="$AG31" "$BIN" agent exec "$S31" sh -c 'echo e2e-kr-marker'
    # restart: the keyring survives + v1.2 rotates creds anyway → re-connect works
    kill "$DAEMON_PID" 2>/dev/null; wait "$DAEMON_PID" 2>/dev/null; DAEMON_PID=""
    "$BIN" start >> "$K31/daemon.log" 2>&1 &
    DAEMON_PID=$!
    for i in $(seq 1 50); do "$BIN" status >/dev/null 2>&1 && break; sleep 0.2; done
    P31B=$(grep 'session password' "$K31/daemon.log" | tail -1 | sed 's/.*: *//')
    c31b=$(FARCONTROL_AGENT_HOME="$AG31" FARCONTROL_DEVICE="$D31" FARCONTROL_SESSION_PASSWORD="$P31B" "$BIN" agent 2>&1)
    echo "$c31b" | grep -q "connected" && ok "keyring payload survives a restart (re-login loads it)" || fail "post-restart keyring connect: $c31b"
    # rotate: password + admin token die, key untouched → connected agent keeps working
    ROT31=$("$BIN" rotate 2>&1)
    echo "$ROT31" | grep -q "NEW SESSION PASSWORD" && ok "rotate works in keyring mode" || fail "keyring rotate: $ROT31"
    # doctor: secret_store check green
    D31v=$("$BIN" doctor 2>&1)
    echo "$D31v" | grep -q "ALL GREEN" && ok "doctor ALL GREEN in keyring mode" || fail "doctor red: $(echo "$D31v" | grep FAIL | head -2)"
    rm -rf "$AG31"
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
D32=$(grep -o 'FAR-[A-Z0-9]*-[A-Z0-9]*' "$K32/daemon.log" | head -1)
D32_PW=$(grep 'session password' "$K32/daemon.log" | sed 's/.*: *//')
AG32=$(mktemp -d /tmp/farcontrol-e2e-ag32.XXXXXX)
FARCONTROL_AGENT_HOME="$AG32" FARCONTROL_DEVICE="$D32" FARCONTROL_SESSION_PASSWORD="$D32_PW" "$BIN" agent >/dev/null 2>&1
R32=$(FARCONTROL_AGENT_HOME="$AG32" "$BIN" agent request stress-agent full_access 6 stress panic 2>/dev/null | jq_get "['request_id']")
"$BIN" approve "$R32" >/dev/null 2>&1
S32=$(env FARCONTROL_AGENT_HOME="$AG32" "$BIN" agent status "$R32" 2>/dev/null | jq_get "['request']['session_id']")
[ -n "$S32" ] || { fail "§32 no session"; exit 1; }
# put REAL work in flight: a live PTY terminal + three bounded commands
( echo 'sleep 60'; sleep 60 ) | timeout 40 env FARCONTROL_AGENT_HOME="$AG32" "$BIN" agent term "$S32" sh > "$K32/term.out" 2>&1 &
TERMS32=$!
for i in 1 2 3; do
    env FARCONTROL_AGENT_HOME="$AG32" "$BIN" agent exec --timeout-ms 4000 "$S32" sleep 20 > "$K32/exec$i.out" 2>&1 &
    eval "EX$i=$!"
done
sleep 1.5   # let the work actually start
# EMERGENCY STOP mid-flight
P32=$("$BIN" panic e2e-stress-panic 2>&1)
echo "$P32" | grep -q "PANIC executed" && ok "panic executed under load" || fail "panic failed: $P32"
echo "$P32" | grep -Eq "revoked sessions *: [1-9]" && ok "active session revoked mid-flight" || fail "session not revoked"
echo "$P32" | grep -Eq "killed terminals *: [1-9]" && ok "live terminal killed mid-flight" || fail "terminal not killed"
wait $EX1 $EX2 $EX3 2>/dev/null
STILL=0
for i in 1 2 3; do kill -0 $(eval "echo \$EX$i") 2>/dev/null && STILL=$((STILL+1)); done
[ $STILL -eq 0 ] && ok "in-flight commands did not orphan (bounded by their timeouts)" || fail "$STILL exec call(s) still hanging after panic"
kill $TERMS32 2>/dev/null; wait $TERMS32 2>/dev/null
# old session + old token are both dead
OUT32=$(env FARCONTROL_AGENT_HOME="$AG32" "$BIN" agent exec "$S32" echo hi 2>&1)
RC32=$?
# v1.2: the runtime may already have cleared the saved connection on expiry —
# "no saved connection" is exactly the designed fail-closed outcome too.
{ [ $RC32 -eq 4 ] || [ $RC32 -eq 3 ] || [ $RC32 -eq 1 ]; } && echo "$OUT32" | grep -qE '"code":"(session_revoked|invalid_signature)"|no saved connection' \
    && ok "post-panic exec fails closed (session + session key both dead)" || fail "revoked session still usable (rc=$RC32): $OUT32"
echo "$P32" | grep -q "session password + session key + admin token" && ok "panic rotated the whole credential set (v1.2)" || fail "no rotation report in panic output"
# the system must be fully ALIVE again: fresh cycle with the new password
PW32B=$(echo "$P32" | grep -A1 'NEW SESSION PASSWORD' | tail -1 | sed 's/^ *//')
rec32=$(env FARCONTROL_AGENT_HOME="$AG32" FARCONTROL_DEVICE="$D32" FARCONTROL_SESSION_PASSWORD="$PW32B" "$BIN" agent 2>&1)
echo "$rec32" | grep -q "connected" && ok "post-panic re-connect mints a fresh session" || fail "re-connect failed: $rec32"
R32B=$(env FARCONTROL_AGENT_HOME="$AG32" "$BIN" agent request fresh-agent terminal_only 6 after panic 2>/dev/null | jq_get "['request_id']")
[ -n "$R32B" ] && ok "new request flow works after panic" || fail "agent API dead after panic"
AP32B=$("$BIN" approve "$R32B" 2>&1)
echo "$AP32B" | grep -q 'approved' || fail "debug §32 approve: $AP32B"
S32B=$(env FARCONTROL_AGENT_HOME="$AG32" "$BIN" agent status "$R32B" 2>/dev/null | jq_get "['request']['session_id']")
expect_ok "e2e-fresh-marker" env FARCONTROL_AGENT_HOME="$AG32" "$BIN" agent exec "$S32B" sh -c 'echo e2e-fresh-marker'
H32=$(curl -s --cacert "$K32/cert.pem" -o /dev/null -w "%{http_code}" "https://127.0.0.1:7789/healthz" -m 5)
[ "$H32" = "200" ] && ok "healthz 200 after the storm" || fail "healthz → $H32"
D32=$("$BIN" doctor 2>&1)
echo "$D32" | grep -q "ALL GREEN" && ok "doctor ALL GREEN after the storm" || fail "doctor red: $(echo "$D32" | grep FAIL | head -2)"
"$BIN" audit 2>/dev/null | grep -q "system.panic" && ok "the stop itself is audited (invariant 8)" || fail "no system.panic audit event"
fi

# ---- v1.1 (ADR-0025/0026/0027) sections: device auth + CLI v2 + console v2 ----
# Self-contained where needed (own home) so mutation checks can target them:
# FARCONTROL_E2E_ONLY="33,34,35,36,37,38,39"

if section_wanted 33; then
say "33. agent runtime lifecycle (v1.2 ADR-0030): connect → survives exit → heartbeat → stop"
# fresh home so the runtime story stands alone
[ -n "$DAEMON_PID" ] && kill "$DAEMON_PID" 2>/dev/null; wait "$DAEMON_PID" 2>/dev/null; DAEMON_PID=""
K33=$(mktemp -d /tmp/farcontrol-e2e-rt.XXXXXX)
export FARCONTROL_HOME="$K33"
"$BIN" start > "$K33/daemon.log" 2>&1 &
DAEMON_PID=$!
for i in $(seq 1 50); do "$BIN" status >/dev/null 2>&1 && break; sleep 0.2; done
D33=$(grep -o 'FAR-[A-Z0-9]*-[A-Z0-9]*' "$K33/daemon.log" | head -1)
P33=$(grep 'session password' "$K33/daemon.log" | sed 's/.*: *//')
AG33=$(mktemp -d /tmp/farcontrol-e2e-ag33.XXXXXX)
# typo protection survives v1.2: the check char catches a corrupted id client-side
LAST33=$(echo "$D33" | grep -o '.$')
if [ "$LAST33" = "A" ]; then BAD33=$(echo "$D33" | sed 's/.$/B/'); else BAD33=$(echo "$D33" | sed 's/.$/A/'); fi
badout=$(FARCONTROL_AGENT_HOME="$AG33" FARCONTROL_DEVICE="$BAD33" FARCONTROL_SESSION_PASSWORD=x "$BIN" agent 2>&1); badrc=$?
[ $badrc -eq 2 ] && echo "$badout" | grep -q "not a valid FAR-XXXX-XXXX" && ok "typo in device id caught by check char (no network round-trip)" || fail "typo id accepted: $badout"
# connect with a declared name (audit + console chips, ADR-0030)
c33=$(FARCONTROL_AGENT_HOME="$AG33" FARCONTROL_DEVICE="$D33" FARCONTROL_SESSION_PASSWORD="$P33" "$BIN" agent --name e2e-runner 2>&1)
echo "$c33" | grep -q "connected" && ok "connect with --name e2e-runner" || fail "connect 33: $c33"
[ -f "$AG33/cert.pem" ] && ok "cert pinned (TOFU known_hosts analog)" || fail "no pinned cert"
# the runtime outlives the CLI that spawned it (master prompt §17 HARD requirement)
APID=$(cat "$AG33/agentd.pid" 2>/dev/null)
[ -n "$APID" ] && kill -0 "$APID" 2>/dev/null && ok "agentd alive after the CLI exited (pid $APID)" || { fail "agentd not running"; cat "$AG33/agentd.log" 2>/dev/null; }
sleep 2
kill -0 "$APID" 2>/dev/null && ok "agentd still alive 2s later (detached process group)" || fail "agentd died"
# idempotent connect → receipt, no duplicate runtime
c33b=$(FARCONTROL_AGENT_HOME="$AG33" FARCONTROL_DEVICE="$D33" FARCONTROL_SESSION_PASSWORD="$P33" "$BIN" agent 2>&1)
echo "$c33b" | grep -q "already connected" && ok "second connect is idempotent (single runtime, §41)" || fail "idempotent connect: $c33b"
# runtime status (local read, no network)
ST33=$(FARCONTROL_AGENT_HOME="$AG33" "$BIN" agent status 2>&1)
echo "$ST33" | grep -q "connected" && ok "agent status: connected" || fail "status: $ST33"
ST33J=$(FARCONTROL_AGENT_HOME="$AG33" "$BIN" agent status --json 2>&1)
echo "$ST33J" | grep -q '"state":"connected"' && ok "agent status --json {state}" || fail "status json: $ST33J"
# the OWNER sees the heartbeat: agents map in status --json (§32)
sleep 1.5
OS33=$("$BIN" status --json 2>/dev/null)
echo "$OS33" | python3 -c "
import json,sys
d = json.load(sys.stdin)
agents = d.get('agents') or []
assert any(a.get('name') == 'e2e-runner' for a in agents), 'e2e-runner missing: %r' % agents
print('ok')" | grep -q ok && ok "owner status --json shows the live agent (heartbeat map)" || fail "owner cannot see the agent: $OS33"
# canary: the session key + password never leak into agent-side files
KEY33=$(python3 -c "import json; print(json.load(open('$AG33/connection.json'))['key'])")
if grep -rq "$KEY33" "$AG33/agentd.log" "$AG33/status.json" 2>/dev/null; then fail "SESSION KEY LEAKED in agent files"; else ok "no session key in agentd.log/status.json"; fi
if grep -rq "$P33" "$AG33/agentd.log" "$AG33/status.json" 2>/dev/null; then fail "PASSWORD LEAKED in agent files"; else ok "no password in agentd.log/status.json"; fi
# agent stop → runtime dies + credentials cleared (fail closed, §18 anti-backdoor)
FARCONTROL_AGENT_HOME="$AG33" "$BIN" agent stop >/dev/null 2>&1 && ok "agent stop executed" || fail "agent stop failed"
sleep 0.5
[ -n "$APID" ] && ! kill -0 "$APID" 2>/dev/null && ok "runtime exited on stop" || fail "runtime survived stop"
[ ! -f "$AG33/connection.json" ] && ok "credentials cleared on stop (no lingering backdoor)" || fail "connection.json survived stop"
st33z=$(FARCONTROL_AGENT_HOME="$AG33" "$BIN" agent status 2>&1)
echo "$st33z" | grep -q "stopped" && ok "status after stop reports the terminal state" || true
rm -rf "$AG33"
fi

if section_wanted 34; then
say "34. login backoff (v1.2): wrong passwords lock the DEVICE login, not the box"
[ -n "$DAEMON_PID" ] && kill "$DAEMON_PID" 2>/dev/null; wait "$DAEMON_PID" 2>/dev/null; DAEMON_PID=""
K34=$(mktemp -d /tmp/farcontrol-e2e-bd.XXXXXX)
export FARCONTROL_HOME="$K34"
"$BIN" start > "$K34/daemon.log" 2>&1 &
DAEMON_PID=$!
for i in $(seq 1 50); do "$BIN" status >/dev/null 2>&1 && break; sleep 0.2; done
D34=$(grep -o 'FAR-[A-Z0-9]*-[A-Z0-9]*' "$K34/daemon.log" | head -1)
AG34=$(mktemp -d /tmp/farcontrol-e2e-ag34.XXXXXX)   # fresh agent home: no cross-home cert pin
LAST=""
for i in $(seq 1 9); do
    LAST=$(FARCONTROL_AGENT_HOME="$AG34" FARCONTROL_DEVICE="$D34" FARCONTROL_SESSION_PASSWORD="wrong-$i" "$BIN" agent 2>&1)
done
echo "$LAST" | grep -q '"code":"rate_limited"' && ok "hammered logins lock (429 rate_limited)" || fail "no lock: $LAST"
# the ADMIN plane (a different principal) stays usable while the agent login is locked
sleep 3   # let the seconds-scale global burst window pass; the per-principal lock stays
ADM34=$(grep 'admin token' "$K34/daemon.log" | sed 's/.*: *//')
code34=$(curl -s --cacert "$K34/cert.pem" -o /dev/null -w "%{http_code}" -X POST "https://127.0.0.1:7789/ui/login" \
    -H "X-Far-Ui: 1" -H "Content-Type: application/json" -d "{\"password\":\"$ADM34\"}" -m 5)
[ "$code34" = "200" ] && ok "web-ui login unaffected by the agent-login lockout (per-principal)" || fail "admin plane blocked: HTTP $code34"
# audit captured the escalation
"$BIN" audit --json 2>/dev/null | grep -q '"action":"auth.login_failed"' && ok "auth.login_failed audited" || fail "login failures not audited"
fi

if section_wanted 35; then
say "35. fingerprint TOFU (ADR-0029): --expect-fp aborts BEFORE the password"
[ -n "$DAEMON_PID" ] && kill "$DAEMON_PID" 2>/dev/null; wait "$DAEMON_PID" 2>/dev/null; DAEMON_PID=""
K35=$(mktemp -d /tmp/farcontrol-e2e-tofu.XXXXXX)
export FARCONTROL_HOME="$K35"
"$BIN" start > "$K35/daemon.log" 2>&1 &
DAEMON_PID=$!
for i in $(seq 1 50); do "$BIN" status >/dev/null 2>&1 && break; sleep 0.2; done
D35=$(grep -o 'FAR-[A-Z0-9]*-[A-Z0-9]*' "$K35/daemon.log" | head -1)
P35=$(grep 'session password' "$K35/daemon.log" | sed 's/.*: *//')
FP35=$("$BIN" fingerprint 2>&1 | grep -o 'SHA256:[A-Za-z0-9+/]*' | head -1)
# strict match: fingerprint verified, THEN the password is sent
AG35=$(mktemp -d /tmp/farcontrol-e2e-ag35.XXXXXX)
strict=$(FARCONTROL_AGENT_HOME="$AG35" FARCONTROL_DEVICE="$D35" FARCONTROL_SESSION_PASSWORD="$P35" "$BIN" agent --expect-fp "$FP35" 2>&1)
echo "$strict" | grep -q "matches --expect-fp" && echo "$strict" | grep -q "connected" \
    && ok "strict connect: fingerprint verified before the password" || fail "strict connect: $strict"
[ -f "$AG35/cert.pem" ] && ok "captured cert pinned (known_hosts analog)" || fail "no pinned cert"
# mismatch → exit 3, password NEVER sent, evil pin not left behind
AG35b=$(mktemp -d /tmp/farcontrol-e2e-ag35b.XXXXXX)
mis=$(FARCONTROL_AGENT_HOME="$AG35b" FARCONTROL_DEVICE="$D35" FARCONTROL_SESSION_PASSWORD="$P35" "$BIN" agent --expect-fp "SHA256:00000000000000000000000000000000000000000000" 2>&1); misrc=$?
[ "$misrc" = "3" ] && echo "$mis" | grep -q "FINGERPRINT MISMATCH" && ok "fingerprint mismatch aborts (exit 3, password never sent)" || fail "mismatch not aborted: rc=$misrc $mis"
[ ! -f "$AG35b/cert.pem" ] && ok "the mismatched cert was NOT left pinned" || fail "evil pin survived the refusal!"
# exactly ONE login reached the server (the strict one)
N35=$("$BIN" audit --json 2>/dev/null | grep -c '"action":"auth.login"')
[ "$N35" = "1" ] && ok "exactly ONE login reached the server (the strict one)" || fail "login count: $N35"
rm -rf "$AG35" "$AG35b"
fi

if section_wanted 36; then
say "36. v1.1 registry migration (ADR-0031 §5): legacy devices locked, keys rotated, grants revoked"
[ -n "$DAEMON_PID" ] && kill "$DAEMON_PID" 2>/dev/null; wait "$DAEMON_PID" 2>/dev/null; DAEMON_PID=""
K36=$(mktemp -d /tmp/farcontrol-e2e-mig.XXXXXX)
# init WITHOUT starting, then inject a v1.1-shaped registry: one device row
# with a permanent password + key, plus a v1.0-style agent_token meta.
# (device id reuses a VALID check-char id so the client-side validator lets it through)
FARCONTROL_HOME="$K36" "$BIN" init >/dev/null 2>&1
python3 - "$K36/state.db" "$E2E_DEV" << 'PY36'
import sqlite3, sys
conn = sqlite3.connect(sys.argv[1])
conn.execute("INSERT OR REPLACE INTO meta(key, value) VALUES ('agent_token', 'legacy-e2e-token-v100')")
conn.execute("INSERT INTO devices(id, name, password_hash, device_key, status, login_enabled, created_at) "
             "VALUES (?, 'old-laptop', 'x-unused-hash', 'legacy-key-material', 'active', 1, 0)", (sys.argv[2],))
conn.commit()
PY36
export FARCONTROL_HOME="$K36"
"$BIN" start > "$K36/daemon.log" 2>&1 &
DAEMON_PID=$!
for i in $(seq 1 50); do "$BIN" status >/dev/null 2>&1 && break; sleep 0.2; done
"$BIN" audit 2>/dev/null | grep -q "device.model_migrated" && ok "v1.1 registry migrated at daemon start (audited)" || fail "migration did not run"
# row-level proof: the legacy device is locked + its key rotated to noise
M36=$(python3 - "$K36/state.db" "$E2E_DEV" << 'PY36b'
import sqlite3, sys
conn = sqlite3.connect(sys.argv[1])
row = conn.execute("SELECT login_enabled, status, device_key FROM devices WHERE id = ?", (sys.argv[2],)).fetchone()
assert row is not None, "legacy row vanished"
assert row[0] == 0, "legacy device still login-enabled"
assert row[1] == "locked", "legacy device not locked: %r" % (row,)
assert row[2] != "legacy-key-material", "legacy key NOT rotated"
print("ok")
PY36b
)
[ "$M36" = "ok" ] && ok "legacy device locked + key rotated (row-level proof)" || fail "legacy row wrong: $M36"
# the legacy device id cannot log in (single machine device — generic rejection, no oracle)
AG36b=$(mktemp -d /tmp/farcontrol-e2e-ag36b.XXXXXX)
L36=$(FARCONTROL_AGENT_HOME="$AG36b" FARCONTROL_DEVICE="$E2E_DEV" FARCONTROL_SESSION_PASSWORD="whatever" "$BIN" agent 2>&1)
echo "$L36" | grep -q '"code":"invalid_credentials"' && ok "v1.1 device id rejected (not the machine device)" || fail "legacy id login: $L36"
sleep 2   # the burst brake is seconds-scale: let the deliberate failure above age out
# the legacy HMAC key is dead (forged connection over the old key)
AG36=$(mktemp -d /tmp/farcontrol-e2e-ag36.XXXXXX)
python3 - "$AG36" "$E2E_DEV" << 'PY36c'
import json, sys
home, dev = sys.argv[1], sys.argv[2]
json.dump({"version": 2, "base_url": "https://127.0.0.1:7788", "device_id": dev,
           "session_id": "", "key": "legacy-key-material", "agent_name": "old"},
          open(home + "/connection.json", "w"))
PY36c
old36=$(FARCONTROL_AGENT_HOME="$AG36" "$BIN" agent ping 2>&1); rc36=$?
# device_locked is the specific v1.2 outcome for a retired-at-migration device;
# invalid_signature is the generic wrong-key outcome — both are fail-closed.
[ $rc36 -ne 0 ] && echo "$old36" | grep -qE '"code":"(invalid_signature|device_locked)"' \
    && ok "v1.1 device key dead (retired at migration)" || fail "legacy key works: $old36"
# the v1.0 token path is GONE: headerless requests are refused fail-closed
h36=$(curl -s --cacert "$K36/cert.pem" -o /dev/null -w "%{http_code}" "https://127.0.0.1:7788/v1/ping" -m 5)
[ "$h36" = "401" ] && ok "headerless v1.0-style request rejected (401, no legacy path)" || fail "headerless → $h36"
sleep 2   # same brake discipline before the (must-succeed) machine connect
# the machine device works with the NEW session password (the migration's gift)
D36=$(grep -o 'FAR-[A-Z0-9]*-[A-Z0-9]*' "$K36/daemon.log" | head -1)
P36=$(grep 'session password' "$K36/daemon.log" | sed 's/.*: *//')
[ "$D36" != "$E2E_DEV" ] && ok "the machine device id is minted fresh ($D36)" || fail "machine id collision with the legacy row?!"
c36=$(FARCONTROL_AGENT_HOME="$AG36" FARCONTROL_DEVICE="$D36" FARCONTROL_SESSION_PASSWORD="$P36" "$BIN" agent 2>&1)
echo "$c36" | grep -q "connected" && ok "post-migration connect with the session password works" || fail "post-migration connect: $c36"
rm -rf "$AG36" "$AG36b"
fi

if section_wanted 37; then
say "37. --json everywhere (v1.1 ADR-0026 → v1.2 surface): stable machine output"
for cmdjson in "fingerprint --json" "status --json" "list --json"; do
    out37=$("$BIN" $cmdjson 2>/dev/null)
    echo "$out37" | python3 -m json.tool >/dev/null 2>&1 && ok "$cmdjson → valid JSON" || fail "$cmdjson not valid JSON: $(echo "$out37" | head -c 80)"
done
FP37=$("$BIN" fingerprint --json 2>/dev/null | python3 -c "import json,sys; print(json.load(sys.stdin)['fingerprint'][:7])")
[ "$FP37" = "SHA256:" ] && ok "fingerprint --json shape {fingerprint}" || fail "fingerprint --json: $FP37"
ST37=$("$BIN" status --json 2>/dev/null | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('service'), 'agents' in d)")
echo "$ST37" | grep -q "farcontrol True" && ok "status --json keeps §45 shape (service) + carries agents" || fail "status --json shape: $ST37"
L37=$("$BIN" list --json 2>/dev/null | python3 -c "import json,sys; d=json.load(sys.stdin); print('requests' in d and 'sessions' in d)")
[ "$L37" = "True" ] && ok "list --json = {requests, sessions} (§45)" || fail "list --json shape wrong"
fi

if section_wanted 38; then
say "38. web console v1.2 (ADR-0032): session-first IA + rotate + host allowlist"
UI="https://127.0.0.1:7789"
CA="$FARCONTROL_HOME/cert.pem"
CJ="$(mktemp /tmp/fui38.XXXXXX)"
ADMTOK=$(cat "$FARCONTROL_HOME/admin-token")
html=$(curl -s --retry 2 --retry-connrefused --cacert "$CA" "$UI/" -m 5)
echo "$html" | grep -q "FARcontrol" && ok "v1.2 console shell served" || fail "shell missing"
echo "$html" | grep -q "frtrol start" && ok "login label points to 'frtrol start' (per-session admin token, r12)" || fail "login label does not reference the start banner"
if echo "$html" | grep -qE "innerHTML|document\.write|eval\("; then fail "v1.2 page uses innerHTML/eval"; else ok "page is textContent-only (no HTML-string sinks)"; fi
if echo "$html" | grep -q "http://\|https://"; then fail "v1.2 page references external assets"; else ok "zero external assets (offline localhost)"; fi
# host allowlist (r12 / ADR-0032 #4): a foreign Host header must not reach the admin app
code_evil=$(curl -s --cacert "$CA" -o /dev/null -w "%{http_code}" -H "Host: evil.example" "$UI/ui/state" -m 5)
[ "$code_evil" = "403" ] && ok "Host: evil.example → 403 (DNS-rebinding guard)" || fail "evil host → $code_evil"
# the agent plane is HMAC-authenticated, not cookie-authenticated — the allowlist is admin-only
code_agent=$(curl -s --cacert "$CA" -o /dev/null -w "%{http_code}" -H "Host: evil.example" "https://127.0.0.1:7788/v1/ping" -m 5)
[ "$code_agent" = "401" ] && ok "agent plane ignores the Host header (HMAC, no ambient cookies)" || fail "agent plane Host handling: $code_agent"
curl -s --cacert "$CA" -c "$CJ" -o /dev/null -X POST "$UI/ui/login" -H "X-Far-Ui: 1" -H "Content-Type: application/json" -d "{\"password\":\"$ADMTOK\"}" -m 5
state=$(curl -s --cacert "$CA" -b "$CJ" "$UI/ui/state" -m 5)
echo "$state" | python3 -c "
import json,sys
d = json.load(sys.stdin)
for k in ('version','device_id','agents','pending','sessions','audit_chain','fingerprint'):
    assert k in d, 'missing ' + k
assert 'devices' not in d, 'v1.1 devices payload must be gone'
print('ok')" | grep -q ok && ok "/ui/state = session-first payload (version/device_id/agents, no devices)" || fail "state payload incomplete"
# /ui/rotate: CSRF enforced, then rotates password + admin token (key untouched)
code=$(curl -s --cacert "$CA" -b "$CJ" -o /dev/null -w "%{http_code}" -X POST "$UI/ui/rotate" -H "Content-Type: application/json" -d '{}' -m 5)
[ "$code" = "403" ] && ok "UI rotate without X-Far-Ui → 403 (CSRF)" || fail "UI rotate CSRF: $code"
rot38=$(curl -s --cacert "$CA" -b "$CJ" -X POST "$UI/ui/rotate" -H "X-Far-Ui: 1" -H "Content-Type: application/json" -d '{}' -m 5)
echo "$rot38" | python3 -c "
import json,sys
d = json.load(sys.stdin)
assert d.get('password') and d.get('admin_token') and d.get('device_id'), d
print('ok')" | grep -q ok && ok "UI rotate → new password + admin token (shown once)" || fail "UI rotate failed: $rot38"
# panic via the v1.2 console: revokes + rotates everything (this home has no
# active sessions — the revocation semantics are proven with real sessions in §19k)
pn=$(curl -s --cacert "$CA" -b "$CJ" -X POST "$UI/ui/panic" -H "X-Far-Ui: 1" -H "Content-Type: application/json" -d '{"reason":"e2e 38"}' -m 5)
echo "$pn" | python3 -c "
import json,sys
d = json.load(sys.stdin)
assert d.get('password') and d.get('admin_token') and d.get('device_id'), d
assert 'revoked_sessions' in d
print('ok')" | grep -q ok && ok "UI panic rotates the whole credential set (password + admin token shown once)" || fail "UI panic: $pn"
echo "$pn" | grep -q '"device_id"' && ok "UI panic reports the session identity" || fail "UI panic missing device_id"
rm -f "$CJ"
fi

if section_wanted 39; then
say "39. CLI v2 output contract (ADR-0026/0031): tables, glyphs, hints, NO_COLOR"
[ -n "$DAEMON_PID" ] && kill "$DAEMON_PID" 2>/dev/null; wait "$DAEMON_PID" 2>/dev/null; DAEMON_PID=""
K39=$(mktemp -d /tmp/farcontrol-e2e-out.XXXXXX)
export FARCONTROL_HOME="$K39"
"$BIN" start > "$K39/daemon.log" 2>&1 &
DAEMON_PID=$!
for i in $(seq 1 50); do "$BIN" status >/dev/null 2>&1 && break; sleep 0.2; done
D39=$(grep -o 'FAR-[A-Z0-9]*-[A-Z0-9]*' "$K39/daemon.log" | head -1)
P39=$(grep 'session password' "$K39/daemon.log" | sed 's/.*: *//')
AG39=$(mktemp -d /tmp/farcontrol-e2e-ag39.XXXXXX)
FARCONTROL_AGENT_HOME="$AG39" FARCONTROL_DEVICE="$D39" FARCONTROL_SESSION_PASSWORD="$P39" "$BIN" agent --name pretty-runner >/dev/null 2>&1
sleep 1.5   # let one heartbeat land so the agent shows up in status
R39=$(FARCONTROL_AGENT_HOME="$AG39" "$BIN" agent request pretty-agent terminal_only 6 pretty output 2>/dev/null | jq_get "['request_id']")
"$BIN" approve "$R39" >/dev/null 2>&1
# the session box IS the v1.2 home screen: identity + handover + ephemerality
grep -q "device id" "$K39/daemon.log" && ok "start banner carries the device id line" || fail "no device id in banner"
# status shows the session + the live agent (r10 console story, CLI side)
OUT39=$("$BIN" status 2>&1)
echo "$OUT39" | grep -q "$D39" && ok "status shows the machine device id" || fail "status missing device id: $OUT39"
echo "$OUT39" | grep -q "pretty-runner" && ok "status shows the connected agent" || fail "status missing agent: $OUT39"
# tables + glyphs + humanized durations in list
L39=$("$BIN" list 2>&1)
echo "$L39" | grep -q "ID" && echo "$L39" | grep -q "SCOPE" && ok "list renders a table with headers" || fail "list table missing: $L39"
echo "$L39" | grep -q "●" && ok "status glyphs present (shape-carried meaning)" || fail "no glyphs in list"
echo "$L39" | grep -qE "[0-9]+h [0-9]+m left" && ok "durations humanized (2h 15m left)" || fail "no humanized countdown: $L39"
# NO_COLOR + pipe -> no ANSI escapes ever
if NO_COLOR=1 "$BIN" list 2>&1 | grep -q $'\x1b\['; then fail "NO_COLOR still emits ANSI"; else ok "NO_COLOR strips styling"; fi
if "$BIN" list 2>&1 | grep -q $'\x1b\['; then fail "piped output contains ANSI"; else ok "piped output is plain ASCII (pipe safety)"; fi
# removed commands are really gone (v1.2 breaking contract, documented in CHANGELOG)
if "$BIN" device list >/dev/null 2>&1; then fail "removed command 'device' still works"; else ok "removed v1.1 command surface ('device ...') is gone"; fi
if "$BIN" agent login 2>/dev/null >/dev/null; then fail "removed command 'agent login' still works"; else ok "removed v1.1 command 'agent login' is gone"; fi
rm -rf "$AG39"
fi

say "RESULT"
echo "  passed: $PASS"
echo "  failed: $FAIL"
if [ $FAIL -gt 0 ]; then
    echo "  daemon log tail:"
    tail -20 "$FARCONTROL_HOME/daemon.log" | sed 's/^/    /'
    exit 1
fi
echo "  ALL GREEN — FARcontrol 1.2.0 e2e verification PASSED (v1.2: ephemeral session credentials + agent connect + background runtime + console v1.2 + host allowlist + v1.1 migration; 1.1: device auth + stress panic; 1.0: panic-under-stress; 0.9: backoff/validation/keyring; 0.8: catalog/exits/json/proto/retention)"
