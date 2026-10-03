#!/usr/bin/env bash
# v1.2.0 manual smoke — the master prompt §50 definition of done, run by hand.
# PREDICTIONS written BEFORE running (discipline §8.1):
#   1. start prints the session box with device id + session password + admin token
#   2. `frtrol agent` (env creds) connects, spawns agentd, exits 0
#   3. agentd survives CLI exit (pid alive)
#   4. `frtrol agent status` → connected
#   5. owner `frtrol status` shows the agent
#   6. `frtrol stop` → daemon dies; agentd reaches `expired` (creds cleared)
#   7. restart → NEW password; OLD password → 401
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/target/release/frtrol"
OWNER=$(mktemp -d /tmp/far-v12-owner.XXXXXX)
AGENT=$(mktemp -d /tmp/far-v12-agent.XXXXXX)
export FARCONTROL_HOME="$OWNER"
export FARCONTROL_AGENT_HOME="$AGENT"
export FARCONTROL_TEST_MODE=1
PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); echo "  [PASS] $1"; }
bad()  { FAIL=$((FAIL+1)); echo "  [FAIL] $1"; }

echo "== 1. frtrol start (first run) =="
"$BIN" start > "$OWNER/daemon1.log" 2>&1 &
DPID=$!
for i in $(seq 1 60); do [ -f "$OWNER/admin-token" ] && break; sleep 0.2; done
grep -q "session started" "$OWNER/daemon1.log" && ok "session box printed" || { bad "no session box"; cat "$OWNER/daemon1.log"; exit 1; }
DEV=$(grep -o 'device id *: *FAR-[A-Z0-9]*-[A-Z0-9]*' "$OWNER/daemon1.log" | head -1 | grep -o 'FAR-.*')
PW1=$(grep 'session password' "$OWNER/daemon1.log" | sed 's/.*: *//')
ADMIN1=$(grep 'admin token' "$OWNER/daemon1.log" | sed 's/.*: *//')
[ -n "$DEV" ] && ok "device id: $DEV" || bad "no device id"
[ -n "$PW1" ] && ok "session password printed" || bad "no password"
[ -n "$ADMIN1" ] && ok "admin token printed" || bad "no admin token"
grep -q "frtrol agent" "$OWNER/daemon1.log" && ok "banner tells the agent line" || bad "no agent line"
grep -c "$PW1" "$OWNER/daemon1.log" | grep -q "^1$" && ok "password appears exactly ONCE in start output" || bad "password printed more than once"

echo "== 2. second start while running =="
"$BIN" start > "$OWNER/daemon2.log" 2>&1
RC=$?
[ $RC -ne 0 ] && grep -q "already running" "$OWNER/daemon2.log" && ok "second start fails with a clear hint" || bad "second start rc=$RC"

echo "== 3. agent connect (env creds, non-tty) =="
FARCONTROL_DEVICE="$DEV" FARCONTROL_SESSION_PASSWORD="$PW1" "$BIN" agent > "$AGENT/connect.log" 2>&1
RC=$?
[ $RC -eq 0 ] && grep -q "connected" "$AGENT/connect.log" && ok "frtrol agent connected (rc=0)" || { bad "connect rc=$RC"; cat "$AGENT/connect.log"; }
[ -f "$AGENT/connection.json" ] && ok "connection.json saved" || bad "no connection.json"
stat -c '%a' "$AGENT/connection.json" | grep -q "^600$" && ok "connection.json mode 0600" || bad "mode $(stat -c '%a' "$AGENT/connection.json")"
grep -q "server fingerprint" "$AGENT/connect.log" && ok "TOFU pin + fingerprint shown" || bad "no fingerprint"

echo "== 4. runtime survives CLI exit (HARD requirement §17) =="
APID=$(cat "$AGENT/agentd.pid" 2>/dev/null)
[ -n "$APID" ] && kill -0 "$APID" 2>/dev/null && ok "agentd alive after CLI exited (pid $APID)" || { bad "agentd not running"; cat "$AGENT/agentd.log"; }
sleep 2
kill -0 "$APID" 2>/dev/null && ok "agentd still alive 2s later" || bad "agentd died"

echo "== 5. agent status =="
ST=$("$BIN" agent status 2>&1)
echo "$ST" | grep -q "connected" && ok "agent status: connected" || { bad "status: $ST"; cat "$AGENT/status.json"; }
STJ=$("$BIN" agent status --json 2>&1)
echo "$STJ" | grep -q '"state":"connected"' && ok "agent status --json stable" || bad "json: $STJ"

echo "== 6. owner sees the agent =="
OS=$("$BIN" status 2>&1)
echo "$OS" | grep -q "agent" && ok "owner status shows the agent" || bad "owner status: $OS"

echo "== 7. request → approve → exec (full loop over the saved connection) =="
REQ=$(FARCONTROL_AGENT_HOME="$AGENT" "$BIN" agent request smoke-agent terminal_only 6 smoke test 2>/dev/null)
RID=$(echo "$REQ" | python3 -c "import json,sys; print(json.load(sys.stdin)['request_id'])" 2>/dev/null)
[ -n "$RID" ] && ok "request created: $RID" || bad "request failed: $REQ"
AP=$("$BIN" approve "$RID" 2>&1)
SID=$(echo "$AP" | grep -o 'ses_[A-Za-z0-9]*' | head -1)
[ -n "$SID" ] && ok "approved → $SID" || bad "approve: $AP"
EXEC=$(FARCONTROL_AGENT_HOME="$AGENT" "$BIN" agent exec "$SID" sh -c 'echo v12-smoke-marker' 2>/dev/null)
echo "$EXEC" | grep -q "v12-smoke-marker" && ok "exec works over the saved connection" || bad "exec: $EXEC"

echo "== 8. canary: key/password never leak into agent-side logs =="
KEY=$(python3 -c "import json; print(json.load(open('$AGENT/connection.json'))['key'])")
if grep -rq "$KEY" "$AGENT/agentd.log" "$AGENT/status.json" 2>/dev/null; then bad "SESSION KEY LEAKED in agent files"; else ok "no key in agentd.log/status.json"; fi
if grep -rq "$PW1" "$AGENT/agentd.log" "$AGENT/status.json" 2>/dev/null; then bad "PASSWORD LEAKED in agent files"; else ok "no password in agentd.log/status.json"; fi

echo "== 9. frtrol stop → daemon down → runtime RECONNECTING (creds kept) =="
"$BIN" stop > /dev/null 2>&1 && ok "frtrol stop ok" || bad "stop failed"
sleep 2
ST=$("$BIN" agent status 2>&1)
echo "$ST" | grep -q "reconnecting" && ok "runtime reconnecting while the daemon is down (network loss ≠ session end)" || bad "status: $ST"
[ -f "$AGENT/connection.json" ] && ok "credentials kept during a network outage (§20)" || bad "creds dropped too early"

echo "== 10. restart → NEW password; old one dead =="
"$BIN" start > "$OWNER/daemon3.log" 2>&1 &
DPID2=$!
for i in $(seq 1 60); do "$BIN" status >/dev/null 2>&1 && break; sleep 0.2; done
# the OLD runtime (still running from section 3) must see the dead key → expired
for i in $(seq 1 30); do
  ST=$("$BIN" agent status --json 2>/dev/null || true)
  echo "$ST" | grep -q '"state":"expired"' && break
  sleep 0.5
done
echo "$ST" | grep -q '"state":"expired"' && ok "old runtime reached expired after the restart (dead key, ADR-0028)" || { bad "old runtime state: $ST"; cat "$AGENT/agentd.log"; }
[ ! -f "$AGENT/connection.json" ] && ok "expired runtime cleared its credentials (fail closed)" || bad "connection.json survived expiry"
PW2=$(grep 'session password' "$OWNER/daemon3.log" | sed 's/.*: *//')
ADMIN2=$(grep 'admin token' "$OWNER/daemon3.log" | sed 's/.*: *//')
[ -n "$PW2" ] && ok "restart printed a new password" || { bad "no password in daemon3.log"; tail -3 "$OWNER/daemon3.log"; }
[ "$PW1" != "$PW2" ] && ok "session password rotated across restarts" || bad "password NOT rotated"
[ "$ADMIN1" != "$ADMIN2" ] && ok "admin token rotated across restarts" || bad "admin token NOT rotated"
OUT=$(FARCONTROL_AGENT_HOME="$AGENT" FARCONTROL_DEVICE="$DEV" FARCONTROL_SESSION_PASSWORD="$PW1" "$BIN" agent 2>&1)
echo "$OUT" | grep -q "invalid_credentials" && ok "OLD password rejected (401)" || bad "old password accepted?! $OUT"
OUT=$(FARCONTROL_AGENT_HOME="$AGENT" FARCONTROL_DEVICE="$DEV" FARCONTROL_SESSION_PASSWORD="$PW2" "$BIN" agent 2>&1)
echo "$OUT" | grep -q "connected" && ok "NEW password connects" || bad "new password failed: $OUT"
"$BIN" stop > /dev/null 2>&1

echo "== 11. host allowlist (DNS-rebinding guard) =="
"$BIN" start > "$OWNER/daemon4.log" 2>&1 &
DPID3=$!
for i in $(seq 1 60); do "$BIN" status >/dev/null 2>&1 && break; sleep 0.2; done
ADMIN3=$(grep 'admin token' "$OWNER/daemon4.log" | sed 's/.*: *//')
CODE_EVIL=$(curl -s -o /dev/null -w "%{http_code}" --cacert "$OWNER/cert.pem" -H "Host: evil.example" "https://127.0.0.1:7789/" -m 3)
CODE_OK=$(curl -s -o /dev/null -w "%{http_code}" --cacert "$OWNER/cert.pem" "https://127.0.0.1:7789/" -m 3)
[ "$CODE_EVIL" = "403" ] && ok "Host: evil.example → 403" || bad "evil host → $CODE_EVIL"
[ "$CODE_OK" = "200" ] && ok "Host: 127.0.0.1 → 200" || bad "ok host → $CODE_OK"
"$BIN" stop > /dev/null 2>&1

echo "== 12. secret scan on owner dir =="
[ -n "$PW2" ] && [ -n "$ADMIN2" ] && ok "restart credentials parsed (non-empty)" || bad "PW2/ADMIN2 empty — earlier cascade"
if grep -q "$PW2" "$OWNER/audit.jsonl" 2>/dev/null; then bad "password leaked into audit"; else ok "no password in audit.jsonl"; fi
if grep -q "$ADMIN2" "$OWNER/audit.jsonl" 2>/dev/null; then bad "admin token leaked into audit"; else ok "no admin token in audit"; fi
if grep -q "$PW1" "$OWNER/audit.jsonl" 2>/dev/null; then bad "first password leaked into audit"; else ok "no first password in audit"; fi

echo
echo "SMOKE RESULT: PASS=$PASS FAIL=$FAIL"
rm -rf "$OWNER" "$AGENT"
[ $FAIL -eq 0 ]
