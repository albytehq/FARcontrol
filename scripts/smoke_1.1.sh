#!/bin/bash
# smoke_1.1.sh — full v1.1 device-auth flow in ONE call (sandbox reaps bg processes)
set -u
BIN=/home/z/my-project/farcontrol/target/debug/frtrol
S=/home/z/my-project/farcontrol/smoke
rm -rf "$S"; mkdir -p "$S/owner" "$S/agent"
PASS=0; FAIL=0
ck() { if [ "$2" = "0" ]; then PASS=$((PASS+1)); echo "  ✓ $1"; else FAIL=$((FAIL+1)); echo "  ✗ $1  [exit $2]"; fi; }

# --- daemon up
FARCONTROL_HOME="$S/owner" "$BIN" start --bind 127.0.0.1:17788 > "$S/daemon.log" 2>&1 &
DPID=$!
sleep 2

# --- 1. device add (owner CLI → admin plane)
FARCONTROL_HOME="$S/owner" "$BIN" device add testlaptop > "$S/devadd.txt" 2>&1
ck "device add" $?
DEV_ID=$(grep -o 'FAR-[A-Z0-9]*-[A-Z0-9]*' "$S/devadd.txt" | head -1)
PASSWORD=$(grep -A1 'DEVICE PASSWORD' "$S/devadd.txt" | tail -1 | sed 's/^ *//')
echo "    id=[$DEV_ID] pw=[$PASSWORD]"

# --- 2. fingerprint (owner) vs agent TOFU
FARCONTROL_HOME="$S/owner" "$BIN" fingerprint > "$S/fp.txt" 2>&1; ck "fingerprint" $?
FP=$(grep -o 'SHA256:[^ ]*' "$S/fp.txt" | head -1)
echo "    fp=$FP"

# --- 3. agent login TOFU (no cert yet → capture)
FARCONTROL_HOME="$S/agent" FARCONTROL_URL="https://127.0.0.1:17788" FARCONTROL_PASSWORD="$PASSWORD" \
  "$BIN" agent login "$DEV_ID" > "$S/login.txt" 2>&1; ck "agent login (TOFU capture)" $?
grep -q "server fingerprint" "$S/login.txt" && echo "    $(grep 'server fingerprint' "$S/login.txt")"

# --- 4. strict login with --expect-fp on a FRESH agent home (must verify)
rm -rf "$S/agent"; mkdir -p "$S/agent"
FARCONTROL_HOME="$S/agent" FARCONTROL_URL="https://127.0.0.1:17788" FARCONTROL_PASSWORD="$PASSWORD" \
  "$BIN" agent login "$DEV_ID" --expect-fp "$FP" > "$S/login2.txt" 2>&1; ck "agent login strict (--expect-fp match)" $?

# --- 5. wrong fingerprint must abort BEFORE password send
rm -rf "$S/agent"; mkdir -p "$S/agent"
FARCONTROL_HOME="$S/agent" FARCONTROL_URL="https://127.0.0.1:17788" FARCONTROL_PASSWORD="$PASSWORD" \
  "$BIN" agent login "$DEV_ID" --expect-fp "SHA256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef" > "$S/login3.txt" 2>&1
RC=$?; [ "$RC" = "3" ]; ck "login aborts on fingerprint mismatch (exit 3, password never sent)" $?

# --- 6. re-login (device key rotation on login: old key dies)
rm -rf "$S/agent"; mkdir -p "$S/agent"
FARCONTROL_HOME="$S/agent" FARCONTROL_URL="https://127.0.0.1:17788" FARCONTROL_PASSWORD="$PASSWORD" \
  "$BIN" agent login "$DEV_ID" > /dev/null 2>&1; ck "re-login (key rotated)" $?

# --- 7. agent ping (device-signed requests)
FARCONTROL_HOME="$S/agent" FARCONTROL_URL="https://127.0.0.1:17788" "$BIN" agent ping > "$S/ping.txt" 2>&1
ck "agent ping (device-signed)" $?

# --- 8. request session
FARCONTROL_HOME="$S/agent" FARCONTROL_URL="https://127.0.0.1:17788" \
  "$BIN" agent request testai terminal_only 6 smoke test reasons > "$S/req.txt" 2>&1
ck "agent request" $?
REQ_ID=$(grep -o 'req_[A-Za-z0-9]*' "$S/req.txt" | head -1); echo "    req=[$REQ_ID]"

# --- 9. owner approve
FARCONTROL_HOME="$S/owner" "$BIN" approve "$REQ_ID" > "$S/appr.txt" 2>&1; ck "owner approve" $?
SES_ID=$(grep -o 'ses_[A-Za-z0-9]*' "$S/appr.txt" | head -1); echo "    ses=[$SES_ID]"

# --- 10. device binding visible in list --json
FARCONTROL_HOME="$S/owner" "$BIN" list --json > "$S/list.json" 2>&1
grep -q "\"device_id\":\"$DEV_ID\"" "$S/list.json"; ck "session bound to device id (list --json)" $?

# --- 11. exec
FARCONTROL_HOME="$S/agent" FARCONTROL_URL="https://127.0.0.1:17788" \
  "$BIN" agent exec "$SES_ID" echo v11-works --raw > "$S/exec.txt" 2>&1
ck "agent exec" $?
grep -q "v11-works" "$S/exec.txt"; ck "exec output" $?

# --- 12. bad password login → 401 + strike
rm -rf "$S/agent-bad"; mkdir -p "$S/agent-bad"
FARCONTROL_HOME="$S/agent-bad" FARCONTROL_URL="https://127.0.0.1:17788" FARCONTROL_PASSWORD="wrong-password-99" \
  "$BIN" agent login "$DEV_ID" > "$S/badlogin.txt" 2>&1
RC=$?; [ "$RC" != "0" ] && grep -q "invalid_credentials" "$S/badlogin.txt"; ck "bad password rejected (401 invalid_credentials)" $?

# --- 13. device list shows the device
FARCONTROL_HOME="$S/owner" "$BIN" device list > "$S/devlist.txt" 2>&1; ck "device list" $?
grep -q "$DEV_ID" "$S/devlist.txt"; ck "device list contains id" $?

# --- 14. legacy compat: v1.0-style headerless request must FAIL (no legacy device on fresh install)
mkdir -p "$S/agent-legacy"; cp "$S/owner/cert.pem" "$S/agent-legacy/cert.pem"
FARCONTROL_HOME="$S/agent-legacy" FARCONTROL_URL="https://127.0.0.1:17788" FARCONTROL_TOKEN="some-old-token" \
  "$BIN" agent ping > "$S/legacy.txt" 2>&1
grep -q "no_legacy_device" "$S/legacy.txt"; ck "fresh install: headerless legacy request rejected (no legacy device)" $?

# --- 15. panic rotates device keys → old device key dies
FARCONTROL_HOME="$S/owner" "$BIN" panic "smoke panic" > "$S/panic.txt" 2>&1; ck "panic" $?
grep -q "device keys rotated" "$S/panic.txt"; ck "panic reports rotated device keys" $?
FARCONTROL_HOME="$S/agent" FARCONTROL_URL="https://127.0.0.1:17788" \
  "$BIN" agent exec "$SES_ID" echo nope > "$S/afterpanic.txt" 2>&1
grep -qE "session_revoked|invalid_signature" "$S/afterpanic.txt"; ck "panic kills access (key rotated → signature fails, fail closed)" $?

kill $DPID 2>/dev/null
echo; echo "SMOKE RESULT: PASS=$PASS FAIL=$FAIL"
