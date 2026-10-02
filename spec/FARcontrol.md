# FARcontrol

**Document:** Product & Technical Specification  
**Version:** 0.1.0-draft  
**Status:** Production-grade architecture specification  
**Audience:** Founder, backend engineers, agent/runtime engineers, security engineers, frontend engineers, DevOps/SRE, QA  
**Primary Goal:** Provide a secure, temporary, user-controlled bridge that lets an external AI Agent request and receive scoped access to a user's local computer through a FARcontrol session.

---

## 0. Executive Definition

FARcontrol is a **local control-plane + remote session gateway** designed to let an external AI Agent operate a user's computer without giving the AI an unconditional or permanent remote-access channel.

The core security model is:

> **Authentication is not authorization.**  
> **A valid Device ID + secret can create a connection request, but cannot by itself grant machine access.**  
> **The user explicitly approves the request, chooses a duration, chooses an access scope, and the resulting session expires or is revoked.**

The product has two primary operating modes:

1. **User / Device mode** via `frtrol start`
2. **AI Agent mode** via `frtrol agent`

The initial permission model intentionally contains only two access levels:

- **Terminal Only**
- **Full Access**

The initial session lifetime policy is:

- **Minimum:** 5 hours
- **Maximum:** 3 days

These values are product defaults and must be enforced server-side, not trusted to the client.

---

# 1. Product Vision

FARcontrol acts as the user's **permissioned bridge between an AI platform and a local machine**.

The remote AI remains the intelligence layer. FARcontrol is the control and security layer. The local FARcontrol Agent is the execution layer.

Conceptually:

```text
                    REMOTE / INTERNET

        +-------------------------------+
        |         AI PLATFORM           |
        |  Z.ai / Qwen / other client   |
        +---------------+---------------+
                        |
                 FAR Agent Session
                        |
                Authenticated channel
                        |
        +---------------v---------------+
        |          FARcontrol            |
        |  Session + Policy + Audit      |
        +---------------+---------------+
                        |
                 Encrypted tunnel
                        |
             +----------v----------+
             |   Local FAR Agent   |
             |      on Laptop      |
             +----------+----------+
                        |
          +-------------+--------------+
          |             |              |
       Terminal       Files        Desktop/Apps
```

The product must preserve the following invariant:

```text
AI intent != machine authority
```

Every machine action must pass through FARcontrol's authorization boundary.

---

# 2. Goals

## 2.1 Primary goals

- Allow an external AI Agent to request a connection to a user's device.
- Authenticate the target device using a high-entropy secret.
- Require explicit user approval before remote control becomes active.
- Let the user choose session duration.
- Let the user choose an access scope.
- Provide a local CLI and local web UI.
- Allow access through NAT/firewalls without requiring inbound port forwarding in the standard deployment.
- Keep the user in control at all times.
- Support immediate session revocation.
- Record a tamper-evident audit trail.
- Keep the protocol provider-agnostic while offering initial AI identity choices.
- Make permissions extensible without changing the core session architecture.
- Fail closed on authentication, authorization, policy, or connectivity errors.

## 2.2 Non-goals for v0.1

- Unattended permanent remote administration.
- Hidden/background access unknown to the user.
- Credential extraction from browsers, password managers, or operating systems.
- Privilege escalation.
- Kernel-level remote control.
- Bypassing OS security controls.
- Password scraping or keylogging.
- Automatic privilege elevation without user action.
- Anonymous public device discovery.
- Arbitrary peer-to-peer connections without a FARcontrol session.

---

# 3. Core Terminology

## Device

A local computer running FARcontrol in server/device mode.

## User

The human who controls the Device and approves/rejects sessions.

## AI Agent

A remote automation client operating on behalf of an AI model/platform.

## Agent Identity

A structured identity describing the agent's company/provider and model.

Initial catalog:

- Z.ai
  - GLM 5.3
  - GLM 5.3 Flash
  - GLM 5.2
  - GLM 5.1
- Qwen
  - Qwen 3.8 MAX
  - Qwen 3.8 Plus
  - Qwen 3.7 Max
  - Qwen 3.7 Plus
  - Qwen 3.7 Turbo

**Important:** these are treated as an application identity catalog supplied by FARcontrol product configuration. FARcontrol must not imply external vendor verification unless the provider has actually authenticated the agent.

## Device ID

A public-ish identifier used by an AI Agent to identify a user's FARcontrol device. It is **not** a secret.

## Device Secret

The high-entropy device credential used to authenticate a connection request. User UX may call this the "24-character password". It is secret and must never be logged in plaintext.

## Connection Request

A pending request created after successful device authentication and before user approval.

## Session

A temporary authorized control relationship between one AI Agent and one Device.

## Capability / Access Scope

The set of machine actions a session may perform.

Initial scopes:

- `terminal_only`
- `full_access`

## Policy

The server-side rules governing session lifetime, capabilities, command execution, approval, rate limits, and revocation.

---

# 4. System Architecture

FARcontrol consists of four logical components.

## 4.1 Local CLI

Command: `frtrol`

Responsibilities:

- Start/stop local FARcontrol service.
- Show local device status.
- Show Device ID and onboarding information.
- Launch or expose local web UI.
- Approve/reject session requests.
- Select session duration.
- Select access scope.
- Revoke active sessions.
- Inspect local logs and status.
- Run diagnostics.
- Start AI Agent client mode.

## 4.2 Local FARcontrol Runtime

Long-running daemon/service on the user's machine.

Responsibilities:

- Maintain outbound control-plane connectivity.
- Authenticate to FARcontrol cloud/relay services.
- Track the local device.
- Receive and validate connection requests.
- Enforce session policy.
- Spawn isolated execution workers.
- Route approved commands to OS-level adapters.
- Collect stdout/stderr and operation metadata.
- Enforce expiration and revocation.
- Send audit events.

## 4.3 FARcontrol Control Plane

Cloud or remotely hosted service.

Responsibilities:

- Device registry.
- Agent request routing.
- Session state machine.
- Authentication metadata.
- Authorization/policy enforcement.
- Session token issuance.
- Relay/signaling where direct connectivity is unavailable.
- Audit-event ingestion.
- Rate limiting and abuse controls.
- Observability.

The control plane should not require plaintext access to user terminal output unless the architecture specifically requires it. End-to-end encryption between authorized endpoints is preferred.

## 4.4 Local Web UI

Hosted locally by the FARcontrol runtime, for example:

```text
http://127.0.0.1:<port>
```

Responsibilities:

- Device dashboard.
- Pending connection request screen.
- Session approval.
- Duration selector.
- Access selector.
- Active session display.
- One-click revoke.
- Recent audit log.
- Security settings.

The web UI must bind to loopback by default.

---

# 5. Trust Model

The trust hierarchy is:

```text
User
  > FARcontrol policy
      > session authorization
          > execution worker
              > AI command
```

The AI Agent is never treated as the top-level authority.

## 5.1 Trust boundaries

### Boundary A: AI platform -> Agent CLI

AI runtime invokes `frtrol agent`.

### Boundary B: Agent CLI -> FARcontrol control plane

Authenticated network interaction.

### Boundary C: Control plane -> user's local runtime

Authenticated encrypted session channel.

### Boundary D: Local runtime -> OS

High-risk boundary. Must be tightly controlled and observable.

### Boundary E: Local Web UI -> local runtime

Must require local authentication/session binding and CSRF protection where applicable.

---

# 6. Security Principles

## 6.1 Default deny

Every capability is denied unless explicitly granted.

## 6.2 Explicit user approval

Remote access does not become active until the user accepts.

## 6.3 Time-bounded authorization

Every session has an expiration timestamp.

## 6.4 Revocable authorization

User can revoke a session before expiration.

## 6.5 Short-lived session credentials

The device secret is used to authenticate the request but must not be reused as the long-lived data-plane session key.

## 6.6 No plaintext secrets in logs

Device secrets, session secrets, access tokens, cookies, and private keys must be redacted.

## 6.7 Fail closed

If policy validation fails, terminate or suspend the requested action rather than guessing.

## 6.8 Least privilege

`terminal_only` must expose only terminal capabilities.

## 6.9 User-visible control

The local UI must clearly display active remote access.

## 6.10 Auditable actions

Every privileged operation must produce an audit event.

---

# 7. Device Identity Model

Each Device receives:

```text
Device ID      : 8-character identifier
Device Secret  : 24-character high-entropy secret
```

## 7.1 Device ID format

The user requested a digit/character format. Recommended production format:

```text
ABCDEFGH
```

Character set should exclude ambiguous characters such as:

- `0`
- `O`
- `I`
- `l`
- `1`

Example:

```text
7K4M9P2X
```

The exact public format should be versioned.

## 7.2 Device secret format

The UI may display a 24-character secret, but implementation must use a cryptographically secure random generator.

Recommended properties:

- At least 128 bits of effective entropy.
- Generated using an OS CSPRNG.
- Never derived from hostname, username, MAC address, serial number, or timestamp.
- Stored locally using OS-protected secret storage where available.
- Stored server-side as a verifier/hash rather than reversible plaintext.
- Rotatable.
- Revocable.

Example UX only:

```text
fQ7xK2mP9vR4sN8tL3wY6cZa
```

Do not use this literal value in production.

---

# 8. `frtrol start` Specification

## 8.1 Command

```bash
frtrol start
```

## 8.2 Expected behavior

1. Load local FARcontrol configuration.
2. Generate device identity on first run if absent.
3. Load existing device identity on subsequent starts.
4. Bind local web service to loopback.
5. Start FARcontrol runtime.
6. Establish outbound connection to the control plane.
7. Register/update device metadata.
8. Report local server status.

## 8.3 Example output

```text
$ frtrol start

Starting a server....

Server online at: 127.0.0.1:7481
Control plane: ONLINE

Information
────────────────────────────────────────
Device Name    : ALBI-LAPTOP
OS             : Windows 11
Architecture   : x64
FARcontrol     : v0.1.0
Runtime        : ONLINE
Web UI         : http://127.0.0.1:7481

Your ID        : 7K4M9P2X
Your Password  : fQ7xK2mP9vR4sN8tL3wY6cZa
────────────────────────────────────────

⚠ Keep your password private.
Only provide it to your authorized AI Agent.
```

## 8.4 Subsequent starts

The system should not print the secret by default after initial setup.

Recommended:

```text
Your ID        : 7K4M9P2X
Your Password  : ********

Use `frtrol credential reveal` only after explicit local confirmation.
```

## 8.5 Start options

```text
frtrol start
frtrol start --no-web
frtrol start --port 7481
frtrol start --host 127.0.0.1
frtrol start --foreground
frtrol start --verbose
```

Production builds should reject unsafe bindings unless explicitly enabled.

---

# 9. `frtrol agent` Specification

## 9.1 Command

```bash
frtrol agent
```

The command launches the AI Agent identity and connection flow.

## 9.2 Provider selection

```text
Welcome to FARcontrol Agent.

Tell us what model you are?
Select your company.

[1] Z.ai
[2] Qwen
```

For v0.1, only these two choices are exposed in the default catalog.

## 9.3 Z.ai model selection

```text
Z.ai
────────────────────
[1] GLM 5.3
[2] GLM 5.3 Flash
[3] GLM 5.2
[4] GLM 5.1
────────────────────
Select model:
>
```

## 9.4 Qwen model selection

```text
Qwen
────────────────────
[1] Qwen 3.8 MAX
[2] Qwen 3.8 Plus
[3] Qwen 3.7 Max
[4] Qwen 3.7 Plus
[5] Qwen 3.7 Turbo
────────────────────
Select model:
>
```

## 9.5 Identity object

Internally:

```json
{
  "provider": "z_ai",
  "model": "glm-5.3",
  "identityVersion": 1,
  "clientVersion": "0.1.0"
}
```

This object identifies the requesting agent. It does not grant authority.

---

# 10. Device Connection Flow

After model selection:

```text
Insert a device ID:
>
```

The agent sends a device lookup/authentication request.

Expected UX:

```text
Insert a device ID:
> 7K4M9P2X

Searching....

Found a device:

Information device
────────────────────────────
Device Name   : ALBI-LAPTOP
OS            : Windows 11
Architecture  : x64
FARcontrol    : v0.1.0
Status        : ONLINE
────────────────────────────

Tell me the password:
>
```

Upon success:

```text
OK password accepted!
Sending a connection request...
```

Upon failure:

```text
Authentication failed.
The Device ID or password is invalid, expired, or unavailable.
```

Do not reveal whether a Device ID exists to unauthenticated callers. To prevent enumeration, the public lookup path should return generic results unless the request is sufficiently authenticated or rate-limited.

---

# 11. Connection Request Object

Logical request schema:

```json
{
  "requestId": "req_01J...",
  "deviceId": "7K4M9P2X",
  "agent": {
    "provider": "z_ai",
    "model": "glm-5.3"
  },
  "createdAt": "2026-10-02T13:00:00Z",
  "expiresAt": "2026-10-02T13:05:00Z",
  "status": "PENDING",
  "requestedScope": null,
  "requestedDurationHours": null
}
```

The agent should not be able to pre-approve its own requested scope.

The final scope and duration must be selected by the User/Device side and enforced server-side.

---

# 12. User Approval UX

The request must appear both in the local terminal when practical and in the local web UI.

Example:

```text
╔══════════════════════════════════════╗
║      FARcontrol Connection Request   ║
╚══════════════════════════════════════╝

AI Agent wants to connect.

Company : Z.ai
Model   : GLM 5.3
Device  : 7K4M9P2X

Choose access duration:

[1] 5 Hours
[2] 12 Hours
[3] 24 Hours
[4] 2 Days
[5] 3 Days

Choose access level:

[1] Terminal Only
[2] Full Access

[ ACCEPT ]  [ DENY ]
```

The final user-selected policy is authoritative.

---

# 13. Session Lifetime

## 13.1 Bounds

```text
MIN = 5 hours
MAX = 3 days
```

Recommended internal representation:

```text
notBefore = approval timestamp
expiresAt = approval timestamp + selected duration
```

## 13.2 Expiration

When `now >= expiresAt`:

1. Mark session `EXPIRED`.
2. Revoke all session credentials.
3. Close open execution streams.
4. Terminate or cancel active workers according to the operation safety policy.
5. Emit `SESSION_EXPIRED` audit event.
6. Notify the local UI.

## 13.3 Renewal

v0.1 should require a fresh approval rather than silently extending an active session.

A future version may support renewal as an explicit user action.

---

# 14. Access Levels

## 14.1 `terminal_only`

Purpose: allow AI to control a shell/terminal environment.

Initial capabilities:

```text
terminal.open
terminal.execute
terminal.read_stdout
terminal.read_stderr
terminal.close
```

The runtime should expose command execution through a controlled session worker rather than passing a raw unauthenticated socket to the OS shell.

## 14.2 `full_access`

Purpose: allow broader computer interaction.

Conceptual capabilities:

```text
terminal.*
process.read
process.control
filesystem.read
filesystem.write
application.launch
application.close
desktop.read
desktop.input
```

The exact capability matrix must be OS-specific.

**Critical:** Full Access is a product label, not a bypass of the operating system. FARcontrol must still enforce OS permissions and should avoid system-level privileges unless explicitly configured.

---

# 15. Permission Architecture

FARcontrol should model access using capabilities internally even though the user-facing UI exposes only two levels.

Example:

```json
{
  "scope": "terminal_only",
  "capabilities": [
    "terminal.open",
    "terminal.execute",
    "terminal.read_stdout",
    "terminal.read_stderr"
  ]
}
```

Full Access:

```json
{
  "scope": "full_access",
  "capabilities": [
    "terminal.open",
    "terminal.execute",
    "terminal.read_stdout",
    "terminal.read_stderr",
    "process.read",
    "process.control",
    "filesystem.read",
    "filesystem.write",
    "application.launch",
    "application.close",
    "desktop.read",
    "desktop.input"
  ]
}
```

This gives future versions room to introduce granular permissions without redesigning the entire session layer.

---

# 16. Session State Machine

```text
                   +----------------+
                   |                |
                   v                |
REQUESTED -> AUTHENTICATED ---------+
                   |
                   v
               PENDING_APPROVAL
                 /        \
                /          \
            DENIED        ACCEPTED
              |              |
              v              v
            CLOSED       AUTHORIZED
                             |
                             v
                          ACTIVE
                       /      |      \
                      /       |       \
                  REVOKED   EXPIRED  DISCONNECTED
                      |        |         |
                      +--------+---------+
                               |
                               v
                             CLOSED
```

Recommended states:

- `REQUESTED`
- `AUTHENTICATED`
- `PENDING_APPROVAL`
- `AUTHORIZED`
- `ACTIVE`
- `REVOKED`
- `EXPIRED`
- `DENIED`
- `DISCONNECTED`
- `CLOSED`
- `ERROR`

State transitions must be atomic and idempotent.

---

# 17. Session Object

Example:

```json
{
  "sessionId": "ses_01JABC...",
  "deviceId": "7K4M9P2X",
  "agent": {
    "provider": "z_ai",
    "model": "glm-5.3"
  },
  "scope": "terminal_only",
  "capabilities": [
    "terminal.open",
    "terminal.execute",
    "terminal.read_stdout",
    "terminal.read_stderr"
  ],
  "status": "ACTIVE",
  "createdAt": "2026-10-02T13:20:00Z",
  "approvedAt": "2026-10-02T13:21:12Z",
  "expiresAt": "2026-10-03T13:21:12Z",
  "revokedAt": null,
  "connectionMode": "relay"
}
```

---

# 18. Secure Session Handshake

The exact wire protocol may evolve, but the v0.1 handshake should conceptually be:

```text
Agent                    Control Plane                 Device
  |                            |                          |
  |-- identify provider/model->|                          |
  |-- device ID + auth proof ->|                          |
  |                            |-- authenticate ---------->|
  |                            |<-- device confirmation ---|
  |<-- request accepted -------|                          |
  |                            |                          |
  |                            |-- approval request ------>|
  |                            |<-- user approval ----------|
  |<-- session authorization --|                          |
  |                            |-- secure channel setup -->|
  |<========== encrypted session / relay ===============>|
```

## 18.1 Avoid putting raw password on every request

The 24-character device secret must not be sent repeatedly after initial authentication.

Preferred design:

1. Device secret establishes proof of possession.
2. Server issues short-lived session material.
3. Data plane uses separate ephemeral keys.
4. Session material is invalid after session closure.

## 18.2 Replay resistance

Requests must contain:

- unique request ID
- timestamp
- nonce
- server-issued challenge where practical
- signature/MAC proof

Replay of an old valid request must fail.

---

# 19. Network Connectivity Model

The standard deployment should favor **outbound connections from the user's device**.

That means the user's laptop can sit behind:

- NAT
- home router
- corporate NAT
- common firewall configurations

without opening an arbitrary inbound port.

Recommended transport stack:

```text
Application protocol
        ↓
Secure WebSocket / HTTP2 / QUIC transport
        ↓
TLS 1.3
        ↓
Internet
```

The architecture should support a relay when direct connectivity is unavailable.

Optional future optimization:

```text
Direct encrypted P2P
      ↓ fallback
FARcontrol relay
```

Security policy must remain identical regardless of transport path.

---

# 20. Cryptography

Recommended baseline:

- TLS 1.3 for network transport.
- OS CSPRNG for secret generation.
- Modern password/secret KDF or verifier appropriate to the credential model.
- Ephemeral session keys.
- Authenticated encryption.
- Certificate validation with hostname verification.

Do not implement custom cryptography primitives.

Do not use:

- MD5
- SHA-1 for password storage
- reversible encryption for server-stored device secrets
- home-grown encryption schemes
- static global encryption keys shared by every device

---

# 21. Local Secret Storage

Preferred platform stores:

### Windows

Use DPAPI / Windows Credential Manager or an equivalent OS-protected secret facility.

### macOS

Use Keychain.

### Linux

Use Secret Service/keyring where available, with a protected file fallback only when documented and permission-restricted.

Device secrets should not be stored in:

```text
~/.farcontrol/config.json
```

as plaintext.

Configuration may store a non-secret identifier while secrets reside in a secure store.

---

# 22. Local Web UI Security

Default binding:

```text
127.0.0.1 only
```

Security requirements:

- local authentication/session cookie
- SameSite protections
- Secure cookie when HTTPS is used
- CSRF protection for state-changing endpoints
- strict content security policy
- no inline remote scripts by default
- explicit origin checking
- localhost/loopback origin validation
- request rate limiting
- auto logout / session timeout
- no secret exposure in browser telemetry

UI must display active remote control prominently.

Example banner:

```text
⚠ REMOTE AI SESSION ACTIVE

Agent: Z.ai / GLM 5.3
Access: Terminal Only
Expires: 23h 41m

[ REVOKE ACCESS ]
```

---

# 23. CLI Command Tree

Recommended v0.1 CLI:

```text
frtrol start
frtrol stop
frtrol status
frtrol agent
frtrol sessions
frtrol sessions list
frtrol sessions inspect <session-id>
frtrol sessions revoke <session-id>
frtrol requests
frtrol requests list
frtrol requests approve <request-id>
frtrol requests deny <request-id>
frtrol credential status
frtrol credential rotate
frtrol credential reveal
frtrol logs
frtrol doctor
frtrol version
```

The initial user-facing onboarding can stay minimal with only:

```text
frtrol start
frtrol agent
```

Additional commands provide production operability.

---

# 24. Request Approval CLI

Example:

```text
$ frtrol requests

Pending connection requests:

ID       Provider   Model       Created        Status
---------------------------------------------------------
REQ91A   Z.ai       GLM 5.3     13:41          PENDING

Approve request? [y/N]
```

Then:

```text
Select duration:
[1] 5h
[2] 12h
[3] 24h
[4] 2d
[5] 3d

Select access:
[1] Terminal Only
[2] Full Access
```

---

# 25. Terminal Execution Architecture

The terminal subsystem should not simply run:

```text
shell(command_from_network)
```

as a direct string without controls.

Preferred architecture:

```text
Remote command
     ↓
Session validator
     ↓
Capability validator
     ↓
Command envelope validator
     ↓
Execution worker
     ↓
OS process
     ↓
stdout/stderr stream
```

## 25.1 Command envelope

Example:

```json
{
  "operationId": "op_01J...",
  "sessionId": "ses_01J...",
  "type": "terminal.execute",
  "shell": "powershell",
  "command": "Get-ChildItem",
  "timeoutMs": 30000,
  "cwd": "C:\\Users\\Albi",
  "stdin": null
}
```

## 25.2 Required validation

- session active
- session not expired
- capability granted
- operation ID unique
- command payload size within limit
- cwd allowed/valid
- shell type supported
- timeout within policy
- environment size within policy
- concurrency within policy

## 25.3 Output limits

Prevent memory exhaustion by enforcing:

- maximum output bytes
- maximum line length
- maximum stream duration
- maximum concurrent processes

Example defaults:

```text
MAX_OUTPUT_BYTES = configurable
MAX_PROCESS_RUNTIME = configurable
MAX_CONCURRENT_TERMINALS = configurable
```

---

# 26. Process Isolation

For `terminal_only`, the preferred design is a dedicated worker per active terminal session.

Worker properties:

- inherited only necessary environment
- no access to FARcontrol secret storage
- explicit working directory
- resource limits where the OS permits
- cancellation support
- clean shutdown on session revoke

Future hardening may use:

- Windows Job Objects
- Linux namespaces/cgroups
- macOS sandbox facilities where practical

The runtime must not grant administrator/root privileges to the worker by default.

---

# 27. Full Access Architecture

Full Access should be implemented as a set of controlled OS adapters, not one giant unrestricted API.

Example:

```text
Full Access
├── Terminal Adapter
├── Filesystem Adapter
├── Process Adapter
├── Application Adapter
└── Desktop Adapter
```

Each adapter validates:

- current session
- capability
- operation type
- target resource
- policy constraints
- user-revoke state

This keeps a compromised adapter from automatically becoming the entire system.

---

# 28. Session Revoke

User command:

```text
frtrol sessions revoke <session-id>
```

or local UI:

```text
[ REVOKE ACCESS ]
```

Required sequence:

1. Mark session `REVOKED` atomically.
2. Invalidate data-plane credentials.
3. Notify control plane.
4. Cancel active workers.
5. Close active streams.
6. Emit audit events.
7. Update UI immediately.

Revocation must be idempotent.

Repeated revoke requests should not produce conflicting state.

---

# 29. Emergency Kill Switch

Recommended product-level feature:

```text
frtrol emergency-stop
```

Effect:

- revoke every active remote session
- reject all pending connection approvals
- disable new remote sessions until manually re-enabled

UI:

```text
                 FARcontrol

REMOTE ACCESS: ENABLED

[ EMERGENCY STOP ALL ]
```

This is a critical operational safety feature.

---

# 30. Audit Logging

Every security-relevant event should be logged.

Event examples:

```text
DEVICE_REGISTERED
DEVICE_CONNECTED
AGENT_IDENTIFIED
AUTH_SUCCESS
AUTH_FAILURE
REQUEST_CREATED
REQUEST_APPROVED
REQUEST_DENIED
SESSION_CREATED
SESSION_ACTIVE
SESSION_REVOKED
SESSION_EXPIRED
COMMAND_STARTED
COMMAND_COMPLETED
COMMAND_FAILED
PROCESS_TERMINATED
CREDENTIAL_ROTATED
EMERGENCY_STOP
```

## 30.1 Event structure

```json
{
  "eventId": "evt_01J...",
  "eventType": "SESSION_CREATED",
  "timestamp": "2026-10-02T13:22:00Z",
  "deviceId": "7K4M9P2X",
  "sessionId": "ses_01J...",
  "agentProvider": "z_ai",
  "agentModel": "glm-5.3",
  "scope": "terminal_only",
  "source": "local_runtime",
  "result": "success"
}
```

Never include:

- device secret
- session private key
- authentication bearer token
- passwords typed into the terminal

---

# 31. Audit Integrity

For production deployments, logs should be tamper-evident.

Possible mechanism:

```text
Event N hash = H(Event N || Event N-1 hash)
```

This forms a simple hash chain.

Central log transport should use authenticated channels, and server-side audit records should be append-only where practical.

---

# 32. Data Model

Minimum persistent entities:

## Device

```text
id
public_id
name
os
architecture
runtime_version
status
created_at
last_seen_at
secret_verifier
credential_version
```

## Agent Identity

```text
id
provider
model
client_version
created_at
last_seen_at
```

## Connection Request

```text
id
device_id
agent_id
status
created_at
expires_at
authenticated_at
approved_at
denied_at
```

## Session

```text
id
device_id
agent_id
request_id
scope
capabilities
status
created_at
approved_at
expires_at
revoked_at
connection_mode
```

## Operation

```text
id
session_id
type
started_at
finished_at
status
exit_code
output_bytes
error_code
```

## Audit Event

```text
event_id
timestamp
device_id
session_id
request_id
event_type
actor
metadata
previous_hash
current_hash
```

---

# 33. API Design

The external API must distinguish control-plane operations from data-plane operations.

## Control API examples

```http
POST /v1/device/authenticate
POST /v1/connection-requests
GET  /v1/devices/{deviceId}
GET  /v1/connection-requests/{requestId}
POST /v1/connection-requests/{requestId}/approve
POST /v1/connection-requests/{requestId}/deny
POST /v1/sessions/{sessionId}/revoke
GET  /v1/sessions/{sessionId}
```

## Session transport

A persistent channel may be used:

```text
wss://control.example.com/v1/session/{sessionId}
```

The actual production domain should be configurable.

---

# 34. Example Approval API

Request:

```json
{
  "durationSeconds": 86400,
  "scope": "terminal_only"
}
```

Server validation:

```text
5h <= duration <= 72h
scope ∈ {terminal_only, full_access}
request.status == PENDING_APPROVAL
```

Response:

```json
{
  "sessionId": "ses_01J...",
  "status": "AUTHORIZED",
  "scope": "terminal_only",
  "expiresAt": "2026-10-03T13:22:00Z"
}
```

---

# 35. Concurrency Policy

v0.1 recommended default:

```text
Maximum active remote sessions per device: 1
```

Reason:

- easier user understanding
- easier auditing
- avoids two AIs controlling the same desktop simultaneously
- reduces race conditions

Future versions may support multiple concurrent sessions with explicit conflict policy.

---

# 36. Agent Identity vs Provider Authentication

The selection menu:

```text
Z.ai
Qwen
```

is an **identity declaration**, not proof that the caller truly comes from that provider.

Production-grade identity verification should therefore be separated into two concepts:

```text
Agent Identity
    = declared provider + model

Provider Authentication
    = optional cryptographic/provider-backed verification
```

v0.1 can use identity declaration for the UX while still treating the Device ID + secret + user approval as the actual access gate.

Future versions can introduce provider attestations without changing the session state machine.

---

# 37. Error Codes

Suggested stable error codes:

```text
FRT-001 INVALID_DEVICE_ID
FRT-002 INVALID_DEVICE_SECRET
FRT-003 DEVICE_OFFLINE
FRT-004 DEVICE_NOT_FOUND
FRT-005 REQUEST_EXPIRED
FRT-006 REQUEST_DENIED
FRT-007 SESSION_EXPIRED
FRT-008 SESSION_REVOKED
FRT-009 CAPABILITY_DENIED
FRT-010 INVALID_SCOPE
FRT-011 INVALID_DURATION
FRT-012 RATE_LIMITED
FRT-013 PROTOCOL_VERSION_MISMATCH
FRT-014 WORKER_START_FAILED
FRT-015 OPERATION_TIMEOUT
FRT-016 OUTPUT_LIMIT_EXCEEDED
FRT-017 CONTROL_PLANE_UNAVAILABLE
FRT-018 LOCAL_RUNTIME_UNAVAILABLE
FRT-019 USER_CONFIRMATION_REQUIRED
FRT-020 INTERNAL_ERROR
```

Error messages shown to users should be understandable. Internal logs may contain more diagnostic detail.

---

# 38. Rate Limiting

At minimum:

### Device authentication

Aggressive rate limit with progressive backoff.

### Connection requests

Limit requests per Device, Agent Identity, source address, and account context.

### Command execution

Limit operations per second and concurrent workers.

### UI mutations

Rate-limit repeated approval/revoke calls.

A device secret must not be brute-forceable through an unlimited request stream.

---

# 39. Abuse Prevention

FARcontrol is fundamentally a remote-control capability and must be treated as a high-impact security surface.

Required controls:

- clear user consent
- explicit remote-session visibility
- session expiry
- one-click revoke
- audit events
- authentication throttling
- request throttling
- no hidden persistence
- no covert startup installation
- no credential harvesting
- no silent privilege elevation
- no bypass of host OS permissions

---

# 40. Startup / Persistence

Installation can optionally register FARcontrol as a standard OS service, but installation and startup must be transparent to the user.

The product should expose:

```text
frtrol start
frtrol stop
```

and optionally:

```text
frtrol enable-autostart
frtrol disable-autostart
```

Auto-start should never automatically grant an AI remote access. It merely starts the local runtime.

---

# 41. Device Lifecycle

```text
NEW
 ↓
REGISTERED
 ↓
ONLINE
 ↓
OFFLINE
 ↓
ONLINE
```

Credential rotation:

```text
ACTIVE CREDENTIAL
       ↓
ROTATE
       ↓
NEW CREDENTIAL
       ↓
OLD CREDENTIAL INVALID
```

Device removal:

```text
REVOKE DEVICE
 ↓
ALL SESSIONS REVOKED
 ↓
DEVICE DISABLED
 ↓
NEW REQUESTS DENIED
```

---

# 42. Credential Rotation

Command:

```bash
frtrol credential rotate
```

Recommended flow:

```text
Rotate Device Password?

This invalidates the current device credential.
Existing sessions will remain active unless policy says otherwise.

[YES] [NO]
```

Production recommendation: rotate should revoke pending authentication attempts and invalidate all unpublished authentication challenges. Existing sessions should be governed by explicit policy, but a security-sensitive rotation should support an optional “revoke all” path.

---

# 43. Local Configuration

Example conceptual config:

```yaml
version: 1
runtime:
  host: 127.0.0.1
  port: 7481
  web_ui: true
control_plane:
  endpoint: https://control.example.com
security:
  require_user_approval: true
  min_session_hours: 5
  max_session_hours: 72
  max_active_sessions: 1
session:
  default_scope: terminal_only
logging:
  level: info
```

Secrets should not live in this file.

---

# 44. Versioning

Use semantic versioning for the application:

```text
MAJOR.MINOR.PATCH
```

Protocol version should be independent:

```text
FAR-PROTO/1
```

Compatibility rules:

- clients advertise supported protocol versions
- server negotiates one mutually supported version
- unsupported versions fail clearly
- breaking protocol changes require an explicit version change

---

# 45. CLI Output Stability

Human-readable output can evolve, but machine-readable mode should be stable:

```bash
frtrol status --json
frtrol sessions list --json
frtrol requests list --json
```

Example:

```json
{
  "status": "online",
  "deviceId": "7K4M9P2X",
  "activeSessions": 1
}
```

This allows scripts and local automation to integrate without screen-scraping terminal text.

---

# 46. Diagnostics

Command:

```bash
frtrol doctor
```

Checks:

```text
[OK] Local runtime
[OK] Local secret store
[OK] Device identity
[OK] Control plane DNS
[OK] TLS connectivity
[OK] Time synchronization
[OK] Web UI binding
[OK] Session subsystem
[OK] Execution worker
```

If something fails:

```text
[FAIL] Control plane TLS connectivity
Code: FRT-017
Action: Verify network access and system time.
```

---

# 47. Time Handling

All internal timestamps must use UTC.

The UI may render local time.

Use a monotonic clock for local timeout enforcement where possible in addition to wall-clock timestamps.

This protects against clock jumps.

---

# 48. Failure Behavior

## Control plane unavailable

- Local device remains in local-only mode.
- No new remote session authorization occurs.
- Existing sessions follow a strict fail-safe policy.

Recommended v0.1:

```text
control plane lost
      ↓
existing session grace period
      ↓
if not revalidated
      ↓
terminate session
```

## Local runtime crash

- Active session becomes disconnected.
- Remote commands stop.
- Workers are terminated or orphan-safe.
- Service restarts according to OS service policy.

## User UI unavailable

Pending requests remain pending until expiration. They must not auto-approve.

---

# 49. Security Events and Alerts

Recommended user-visible warnings:

```text
⚠ New AI connection request
```

```text
⚠ AI session expires in 15 minutes
```

```text
⚠ Remote access revoked
```

```text
⚠ Repeated authentication failures detected
```

A future version may integrate desktop notifications.

---

# 50. Observability

Metrics:

```text
farcontrol_devices_online
farcontrol_connection_requests_total
farcontrol_connection_requests_denied_total
farcontrol_auth_failures_total
farcontrol_sessions_active
farcontrol_sessions_expired_total
farcontrol_sessions_revoked_total
farcontrol_command_latency_ms
farcontrol_command_failures_total
farcontrol_worker_crashes_total
farcontrol_relay_connections_total
```

Tracing should include a correlation ID across:

```text
request -> session -> operation
```

Never put secret material into trace attributes.

---

# 51. Structured Logging

Log JSON internally.

Example:

```json
{
  "timestamp": "2026-10-02T13:32:01Z",
  "level": "INFO",
  "service": "farcontrol-runtime",
  "event": "SESSION_CREATED",
  "deviceId": "7K4M9P2X",
  "sessionId": "ses_01J...",
  "agentProvider": "z_ai",
  "agentModel": "glm-5.3",
  "scope": "terminal_only"
}
```

Redaction middleware should run before logs are emitted.

---

# 52. Recommended Repository Structure

```text
farcontrol/
├── cmd/
│   └── frtrol/
├── apps/
│   ├── runtime/
│   ├── agent/
│   └── web-ui/
├── internal/
│   ├── auth/
│   ├── identity/
│   ├── sessions/
│   ├── policy/
│   ├── transport/
│   ├── relay/
│   ├── execution/
│   ├── terminal/
│   ├── filesystem/
│   ├── desktop/
│   ├── audit/
│   └── storage/
├── api/
│   └── v1/
├── protocol/
│   └── far-proto-v1/
├── web/
├── tests/
│   ├── unit/
│   ├── integration/
│   ├── e2e/
│   ├── security/
│   └── protocol/
├── packaging/
│   ├── windows/
│   ├── macos/
│   └── linux/
├── docs/
└── FARcontrol.md
```

Exact language choice is implementation-specific. The architecture should remain language-neutral.

---

# 53. Recommended Implementation Layers

```text
CLI Layer
   ↓
Application Layer
   ↓
Policy / Authorization Layer
   ↓
Session Layer
   ↓
Transport Layer
   ↓
Execution Layer
   ↓
OS Adapters
```

No network handler should directly invoke arbitrary OS operations without passing through the policy/session layer.

---

# 54. API Authorization Rules

For every remote operation:

```text
1. Parse request
2. Authenticate transport
3. Resolve session
4. Verify session status == ACTIVE
5. Verify now < expiresAt
6. Verify capability
7. Validate target/resource
8. Apply operation policy
9. Execute
10. Emit audit event
11. Return result
```

This ordering should be encoded centrally so individual adapters cannot accidentally bypass authorization.

---

# 55. Idempotency

State-changing requests should carry idempotency keys.

Example:

```text
Idempotency-Key: req-action-123
```

This matters for:

- approve
- deny
- revoke
- credential rotation
- emergency stop

Repeated messages should result in one logical state transition.

---

# 56. Replay and Race Conditions

Important race:

```text
T0 user clicks REVOKE
T1 AI sends COMMAND
```

The command must be rejected if the revocation wins the authoritative state check.

Use atomic state transitions and transactional semantics.

A revoked session must never be resurrected by a delayed network packet.

---

# 57. Multi-Device Support

A user may eventually have:

```text
ALBI-LAPTOP
ALBI-DESKTOP
ALBI-MINI-PC
ALBI-SERVER
```

Each receives a unique Device ID.

The AI agent selects one target device at a time.

Future UI:

```text
Your Devices
────────────────────────────
7K4M9P2X   ALBI-LAPTOP      ONLINE
2Q8W6N4B   ALBI-DESKTOP     OFFLINE
9P3K7M5T   ALBI-SERVER      ONLINE
```

---

# 58. Privacy Design

FARcontrol should minimize cloud-side data.

The control plane may need to know:

- device public ID
- device online/offline state
- software version
- session metadata
- agent identity metadata
- audit metadata

It should avoid collecting unnecessary:

- personal files
- clipboard contents
- browser history
- passwords
- unrelated process memory

Data-plane payloads should be retained only as necessary for the active session and explicit audit requirements.

---

# 59. User Experience Principles

FARcontrol UI should make four things obvious:

```text
WHO is connected?
WHAT can they access?
UNTIL when?
HOW do I stop it?
```

At any moment, the user should be able to answer these four questions in a few seconds.

---

# 60. Example End-to-End Scenario

## Step 1: User

```bash
frtrol start
```

Output:

```text
Server online.
Your ID: 7K4M9P2X
```

## Step 2: AI

```bash
frtrol agent
```

Select:

```text
Z.ai
GLM 5.3
```

## Step 3: AI identifies target

```text
Insert a device ID:
> 7K4M9P2X
```

## Step 4: Authentication

```text
Tell me the password:
> ********
```

Result:

```text
OK password accepted!
Sending a connection request...
```

## Step 5: User approval

```text
New AI connection request
Company : Z.ai
Model   : GLM 5.3

Duration:
5h - 3d

Access:
Terminal Only
Full Access
```

User selects:

```text
Duration: 12h
Access: Terminal Only
Accept
```

## Step 6: Session

```text
SESSION ACTIVE
Agent: Z.ai / GLM 5.3
Access: Terminal Only
Expires: in 12h
```

## Step 7: AI command

```text
terminal.execute
command = "pwd"
```

## Step 8: FARcontrol validation

```text
Session active       ✓
Not expired          ✓
Capability granted   ✓
Payload valid        ✓

Execute
```

## Step 9: User revokes

```text
[ REVOKE ACCESS ]
```

Result:

```text
Session revoked.
Remote access terminated.
```

---

# 61. Threat Model

FARcontrol must explicitly model the following attackers.

## Attacker A: Guessing Device Secret

Mitigations:

- high entropy
- rate limiting
- progressive backoff
- lockout/temporary challenge blocking
- alerting

## Attacker B: Stolen Device Secret

Mitigations:

- user approval still required
- request expiry
- request rate limits
- credential rotation
- audit visibility

## Attacker C: Compromised AI Agent

Mitigations:

- scoped capabilities
- temporary sessions
- one active session default
- command/resource controls
- revoke
- audit

## Attacker D: Compromised Control Plane

Mitigations:

- endpoint authentication
- mutual trust model where practical
- end-to-end session encryption
- device-side authorization policy
- local user approval
- fail-closed behavior

## Attacker E: Local Malware

FARcontrol cannot fully protect against a fully compromised host OS. It must therefore:

- minimize privileges
- isolate workers
- protect secrets using the OS
- make active sessions visible
- provide emergency revoke

---

# 62. Security Boundary: User Approval Must Be Local

A particularly important rule:

> The remote AI must not be able to approve its own request.

Approval must originate from a trusted local user-control path.

This can be:

- local CLI
- loopback web UI
- OS-native local confirmation in a future release

A remote web endpoint should not be the primary approval UI unless a stronger authentication model is introduced.

---

# 63. Why the 24-Character Password Is Not the Session Token

The product UX calls the secret a password, but architecturally it should be treated as a **device authentication credential**, not a persistent remote-control token.

The lifecycle should be:

```text
Device Secret
     ↓
Authentication Proof
     ↓
Connection Request
     ↓
User Approval
     ↓
Temporary Session Credential
     ↓
Session
     ↓
Expiration / Revoke
```

That separation sharply reduces the blast radius of session compromise.

---

# 64. Full Access Safety Policy

Although v0.1 exposes only `Full Access` as a single option, the implementation should internally support deny rules for dangerous categories where reasonable.

Possible policy controls:

```text
network_sensitive_actions
credential_store_access
security_product_tampering
system_policy_modification
boot_configuration
kernel_driver_installation
```

These can be denied even under Full Access unless the user explicitly enables a future elevated mode.

The product should never describe such controls as a guarantee against all host compromise.

---

# 65. Session UX Copy

Preferred language:

```text
Connection request received.

AI Agent: Z.ai / GLM 5.3

This request does not have access yet.
Choose a duration and access level to continue.
```

After approval:

```text
Connection approved.

Access: Terminal Only
Duration: 12 hours

FARcontrol is now protecting this session.
```

After revoke:

```text
Remote access revoked.
The AI Agent can no longer execute operations on this device.
```

---

# 66. Accessibility and CLI Quality

CLI requirements:

- works without color
- supports keyboard-only operation
- clear error messages
- confirmation before destructive local actions
- readable on narrow terminal widths
- stable exit codes

Exit codes:

```text
0 = success
1 = generic failure
2 = invalid command/usage
3 = authentication failure
4 = authorization denied
5 = timeout
6 = unavailable
7 = conflict/state race
```

---

# 67. Configuration Validation

At startup, validate:

- config schema version
- port range
- safe host binding
- control-plane URL
- TLS configuration
- local secret store availability
- policy bounds

Invalid configuration should prevent unsafe startup rather than silently correcting security settings.

---

# 68. Database / Storage Strategy

For the local runtime, v0.1 may use a lightweight embedded database such as SQLite for:

- local sessions
- pending requests cache
- audit events
- configuration metadata

The cloud control plane can use a transactional database such as PostgreSQL.

Caching may use Redis or an equivalent only where required for scale and rate limiting.

The architecture should not make Redis the sole source of session truth.

---

# 69. Transactional Session State

Session state transitions should be transactional.

Example:

```sql
UPDATE sessions
SET status = 'REVOKED', revoked_at = CURRENT_TIMESTAMP
WHERE id = ?
  AND status = 'ACTIVE';
```

If affected rows = 0, return an idempotent or already-closed result according to API semantics.

The implementation language is flexible. The key requirement is atomicity.

---

# 70. Performance Targets

Target v0.1 usability numbers:

- local UI response: typically < 200 ms excluding network operations
- control-plane request latency: target p95 < 500 ms under normal conditions
- session establishment: target p95 < 2 seconds excluding user approval time
- terminal command stream startup: target p95 < 1 second under normal conditions
- revoke propagation: target p95 < 2 seconds under normal network conditions

These are engineering targets, not guarantees, and should be validated with load tests.

---

# 71. Availability Targets

For a production hosted control plane, an initial target may be:

```text
Monthly availability target: 99.9%
```

The local device should remain operational independently of temporary control-plane telemetry outages, while remote-session authorization remains fail-closed.

---

# 72. Disaster Recovery

Cloud components should support:

- automated database backups
- point-in-time recovery where appropriate
- infrastructure-as-code recreation
- key rotation procedures
- incident response procedures
- audit-log retention policy

Device secrets should never be recoverable from cloud backups in plaintext.

---

# 73. Incident Response

Security incident procedure should support:

```text
1. Detect
2. Contain
3. Revoke affected credentials/sessions
4. Preserve audit evidence
5. Rotate secrets
6. Patch
7. Validate
8. Restore normal service
```

Global emergency controls should exist for control-plane administrators, while preserving the ability for users to locally revoke their own sessions.

---

# 74. Testing Strategy

## Unit tests

Test:

- Device ID generation
- secret validation
- duration validation
- capability mapping
- session state transitions
- expiration
- revocation
- idempotency
- audit events
- serialization

## Integration tests

Test:

- agent -> control plane
- control plane -> device
- approval -> session
- revoke -> worker termination
- relay connectivity
- reconnect behavior

## E2E tests

Scenario:

```text
start device
→ identify agent
→ authenticate
→ create request
→ approve
→ choose scope
→ run command
→ revoke
→ verify command blocked
```

## Security tests

Include:

- brute-force simulation
- replay attack simulation
- expired-session requests
- revoked-session requests
- malformed protocol frames
- oversized payloads
- path traversal attempts
- command injection at adapter boundaries
- CSRF tests
- XSS tests
- origin spoofing
- stale credential reuse
- race conditions around revoke/execute
- secret leakage checks

---

# 75. Protocol Fuzzing

The network protocol parser should be fuzz-tested.

Fuzz inputs:

- invalid JSON/CBOR/etc.
- oversized strings
- invalid enum values
- missing fields
- duplicated fields
- invalid UTF-8 where relevant
- extreme numeric values
- deeply nested payloads
- truncated frames

Goal:

```text
Malformed remote input must not crash FARcontrol.
```

---

# 76. Dependency Security

Production build pipeline should include:

- dependency lockfiles
- dependency vulnerability scanning
- SBOM generation
- signed releases
- reproducible or traceable builds where practical
- secret scanning
- static analysis
- container/image scanning for server components

---

# 77. Code Security Rules

Must-have rules:

- no shell invocation with concatenated unvalidated user input where avoidable
- no secrets in source code
- no secrets in test fixtures
- no disabled TLS verification in production
- no wildcard CORS for authenticated control APIs
- no debug endpoints in production
- no insecure fallback from TLS to plaintext
- no bypass flag that can silently disable approval

A local developer override should be obvious, constrained, and unavailable in release builds when it compromises the security contract.

---

# 78. Packaging

Target operating systems:

- Windows
- macOS
- Linux

Packaging options:

```text
Windows: MSI / signed installer
macOS: signed + notarized package
Linux: deb/rpm + portable binary
```

The runtime should install as a standard service only with clear user consent.

---

# 79. Upgrade Strategy

On upgrade:

1. Validate version compatibility.
2. Preserve Device ID.
3. Preserve credentials unless rotation is required.
4. Migrate local database schema.
5. Restart runtime safely.
6. Reconnect control plane.
7. Revalidate active sessions.

A failed migration must not leave the device in an insecure partially upgraded state.

---

# 80. Backwards Compatibility

Device IDs and secrets must not silently change on software upgrade.

Protocol compatibility must be explicit.

Old clients should receive a controlled incompatibility error rather than malformed behavior.

---

# 81. Product Configuration Catalog

Provider/model catalogs should be data-driven.

Example:

```json
{
  "providers": [
    {
      "id": "z_ai",
      "displayName": "Z.ai",
      "models": [
        "GLM 5.3",
        "GLM 5.3 Flash",
        "GLM 5.2",
        "GLM 5.1"
      ]
    },
    {
      "id": "qwen",
      "displayName": "Qwen",
      "models": [
        "Qwen 3.8 MAX",
        "Qwen 3.8 Plus",
        "Qwen 3.7 Max",
        "Qwen 3.7 Plus",
        "Qwen 3.7 Turbo"
      ]
    }
  ]
}
```

This lets FARcontrol update identity menus without changing the core connection protocol.

---

# 82. Agent Registration vs Agent Connection

These should remain conceptually separate.

`frtrol agent` first establishes the agent identity context:

```text
provider + model + client version
```

Then it creates a connection request to a target device.

A future persistent “agent account” system may add a cryptographic agent identity, but that is separate from the current device-authentication flow.

---

# 83. Agent Credential Model for Future Versions

Future production versions should consider giving each agent client a keypair:

```text
Agent private key
Agent public key
```

Then the connection request can contain:

```text
provider
model
agent-public-key
request-signature
```

This gives FARcontrol stronger accountability than a self-declared model string alone.

For v0.1, this is optional but the protocol should leave room for it.

---

# 84. Local Device Discovery

A device may be discoverable by Device ID through the control plane.

Do not expose:

- exact IP address
- local network topology
- filesystem path
- user home directory
- raw OS account names

before authentication/approval unless explicitly necessary.

A generic pre-auth response is preferred.

---

# 85. Connection Request Expiration

Pending requests should expire quickly, for example 5 minutes by default.

This is distinct from the approved session duration.

```text
Request TTL: short
Session TTL: 5h - 72h
```

A request that expires must not be approvable later.

---

# 86. Approval Atomicity

When a user approves a request:

```text
PENDING_APPROVAL
      ↓ atomic transaction
AUTHORIZED + session created
```

Do not create a long-lived authorized state and then separately issue the session credential without transactional safeguards.

---

# 87. Disconnect Semantics

A network disconnect does not automatically mean the user revoked a session.

Recommended semantics:

```text
ACTIVE
 ↓ network disconnected
DISCONNECTED
 ↓ reconnect within grace period
ACTIVE
```

or:

```text
DISCONNECTED
 ↓ grace period elapsed
EXPIRED/TERMINATED
```

The policy should be explicit and security-oriented.

---

# 88. Terminal Session Recovery

If a terminal stream disconnects while the FAR Session is still valid:

- retain session authorization
- terminate or pause the specific worker according to worker policy
- let the AI establish a new terminal channel
- preserve audit linkage to the same session

Avoid zombie processes.

---

# 89. File Access Safety for Full Access

Even Full Access should normalize and validate paths.

Required protections:

- canonicalize paths
- reject malformed paths
- prevent traversal outside allowed roots if a root policy is configured
- use OS ACLs
- log file mutations
- enforce size limits
- enforce operation timeouts

The adapter must distinguish:

```text
requested path
resolved path
allowed policy root
```

---

# 90. Desktop Automation Safety

Desktop input is potentially high impact.

Future APIs should use structured actions where possible:

```json
{
  "type": "mouse_click",
  "x": 800,
  "y": 450,
  "button": "left"
}
```

rather than allowing arbitrary low-level driver commands.

Every action remains subject to session authorization.

---

# 91. Browser Access Safety

If Full Access includes browser automation, the browser adapter should run within a controlled browser context where possible.

The product should not silently expose saved browser passwords or sensitive profile stores.

---

# 92. Terminal Environment Policy

Do not expose FARcontrol internals to the remote shell unintentionally.

Avoid leaking:

```text
FARCONTROL_DEVICE_SECRET
SESSION_TOKEN
CONTROL_PLANE_AUTH
PRIVATE_KEYS
```

into child process environment variables.

Use explicit allowlists for environment propagation where practical.

---

# 93. Shell Support

OS-specific shell selection may be:

### Windows

```text
PowerShell
cmd.exe
```

### macOS/Linux

```text
/bin/bash
/bin/zsh
```

Supported shells should be explicitly declared in the runtime capabilities.

The remote agent should not assume shell syntax across operating systems.

---

# 94. Session Metadata Display

Local UI must show:

```text
Agent Provider
Agent Model
Device
Access Scope
Start Time
Expiration Time
Connection Mode
Session State
```

Optional:

```text
Last Operation
Command Count
Data Transferred
```

Do not display sensitive command inputs if they may contain passwords or secrets. A future redaction system should be used for audit surfaces.

---

# 95. Secret-Aware Audit Redaction

Command logging should default to metadata-only.

Example:

```text
COMMAND_STARTED
shell=PowerShell
cwd=C:\Projects
operationId=op_123
```

Do not automatically write full command contents to central logs.

A local debug mode may optionally record commands with strong warnings and explicit consent.

---

# 96. Security Review Checklist

Before production launch:

```text
[ ] Threat model completed
[ ] Protocol reviewed
[ ] Secret generation reviewed
[ ] Secret storage reviewed
[ ] Session state machine tested
[ ] Approval path tested
[ ] Revoke path tested
[ ] Expiration tested
[ ] Race conditions tested
[ ] TLS configuration reviewed
[ ] Web UI security reviewed
[ ] Command execution sandboxing reviewed
[ ] Full Access adapters reviewed
[ ] Audit logging reviewed
[ ] Dependency scan clean / triaged
[ ] Signed release pipeline ready
[ ] Incident response documented
[ ] Backup/restore tested
[ ] Penetration test completed
```

---

# 97. Production Readiness Criteria

FARcontrol is considered production-ready only when all of the following are true:

1. A device can start reliably and register itself.
2. An agent can identify itself.
3. A device authentication attempt is rate-limited.
4. A valid request creates a pending user approval event.
5. No remote operation is possible before approval.
6. User-selected duration is enforced server-side and locally.
7. Only the selected scope is active.
8. Session expiration terminates access.
9. User revoke terminates access promptly.
10. Audit events are emitted reliably.
11. Secrets never appear in logs.
12. Protocol inputs are fuzz-tested.
13. Updates preserve the security contract.
14. The emergency stop works even when ordinary session management is under stress.

---

# 98. Minimal v0.1 Implementation Contract

The smallest implementation that still respects the architecture should support exactly this flow:

```text
USER
frtrol start
   ↓
FARcontrol server ONLINE
   ↓
Device ID + Device Secret

AI
frtrol agent
   ↓
Select Provider
   ↓
Select Model
   ↓
Insert Device ID
   ↓
Authenticate with Device Secret
   ↓
Connection Request

USER
Receive request
   ↓
Choose duration (5h - 72h)
   ↓
Choose access
      Terminal Only
      Full Access
   ↓
ACCEPT

SYSTEM
Create session
   ↓
Establish encrypted channel
   ↓
AI operates only within granted scope
   ↓
Session expires or user revokes
   ↓
Access terminated
```

---

# 99. Canonical CLI Examples

## Start

```bash
frtrol start
```

## Start foreground

```bash
frtrol start --foreground
```

## Start status

```bash
frtrol status
```

## Start agent

```bash
frtrol agent
```

## List requests

```bash
frtrol requests list
```

## List sessions

```bash
frtrol sessions list
```

## Revoke

```bash
frtrol sessions revoke ses_01J...
```

## Rotate credential

```bash
frtrol credential rotate
```

## Emergency stop

```bash
frtrol emergency-stop
```

---

# 100. Canonical User Experience

The golden path should feel this simple:

```text
frtrol start

Starting a server....
Server online at: 127.0.0.1:7481

Your ID       : 7K4M9P2X
Your Password : ********
```

The AI:

```text
frtrol agent

Select your company:
[1] Z.ai
[2] Qwen

Select model:
> GLM 5.3

Insert a device ID:
> 7K4M9P2X

Searching....
Found a device.

Tell me the password:
> ********

OK password accepted!
Sending a connection request...
```

The user:

```text
╔══════════════════════════════════╗
║ AI CONNECTION REQUEST             ║
╚══════════════════════════════════╝

Z.ai / GLM 5.3

Duration: 12 Hours
Access: Terminal Only

[ ACCEPT ]   [ DENY ]
```

Then:

```text
SESSION ACTIVE

Agent  : Z.ai / GLM 5.3
Access : Terminal Only
Time   : 11h 59m remaining

[ REVOKE ACCESS ]
```

That is the essential FARcontrol experience.

---

# 101. Recommended Security Enhancements After v0.1

The following are intentionally compatible with the base design:

- Agent keypairs and signed requests.
- Device keypairs and certificate-based mutual authentication.
- Hardware-backed key storage (TPM/Secure Enclave where available).
- Fine-grained capability editor.
- Trusted Agent allowlist.
- Device groups.
- SSO for local web UI administration.
- OS-native approval dialogs.
- Approval notifications.
- Session recording with explicit user policy.
- Policy templates.
- Organization/team mode.
- Self-hosted FARcontrol control plane.
- End-to-end encrypted relay.
- Device attestation.
- Security scorecards and compliance reporting.

These are post-v0.1 extensions, not prerequisites for the conceptual MVP flow.

---

# 102. Design Invariants

These invariants must survive all future versions:

### Invariant 1

```text
No user approval = No remote access
```

### Invariant 2

```text
Expired session = No remote access
```

### Invariant 3

```text
Revoked session = No remote access
```

### Invariant 4

```text
Missing capability = Operation denied
```

### Invariant 5

```text
Device secret != session token
```

### Invariant 6

```text
Agent model identity != authorization
```

### Invariant 7

```text
Remote network failure must fail closed for authorization
```

### Invariant 8

```text
Security-sensitive actions must be auditable
```

---

# 103. Definition of Done for FARcontrol v0.1

The v0.1 milestone is complete when:

```text
[✓] frtrol start exists
[✓] device identity exists
[✓] device secret exists
[✓] frtrol agent exists
[✓] provider selection exists
[✓] model selection exists
[✓] device authentication exists
[✓] connection request exists
[✓] local approval exists
[✓] duration selection exists
[✓] 5h minimum enforced
[✓] 72h maximum enforced
[✓] Terminal Only exists
[✓] Full Access exists
[✓] session exists
[✓] expiration exists
[✓] revoke exists
[✓] audit exists
[✓] fail-closed behavior exists
[✓] secure secret storage exists
[✓] test suite covers critical paths
```

---

# 104. One-Sentence Architecture Summary

> **FARcontrol is a user-owned local execution gateway in which an external AI Agent authenticates to a target Device, creates a pending request, waits for explicit local approval, receives a time-bounded scoped Session, executes through controlled local adapters, and loses access automatically on revocation or expiration.**

---

# 105. Final Product Principle

The product should always preserve this mental model:

```text
                 AI
                  │
             asks for access
                  │
                  ▼
          ┌────────────────┐
          │  FARcontrol    │
          │   Gatekeeper   │
          └───────┬────────┘
                  │
             USER DECIDES
                  │
        ┌─────────┴─────────┐
        │                   │
      DENY                ALLOW
                            │
                    TIME + SCOPE
                            │
                            ▼
                       AI SESSION
                            │
                    ┌───────┴───────┐
                    │               │
             TERMINAL ONLY      FULL ACCESS
                    │               │
                    └───────┬───────┘
                            │
                      EXPIRE / REVOKE
                            │
                            ▼
                         CLOSED
```

**FARcontrol does not give an AI ownership of the computer. FARcontrol gives an AI a temporary, visible, auditable, user-approved session.**

---

# Appendix A. Terminology Mapping for UX

The implementation may use security-precise names internally while keeping the CLI simple:

| UX Term | Internal Term |
|---|---|
| Your ID | Device ID |
| Your Password | Device Secret |
| AI Company | Agent Provider |
| AI Model | Agent Model |
| Connection Request | Pending Connection Request |
| Terminal Only | `terminal_only` scope |
| Full Access | `full_access` scope |
| Access Time | Session TTL |
| Accept | Approve / Authorize |
| Stop Access | Revoke Session |

---

# Appendix B. Suggested Initial Ports and Endpoints

These values are examples and should be configurable.

Local UI:

```text
127.0.0.1:7481
```

Local health:

```text
GET /healthz
GET /readyz
```

Control plane:

```text
https://control.<farcontrol-domain>/
```

WebSocket/stream:

```text
wss://control.<farcontrol-domain>/v1/session/<session-id>
```

No production deployment should hard-code insecure endpoints.

---

# Appendix C. Recommended Initial Tech Stack

This is a recommendation, not a hard requirement.

## Local runtime

A compiled systems language is preferable for:

- cross-platform binaries
- process control
- secure secret handling integrations
- predictable memory use
- simple single-binary distribution

Go or Rust are both reasonable candidates.

## Control plane

Possible stack:

```text
Go / Rust / TypeScript
PostgreSQL
Redis (rate limiting / ephemeral coordination)
WebSocket or QUIC transport
```

## Local web UI

Possible stack:

```text
React / Svelte / plain TypeScript
```

The UI should remain lightweight and served locally by the runtime.

---

# Appendix D. Architecture Decision Records to Create Before Coding

Before implementation, write ADRs for:

1. Transport protocol: WebSocket vs QUIC.
2. Control plane hosting model.
3. Local persistence strategy.
4. Secret store abstraction.
5. Terminal worker model.
6. Full Access adapter model.
7. Session encryption architecture.
8. Agent identity verification.
9. Relay/direct connectivity strategy.
10. Audit retention policy.
11. Update/signing strategy.
12. Cross-platform OS abstraction.

---

# Appendix E. Build Phases

## Phase 0: Foundations

- repository
- protocol schemas
- Device identity
- secret store
- CLI skeleton
- local runtime

## Phase 1: Session Core

- device registration
- connection request
- approval
- session state machine
- expiry
- revoke

## Phase 2: Terminal Only

- worker manager
- shell adapters
- streaming I/O
- command lifecycle
- audit

## Phase 3: Local Web UI

- dashboard
- request approval
- active session
- revoke
- logs

## Phase 4: Full Access

- capability framework
- file adapter
- process adapter
- application adapter
- desktop adapter

## Phase 5: Hardening

- fuzzing
- penetration test
- dependency scanning
- signed binaries
- crash recovery
- relay reliability
- production observability

---

# Appendix F. First Build Target

The first executable milestone should be intentionally narrow:

```text
frtrol start
```

creates a local Device and shows:

```text
Server online
Your ID
Your Password
Web UI
```

Then:

```text
frtrol agent
```

can create an authenticated connection request.

The first end-to-end proof should stop at:

```text
Connection request received.

[ ACCEPT ] [ DENY ]
```

Then add:

```text
5h - 72h
Terminal Only / Full Access
```

Then activate the session.

This staged approach keeps the security boundary stable while the execution layer grows.

---

# Status

**FARcontrol.md defines the canonical v0.1 product/technical contract.**

Any implementation that conflicts with the invariants in Section 102 should be treated as a security design regression and reviewed before merge.
