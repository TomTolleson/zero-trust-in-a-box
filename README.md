# zero-trust-in-a-box

A minimal, runnable reference deployment that wires together four off-the-shelf open-source components to demonstrate a complete zero-trust authentication and authorization loop. The goal is clarity and a working end-to-end flow you can `docker compose up` and inspect — not production hardening.

## Control plane vs. data plane

In a zero-trust architecture the **control plane** decides *who can access what and under what conditions*. Here that is Keycloak (identity) + OPA (policy). The **data plane** enforces those decisions on live traffic without re-evaluating policy from scratch. Here that is Pomerium: it sits in front of the protected app, authenticates every request against Keycloak, and evaluates the Rego authorization policy before forwarding a single byte to the upstream. The split matters because it lets you change policy (control plane) without touching the enforcement point (data plane), and it makes the control plane the obvious high-value target to harden — see the threat model below.

## Architecture

```
                        ┌─────────────────────────────────────────────────────────────┐
                        │  Docker network: zero-trust                                 │
                        │                                                             │
                        │  ┌──────────┐   OIDC/JWT   ┌──────────────────────────┐   │
   Browser              │  │          │◄────────────► │  Keycloak :8080          │   │
   https://app.         │  │ Pomerium │               │  Identity Provider        │   │
   localhost.pomerium.io│  │  :443    │   OPA Rego    │  realm: zero-trust        │   │
   ──────────────────►  │  │          │  (embedded)   │  users: alice, bob,       │   │
                        │  │ Enforce- │               │         charlie           │   │
                        │  │  ment    │               │  groups: employees,admins │   │
                        │  │  Point   │               └──────────────────────────┘   │
                        │  │          │                                               │
                        │  │          │  proxy (if allowed)                           │
                        │  │          │──────────────────────────────►┌────────────┐ │
                        │  └──────────┘                               │ app        │ │
                        │                                             │ (whoami)   │ │
                        │  ┌──────────────────────────┐              │ :80        │ │
                        │  │  OPA :8181               │              │            │ │
                        │  │  Standalone policy server│              │ No exposed │ │
                        │  │  - unit tests            │              │ ports      │ │
                        │  │  - direct HTTP queries   │              └────────────┘ │
                        │  └──────────────────────────┘                             │
                        └─────────────────────────────────────────────────────────────┘
```

**Request flow for a protected route:**

```
1.  User visits https://app.localhost.pomerium.io
2.  Pomerium detects no session → redirects to Keycloak login (OIDC Authorization Code flow)
3.  User authenticates at http://keycloak:8080/realms/zero-trust (login page)
4.  Keycloak issues an ID token containing email + groups claim
5.  Pomerium validates the token, evaluates the Rego policy (embedded OPA):
      allow if "employees" in claims.groups AND x-device-posture header present
      allow if "admins" in claims.groups
6.  ALLOWED → Pomerium proxies the request, adding X-Pomerium-Claim-* headers
    DENIED  → Pomerium returns 403, request never reaches the app
```

## Users and groups

| Username | Password   | Groups              | Expected access              |
|----------|------------|---------------------|------------------------------|
| alice    | alice123   | employees, admins   | Always allowed (admin)       |
| bob      | bob123     | employees           | Allowed with posture header  |
| charlie  | charlie123 | (none)              | Always denied                |

## Quick start

### 1. Prerequisites

- Docker Desktop (or Docker Engine + Compose plugin)
- `openssl` for generating secrets

### 2. Add `keycloak` to your hosts file

Pomerium and your browser both need to reach Keycloak at the same hostname
(`keycloak:8080`) so that OIDC token issuers match. This is a one-time setup.

**macOS / Linux:**
```bash
echo "127.0.0.1 keycloak" | sudo tee -a /etc/hosts
```

**Windows (PowerShell as Administrator):**
```powershell
Add-Content C:\Windows\System32\drivers\etc\hosts "`n127.0.0.1 keycloak"
```

### 3. Generate secrets and create `.env`

```bash
cp .env.example .env
```

Then edit `.env` and replace the two `REPLACE_WITH_GENERATED_SECRET` values:

```bash
# macOS / Linux — run twice, once per placeholder:
openssl rand -base64 32
```

The `POMERIUM_IDP_CLIENT_SECRET` is pre-filled with the demo value that matches
`keycloak/realm-export.json`. Leave it as-is for the demo.

### 4. Start the stack

```bash
docker compose up
```

Keycloak takes 60–90 seconds to start and import the realm. Pomerium waits for
Keycloak's healthcheck before starting. You will see
`Realm 'zero-trust' imported successfully` in the Keycloak logs when it's ready.

### 5. Test the flow

**As Alice (admin — always allowed):**

Open `https://app.localhost.pomerium.io` in your browser. Accept the TLS warning
(Pomerium's dev cert). You will be redirected to the Keycloak login page at
`http://keycloak:8080`. Log in as `alice` / `alice123`. You should land on the
whoami page showing all request headers — look for `X-Pomerium-Claim-Email` and
`X-Pomerium-Claim-Groups`.

**As Bob (employee — requires device posture):**

Log in as `bob` / `bob123`. Without the `X-Device-Posture` header, Pomerium
returns 403. To simulate a compliant device, add the header via a browser
extension (e.g., ModHeader) or use curl:

```bash
curl -k -H "X-Device-Posture: compliant" \
  --cookie-jar /tmp/cookies.txt \
  https://app.localhost.pomerium.io
```

**As Charlie (no group — always denied):**

Log in as `charlie` / `charlie123`. Pomerium returns 403 immediately after
authentication — Charlie has a valid identity but no authorization.

### 6. Query OPA directly

The standalone OPA container exposes a REST API at `http://localhost:8181`.

```bash
# Check health
curl http://localhost:8181/health

# Employee with posture — expect {"result": true}
curl -s -X POST http://localhost:8181/v1/data/zerotrust/authz/allow \
  -H "Content-Type: application/json" \
  -d '{
    "input": {
      "user": {"sub": "u1", "email": "bob@example.com", "groups": ["employees"]},
      "request": {"method": "GET", "path": "/",
                  "headers": {"x-device-posture": "compliant"}}
    }
  }'

# Employee without posture — expect {"result": false}
curl -s -X POST http://localhost:8181/v1/data/zerotrust/authz/allow \
  -H "Content-Type: application/json" \
  -d '{
    "input": {
      "user": {"sub": "u1", "email": "bob@example.com", "groups": ["employees"]},
      "request": {"method": "GET", "path": "/", "headers": {}}
    }
  }'
```

### 7. Run OPA unit tests

```bash
docker compose run --rm opa test /policies -v
```

All tests pass, including adversarial cases (group header injection, empty posture
value, no group membership).

### 8. Keycloak admin console

Visit `http://keycloak:8080/admin` → log in as `admin` / `admin`. From here you
can inspect the `zero-trust` realm, disable a user account to test revocation, and
view the `pomerium` client's protocol mapper that injects the `groups` claim.

## Files

```
zero-trust-in-a-box/
├── docker-compose.yml          # Full stack — single entry point
├── .env.example                # Secret template — copy to .env
├── keycloak/
│   └── realm-export.json       # Realm, client, groups, users imported at startup
├── pomerium/
│   └── config.yaml             # OIDC wiring + inline Rego authorization policy
└── opa/
    ├── policy.rego             # Standalone policy with comments on each rule
    └── policy_test.rego        # Unit tests including adversarial cases
```

## Threat model

### What this defends against

- **Unauthenticated access.** No request reaches the app without a valid Keycloak session. Pomerium enforces this at the network level — there is no route that bypasses it.
- **Insufficient authorization.** Group membership is verified from IdP-signed tokens, not from headers an attacker can forge. Charlie can create an account but will never be in `employees` unless an admin puts them there.
- **Unknown device state.** The device posture check requires a signal from a trusted source (in production: a device certificate or endpoint agent query). An unmanaged device with no agent produces no signal and is denied.
- **Stale sessions.** Access tokens in this demo have a 60-second TTL. Pomerium re-validates on each refresh cycle, limiting how long a stolen token remains valid.
- **Direct app access.** The `app` container has no exposed ports. There is no network path to it that bypasses Pomerium, as long as the Docker network is trusted.

### What this does NOT defend against

- **Compromised Pomerium or OPA.** If the enforcement point or policy engine is owned, all bets are off. See below.
- **Lateral movement inside the Docker network.** Once proxied, `app` is reachable from other containers on the same bridge. In production, use network policies and mTLS between services.
- **Token theft before expiry.** A stolen access token is valid until its TTL expires. Combine short TTLs with OPA's revocation list pattern (see `opa/policy.rego`) to shrink the window.
- **Keycloak or OPA compromise.** These are out-of-scope here and require their own hardening: private-network-only exposure, signed policy bundles, audit logging, and credential rotation.
- **Supply chain attacks.** This demo trusts upstream Docker images at their tags. Pin to digests and verify image signatures in production.

### Why the control plane is the highest-value target

Keycloak and OPA together decide *who can do what*. An attacker who controls either can issue tokens for any identity or rewrite policy to permit everything — silently, without touching the enforcement point. In a real deployment these services warrant strict isolation: no public internet exposure, separate admin credentials, read-only policy loading via signed bundles, and independent audit trails. The enforcement point (Pomerium) matters too, but an attacker who controls only Pomerium can affect traffic — they still cannot forge tokens signed by Keycloak's private key.
