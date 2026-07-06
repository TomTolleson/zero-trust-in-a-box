# zerotrust/authz.rego — standalone OPA policy for the zero-trust-in-a-box demo.
#
# This policy is evaluated by the OPA container (port 8181) and can be queried
# directly:
#
#   curl -s -X POST http://localhost:8181/v1/data/zerotrust/authz/allow \
#     -H "Content-Type: application/json" \
#     -d '{"input": {"user": {"sub": "u1", "email": "bob@example.com",
#           "groups": ["employees"]},
#           "request": {"method": "GET", "path": "/",
#             "headers": {"x-device-posture": "compliant"}}}}'
#
# Pomerium's enforcement point uses its *embedded* OPA with the inline Rego in
# pomerium/config.yaml, which mirrors this logic but uses Pomerium's own input
# schema (input.session.claims.* instead of input.user.*).
# Both instances speak the same language — Rego — showing how policy-as-code
# can span control-plane and data-plane enforcement points.

package zerotrust.authz

import rego.v1

# ── ZERO TRUST CORE: DENY BY DEFAULT ──────────────────────────────────────
# Nothing is permitted unless a rule explicitly grants access.
# "Never trust, always verify" is encoded here as a literal default.
default allow := false

# ── RULE 1: AUTHENTICATED EMPLOYEE + VALID DEVICE POSTURE ─────────────────
# An employee may access the app only when the device is known-compliant.
# The x-device-posture header is injected by Pomerium after it validates a
# device certificate or queries an endpoint-agent API (e.g., Kolide, CrowdStrike).
# A missing or "unknown" value means posture is unverified → deny.
allow if {
	is_employee
	has_valid_device_posture
}

# ── RULE 2: ADMIN BYPASS ───────────────────────────────────────────────────
# Admins are granted access regardless of device posture.
# In a production policy you would likely require posture for admins too —
# this rule exists to demonstrate group-based privilege escalation in Rego.
allow if {
	is_admin
}

# ── HELPERS ───────────────────────────────────────────────────────────────

is_employee if "employees" in input.user.groups

is_admin if "admins" in input.user.groups

has_valid_device_posture if {
	posture := input.request.headers["x-device-posture"]
	posture != ""
	posture != "unknown"
}

# ── MID-SESSION REVOCATION (HOW IT WORKS) ─────────────────────────────────
# Zero trust requires the ability to revoke access between token refreshes.
# Two complementary mechanisms:
#
# 1. Short-lived tokens: Configure Keycloak to issue access tokens with a
#    1–5 minute TTL. Pomerium re-validates on each refresh cycle, so a
#    disabled user is locked out within one TTL window.
#
# 2. OPA revocation list: Maintain a set of revoked subject IDs and deny
#    them immediately, regardless of token validity:
#
#      revoked_subjects := {"sub-of-fired-employee", "compromised-device-id"}
#
#      deny if input.user.sub in revoked_subjects
#
#    Update this set via OPA's PUT /v1/data API or by pushing a new policy
#    bundle. Combined with Pomerium's --refresh-session-period flag and
#    Keycloak's session revocation API, you can achieve near-zero-lag
#    revocation without invalidating every session in the system.
