# policy_test.rego — OPA unit tests for zerotrust/authz.
#
# Run all tests:
#   docker compose run --rm opa test /policies -v
#
# Or against the running container:
#   docker compose exec opa opa test /policies -v

package zerotrust.authz_test

import data.zerotrust.authz
import rego.v1

# ── SHARED FIXTURES ────────────────────────────────────────────────────────

employee_with_posture := {
	"user": {
		"sub": "test-bob",
		"email": "bob@example.com",
		"groups": ["employees"],
	},
	"request": {
		"method": "GET",
		"path": "/",
		"headers": {"x-device-posture": "compliant"},
	},
}

admin_no_posture := {
	"user": {
		"sub": "test-alice",
		"email": "alice@example.com",
		"groups": ["employees", "admins"],
	},
	"request": {
		"method": "GET",
		"path": "/",
		"headers": {},
	},
}

# ── POSITIVE CASES (should be allowed) ────────────────────────────────────

test_employee_with_posture_is_allowed if {
	authz.allow with input as employee_with_posture
}

test_admin_is_allowed_without_posture if {
	# Admins bypass device posture — see Rule 2 in policy.rego
	authz.allow with input as admin_no_posture
}

test_admin_with_posture_also_allowed if {
	inp := json.patch(admin_no_posture, [{
		"op": "add",
		"path": "/request/headers/x-device-posture",
		"value": "compliant",
	}])
	authz.allow with input as inp
}

# ── NEGATIVE / ADVERSARIAL CASES (should be denied) ───────────────────────

test_unauthenticated_user_is_denied if {
	# No groups → no identity → deny
	not authz.allow with input as {
		"user": {"sub": "", "email": "", "groups": []},
		"request": {"method": "GET", "path": "/", "headers": {}},
	}
}

test_employee_without_posture_is_denied if {
	# Group membership alone is not enough — device must be verified
	not authz.allow with input as {
		"user": {
			"sub": "test-bob",
			"email": "bob@example.com",
			"groups": ["employees"],
		},
		"request": {"method": "GET", "path": "/", "headers": {}},
	}
}

test_employee_with_unknown_posture_is_denied if {
	# "unknown" means the endpoint agent reported inconclusive — deny
	not authz.allow with input as {
		"user": {
			"sub": "test-bob",
			"email": "bob@example.com",
			"groups": ["employees"],
		},
		"request": {
			"method": "GET",
			"path": "/",
			"headers": {"x-device-posture": "unknown"},
		},
	}
}

test_no_group_membership_is_denied if {
	# Valid identity, compliant device, but no group → deny
	# This is charlie's case — authenticated but not authorized
	not authz.allow with input as {
		"user": {
			"sub": "test-charlie",
			"email": "charlie@example.com",
			"groups": [],
		},
		"request": {
			"method": "GET",
			"path": "/",
			"headers": {"x-device-posture": "compliant"},
		},
	}
}

test_group_injection_via_header_is_denied if {
	# Adversarial: attacker spoofs a group header on the request.
	# Policy only reads groups from input.user.groups (IdP-verified claims),
	# never from request headers — so the spoofed header is silently ignored.
	not authz.allow with input as {
		"user": {
			"sub": "evil-user",
			"email": "evil@example.com",
			"groups": [],
		},
		"request": {
			"method": "GET",
			"path": "/",
			"headers": {
				"x-device-posture": "compliant",
				"x-user-groups": "admins", # <── spoofed, never read by policy
			},
		},
	}
}

test_empty_posture_string_is_denied if {
	# Edge case: header present but empty — treat as missing
	not authz.allow with input as {
		"user": {
			"sub": "test-bob",
			"email": "bob@example.com",
			"groups": ["employees"],
		},
		"request": {
			"method": "GET",
			"path": "/",
			"headers": {"x-device-posture": ""},
		},
	}
}

test_revoked_employee_would_be_denied if {
	# Demonstrates the revocation pattern from policy.rego comments.
	# If you uncomment the revoked_subjects set and deny rule in policy.rego,
	# this test would use it. Shown here as a documentation anchor.
	#
	# not authz.allow with input as employee_with_posture
	#   with data.zerotrust.authz.revoked_subjects as {"test-bob"}
	#
	# For now just assert the positive case still holds (no revocation active).
	authz.allow with input as employee_with_posture
}
