package privacy

// CatalogEntry records one class of personal data the product stores, why it is
// present, and how subject erasure handles it. Keeping this in code makes the
// API and docs tests share one machine-checkable inventory.
type CatalogEntry struct {
	ID             string `json:"id"`
	Location       string `json:"location"`
	Category       string `json:"category"`
	Purpose        string `json:"purpose"`
	RetentionClass string `json:"retention_class"`
	Erasure        string `json:"erasure"`
	Owner          string `json:"owner"`
}

// Catalog is the maintained personal-data inventory for privacy/API export.
func Catalog() []CatalogEntry {
	return []CatalogEntry{
		{
			ID:             "events.actor.subject",
			Location:       "events.Actor.Subject",
			Category:       "authenticated subject identifier",
			Purpose:        "audit attribution for state-changing operations",
			RetentionClass: "audit",
			Erasure:        "tenant audit reads replace erased subjects with subject_ref placeholders",
			Owner:          "platform",
		},
		{
			ID:             "events.data.subject-values",
			Location:       "events.Event.Data",
			Category:       "subject-linked payload values",
			Purpose:        "event-sourced rebuild of read models",
			RetentionClass: "audit",
			Erasure:        "privacy.subject.erased stores non-PII selectors; audit reads redact exact erased subject values",
			Owner:          "platform",
		},
		{
			ID:             "owners.email",
			Location:       "owners.email",
			Category:       "contact identifier",
			Purpose:        "credential ownership and notification metadata",
			RetentionClass: "operational:owner-inactive-after-730d",
			Erasure:        "privacy.subject.erased blanks email; privacy.retention.enforced blanks inactive unreferenced owners and pseudonymizes names",
			Owner:          "identity inventory",
		},
		{
			ID:             "tenant_members.subject",
			Location:       "tenant_members.subject/display_name/email",
			Category:       "administrator subject and contact metadata",
			Purpose:        "RBAC membership and offboarding evidence",
			RetentionClass: "operational:access-terminal-after-90d",
			Erasure:        "privacy.subject.erased replaces subject with erased placeholder; privacy.retention.enforced pseudonymizes offboarded members and clears display/contact fields",
			Owner:          "access control",
		},
		{
			ID:             "api_tokens.subject",
			Location:       "api_tokens.subject",
			Category:       "API-token principal subject",
			Purpose:        "token authentication and revocation metadata",
			RetentionClass: "operational:access-terminal-after-90d",
			Erasure:        "privacy.subject.erased revokes matching tokens; privacy.retention.enforced pseudonymizes expired/revoked token subjects",
			Owner:          "access control",
		},
		{
			ID:             "identities.name-attributes",
			Location:       "identities.name/attributes",
			Category:       "workload or human-linked identity metadata",
			Purpose:        "credential lifecycle inventory",
			RetentionClass: "operational:identity-terminal-after-397d",
			Erasure:        "privacy.subject.erased and privacy.retention.enforced pseudonymize terminal identity names and clear attributes",
			Owner:          "identity inventory",
		},
		{
			ID:             "certificates.subject-sans",
			Location:       "certificates.subject/sans",
			Category:       "certificate subject alternative names",
			Purpose:        "certificate inventory, expiry, and risk analysis",
			RetentionClass: "operational:certificate-terminal-after-397d",
			Erasure:        "privacy.subject.erased clears selected subject/SAN values; privacy.retention.enforced clears terminal subject/SAN/location/source values",
			Owner:          "certificate inventory",
		},
		{
			ID:             "certificates.location-source",
			Location:       "certificates.deployment_location/source",
			Category:       "certificate deployment metadata",
			Purpose:        "connector targeting, inventory provenance, and risk analysis",
			RetentionClass: "operational:certificate-terminal-after-397d",
			Erasure:        "privacy.retention.enforced clears terminal deployment location and source values",
			Owner:          "certificate inventory",
		},
		{
			ID:             "ssh_keys.comment-location",
			Location:       "ssh_keys.comment/location",
			Category:       "SSH key descriptive metadata",
			Purpose:        "SSH trust inventory and drift analysis",
			RetentionClass: "operational:ssh-stale-after-180d",
			Erasure:        "privacy.subject.erased clears selected values; privacy.retention.enforced clears orphaned stale comment and location fields",
			Owner:          "SSH trust",
		},
		{
			ID:             "attestations.evidence",
			Location:       "attestations.evidence",
			Category:       "free-form evidence payload",
			Purpose:        "policy and provenance evidence for credential actions",
			RetentionClass: "operational:attestation-evidence-after-397d",
			Erasure:        "privacy.subject.erased clears selected evidence JSON; privacy.retention.enforced clears stale evidence JSON",
			Owner:          "policy",
		},
		{
			ID:             "approvals.actors",
			Location:       "issuance_approval_requests.requester / issuance_approvals.approver",
			Category:       "dual-control requester and approver subjects",
			Purpose:        "separation-of-duties evidence for privileged lifecycle transitions",
			RetentionClass: "operational:approval-actor-after-397d",
			Erasure:        "privacy.subject.erased or privacy.retention.enforced pseudonymizes requester and approver values while preserving resource/action evidence",
			Owner:          "access control",
		},
		{
			ID:             "profiles.created-by",
			Location:       "certificate_profiles.created_by",
			Category:       "profile author subject",
			Purpose:        "profile change provenance",
			RetentionClass: "operational:profile-actor-after-397d",
			Erasure:        "privacy.subject.erased or privacy.retention.enforced pseudonymizes profile author values",
			Owner:          "certificate inventory",
		},
		{
			ID:             "agents.name",
			Location:       "agents.name",
			Category:       "agent host or workload identifier",
			Purpose:        "fleet inventory and heartbeat status",
			RetentionClass: "operational:agent-stale-after-180d",
			Erasure:        "privacy.subject.erased or privacy.retention.enforced pseudonymizes agent names while preserving agent id/status/version",
			Owner:          "agent fleet",
		},
		{
			ID:             "pam_sessions.subjects",
			Location:       "pam_sessions.subject/requested_by/reason/audit",
			Category:       "privileged-access requester, target subject, and free-form reason metadata",
			Purpose:        "JIT/PAM session approval, revocation, audit, and expiry evidence",
			RetentionClass: "operational:access-terminal-after-90d",
			Erasure:        "privacy.retention.enforced covers terminal PAM session subject fields and free-form reason/audit metadata after the access window; tenant offboarding removes the tenant-scoped read model",
			Owner:          "privileged access",
		},
		{
			ID:             "discovery_findings.triage",
			Location:       "discovery_findings.triage_actor/triage_reason",
			Category:       "discovery triage actor and free-form disposition reason",
			Purpose:        "operator accountability for claiming, dismissing, or marking discovered credentials",
			RetentionClass: "operational:discovery-triage-after-397d",
			Erasure:        "privacy.retention.enforced covers stale triage actors and free-form triage reasons after discovery evidence ages out; tenant offboarding removes the tenant-scoped read model",
			Owner:          "discovery inventory",
		},
		{
			ID:             "notification_threshold_deliveries.subject",
			Location:       "notification_threshold_deliveries.subject/channel",
			Category:       "expiry-alert subject and delivery channel metadata",
			Purpose:        "deduplicate threshold notifications per subject, threshold, and channel",
			RetentionClass: "operational:notification-delivery-after-397d",
			Erasure:        "privacy.retention.enforced covers stale threshold-delivery subjects after notification evidence ages out; tenant offboarding removes the tenant-scoped read model",
			Owner:          "notifications",
		},
		{
			ID:             "incident_executions.operator-evidence",
			Location:       "incident_executions.created_by/reason/evidence_bundle/failed_targets/rollback_refs",
			Category:       "incident operator subject, free-form reason, and remediation evidence labels",
			Purpose:        "incident response accountability, rollback, and audit-ready remediation evidence",
			RetentionClass: "operational:incident-evidence-after-397d",
			Erasure:        "privacy.retention.enforced covers stale operator/free-form incident evidence while preserving non-PII status and identity ids; tenant offboarding removes the tenant-scoped read model",
			Owner:          "incident response",
		},
		{
			ID:             "oidc_prelogin.client-metadata",
			Location:       "oidcPreLoginEntry.ClientIP/UserAgent",
			Category:       "short-lived authentication client IP and user agent metadata",
			Purpose:        "OIDC login continuity and replay protection during the pre-login redirect",
			RetentionClass: "ephemeral:oidc-prelogin-ttl-10m",
			Erasure:        "TTL pruning deletes the in-memory entry on consume or expiry; no durable read model or event stores the client IP/user-agent pre-login metadata",
			Owner:          "access control",
		},
	}
}
