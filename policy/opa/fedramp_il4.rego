# OPA / Conftest Policy-as-Code for FedRAMP Moderate, DoD IL4 & DISA Container STIG
# Run via: conftest test Dockerfile infra/k8s/*.yaml dist/fedramp-il4-evidence.json -p policy/opa
package main

import rego.v1

# -----------------------------------------------------------------------------
# 1. FedRAMP Moderate / DoD IL4 Machine-Readable Evidence Checks
# -----------------------------------------------------------------------------
deny contains msg if {
	input.schemaVersion == "aegis.gov/fedramp-il4-evidence/v1"
	not input.overallCompliant
	msg := "FEDRAMP-IL4: overallCompliant MUST be true before deployment admission"
}

deny contains msg if {
	input.schemaVersion == "aegis.gov/fedramp-il4-evidence/v1"
	not input.fips140Enabled
	msg := "NIST SC-13 / IL4: FIPS 140-3 cryptographic mode MUST be verified active"
}

deny contains msg if {
	input.schemaVersion == "aegis.gov/fedramp-il4-evidence/v1"
	input.thirdPartyDepCount > 0
	msg := sprintf("MINIMAL-TCB VIOLATION: thirdPartyDepCount=%d exceeds zero-dep policy", [input.thirdPartyDepCount])
}

deny contains msg if {
	input.schemaVersion == "aegis.gov/fedramp-il4-evidence/v1"
	some c in input.controls
	c.status != "SATISFIED"
	msg := sprintf("CONTROL FAILURE: %s (%s) status=%s", [c.controlId, c.fedramp20xKsi, c.status])
}

# -----------------------------------------------------------------------------
# 2. Kubernetes Deployment — DISA Container STIG & Platform One Big Bang Checks
# -----------------------------------------------------------------------------
deny contains msg if {
	input.kind == "Deployment"
	some c in input.spec.template.spec.containers
	not c.securityContext.runAsNonRoot
	msg := sprintf("DISA STIG: container %q MUST set securityContext.runAsNonRoot=true", [c.name])
}

deny contains msg if {
	input.kind == "Deployment"
	some c in input.spec.template.spec.containers
	not c.securityContext.readOnlyRootFilesystem
	msg := sprintf("DISA STIG: container %q MUST set securityContext.readOnlyRootFilesystem=true", [c.name])
}

deny contains msg if {
	input.kind == "Deployment"
	some c in input.spec.template.spec.containers
	c.securityContext.allowPrivilegeEscalation != false
	msg := sprintf("DISA STIG: container %q MUST set securityContext.allowPrivilegeEscalation=false", [c.name])
}

deny contains msg if {
	input.kind == "Deployment"
	some c in input.spec.template.spec.containers
	not has_drop_all_caps(c)
	msg := sprintf("DISA STIG: container %q MUST drop ALL Linux capabilities", [c.name])
}

deny contains msg if {
	input.kind == "Deployment"
	some c in input.spec.template.spec.containers
	not has_fips_env(c)
	msg := sprintf("NIST SC-13: container %q MUST set env GODEBUG=fips140=on", [c.name])
}

has_drop_all_caps(c) if {
	some cap in c.securityContext.capabilities.drop
	cap == "ALL"
}

has_fips_env(c) if {
	some e in c.env
	e.name == "GODEBUG"
	contains(e.value, "fips140=on")
}
