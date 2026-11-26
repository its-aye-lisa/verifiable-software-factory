---
name: fedramp-il4-audit
description: Audit the codebase, container, IaC, and generated evidence against FedRAMP Moderate (Rev 5 & 20x KSIs), DoD CC SRG IL4, DISA STIGs, and NIST SP 800-218 SSDF.
---

# Skill: FedRAMP Moderate / 20x / DoD IL4 Compliance Audit

Use this skill before releases, 3PAO readiness reviews, or cATO continuous authorization checks:

1. **Run Full Verifiable Factory & Admission Control:**
   - Execute `make factory && make admit`.
   - Confirm all 9 Gatekeeper checks pass (`RELEASE_AUTHORITY_SIG`, `BINARY_DIGEST_MATCH`, `TWO_PERSON_INTEGRITY`, `SOURCE_HYGIENE_AST_GATE`, `SLSA_HERMETIC_FIPS_PROVENANCE`, `CLEANROOM_REPRODUCIBLE_BUILD`, `DIVERSE_CLEANROOM_SPEC`, `DAST_FIPS140_STIG`, `CYCLONEDX_SBOM`).
2. **Verify Machine-Readable Evidence Artifacts in `dist/`:**
   - `dist/fedramp-il4-evidence.json`: confirm `overallCompliant == true`, `fips140Enabled == true`, `thirdPartyDepCount == 0`, and every NIST 800-53 / FedRAMP 20x KSI control is `SATISFIED`.
   - `dist/aegis-findings.sarif`: confirm `runs[0].results` is empty (0 SAST/DAST findings).
   - `dist/vex.openvex.json` & `dist/vra-report.json`: confirm `releaseBlocked == false`.
3. **Verify Policy-as-Code & IaC Hardening:**
   - Inspect `Dockerfile` (`FROM scratch`, `GOFIPS140=v1.0.0`, `USER 65532:65532`, `GODEBUG=fips140=on`).
   - Inspect `infra/k8s/deployment.yaml` (`runAsNonRoot`, `readOnlyRootFilesystem`, `drop: [ALL]`, `RuntimeDefault` seccomp) and `infra/k8s/networkpolicy.yaml` (`egress: []`).
   - Inspect `infra/k8s/kyverno-admission-policy.yaml` (Cosign OIDC + SLSA provenance enforcement).
   - If `conftest` is installed, run `conftest test dist/fedramp-il4-evidence.json infra/k8s/deployment.yaml -p policy/opa`.
4. **Report Concise Audit Summary:** Highlight any drift, SLA timers, or open POA&M items.
