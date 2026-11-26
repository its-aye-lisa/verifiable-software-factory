# =============================================================================
# Everything-as-Code: GitHub Repository Governance IaC (OpenTofu / Terraform)
# =============================================================================
# Enforces 2PI, signed commits, CODEOWNERS review, required FedRAMP/IL4 status
# checks, Dependabot alerts, and secret scanning push protection on GitHub Free!
# =============================================================================
terraform {
  required_version = ">= 1.6.0"
  required_providers {
    github = {
      source  = "integrations/github"
      version = "~> 6.0"
    }
  }
}

variable "github_owner" {
  type        = string
  description = "GitHub user or organization owning the repository"
}

variable "repository_name" {
  type        = string
  default     = "verifiable-software-factory"
  description = "Name of the governed Software Factory repository"
}

provider "github" {
  owner = var.github_owner
}

resource "github_repository" "factory" {
  name        = var.repository_name
  description = "Spec-Driven, Platform One-Comparable, Untrusted-Developer-Resilient Verifiable Software Factory (FedRAMP Moderate / DoD IL4 / SSDF)"
  visibility  = "public" # Public repos unlock 100% Free GitHub Advanced Security (CodeQL, Secret Scanning, Actions, GHCR)

  has_issues             = true
  has_projects           = true
  vulnerability_alerts   = true
  delete_branch_on_merge = true
  allow_squash_merge     = true
  allow_merge_commit     = false
  allow_rebase_merge     = false

  security_and_analysis {
    secret_scanning {
      status = "enabled"
    }
    secret_scanning_push_protection {
      status = "enabled"
    }
  }
}

# Branch protection enforcing Two-Person Integrity (2PI), signed commits & mandatory CI gates
resource "github_branch_protection" "main" {
  repository_id = github_repository.factory.node_id
  pattern       = "main"

  enforce_admins                  = true
  require_signed_commits          = true
  require_conversation_resolution = true
  allows_force_pushes             = false
  allows_deletions                = false

  required_pull_request_reviews {
    dismiss_stale_reviews           = true
    require_code_owner_reviews      = true
    required_approving_review_count = 2 # Two-Person Integrity (Developer != Reviewer != Security)
    require_last_push_approval      = true
  }

  required_status_checks {
    strict = true
    contexts = [
      "Gate 1 — Secrets, SAST (Aegis AST + Gosec + Semgrep) & Invariants",
      "Gate 2 — SCA (govulncheck + Trivy FS) & Dependency Review",
      "Gate 3 — IaC & Container Policy-as-Code (OPA + Hadolint + Trivy)",
      "Gate 4 — Fast Local DAST & FIPS 140-3 Runtime Probe",
      "CodeQL"
    ]
  }
}
