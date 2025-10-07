# RDS Compliance – Detection and Remediation

> ⚠️ **Remediation Status: EXPERIMENTAL – Do NOT deploy remediation automation or the remediation IAM role in production.**
>
> Only the detection script, detection IAM role template, and any detection workflow you create are considered stable for read‑only use. Remediation code and role template are present for review and sandbox experimentation only and may change without notice.

Overview
- Goal: Detect and optionally remediate deviations from an RDS logging/parameter baseline across multiple AWS accounts
- Content:
  - A JSON baseline file managed in Git.
  - Two Python scripts:
    - dam-detection.py: non-destructive detection (reports deviations) – **Stable**.
    - dam-remediation.py: optional remediation (applies changes) – **Experimental (do not automate in prod)**.
  - GitHub Actions workflows (optional) to run detection on schedule and remediation on demand via OIDC and AssumeRole.

Repository structure
- baselines/rds-baseline.json – baseline parameters & exports with severity.
- dam-detection.py / dam-remediation.py – detection & remediation scripts.
- dam-detection-role.yaml – CloudFormation: detection-only IAM role (optional OIDC provider).
- dam-remediation-role.yaml – CloudFormation: remediation IAM role (optional OIDC provider & log group mgmt actions).
- .github/workflows/detection.yml / remediation.yml – automation.
- test-rds-dam-stack.yaml – optional test stack (scripts only).
- README.md – this document.


Baseline JSON (schemaVersion 1 with severity)
- Managed as code; one file can cover multiple engines. Current example (mirrors the default `baselines/rds-baseline.json` in this repo):
```json
{
  "schemaVersion": 1,
  "engines": {
    "rds/mysql": {
      "parameters": {
        "slow_query_log": "1",
        "long_query_time": "2",
        "log_output": "FILE",
        "general_log": "1"
      },
      "exports": ["error", "general", "slowquery"],
      "severity": {
        "parameters": {"slow_query_log": "high", "general_log": "medium", "long_query_time": "low", "log_output": "low"},
        "exports": {"error": "high", "general": "medium", "slowquery": "low"}
      }
    },
    "rds/aurora-postgresql": {
      "clusterParameters": {
        "pgaudit.role": "rds_pgaudit",
        "shared_preload_libraries": "pg_stat_statements,pgaudit",
        "pgaudit.log": "all",
        "log_connections": "1",
        "log_disconnections": "1",
        "log_error_verbosity": "default"
      },
      "exports": ["postgresql"],
      "severity": {
        "clusterParameters": {"pgaudit.role": "high", "shared_preload_libraries": "high", "pgaudit.log": "high", "log_connections": "medium", "log_disconnections": "medium", "log_error_verbosity": "low"},
        "exports": {"postgresql": "high"}
      }
    },
    "rds/sqlserver-ex": {"parameters": {"default language": "0"}, "exports": ["error"], "severity": {"parameters": {"default language": "low"}, "exports": {"error": "high"}}},
    "rds/sqlserver-web": {"parameters": {"default language": "0"}, "exports": ["error"], "severity": {"parameters": {"default language": "low"}, "exports": {"error": "high"}}},
    "rds/sqlserver-se": {"parameters": {"default language": "0"}, "exports": ["error"], "severity": {"parameters": {"default language": "low"}, "exports": {"error": "high"}}},
    "rds/sqlserver-ee": {"parameters": {"default language": "0"}, "exports": ["error"], "severity": {"parameters": {"default language": "low"}, "exports": {"error": "high"}}}
  },
  "selection": {"tagKey": "DAMOnboarding", "tagValue": "true"},
  "rules": {"skipDefaultParameterGroups": true}
}
```
Key points:
- Engine keys use prefix `rds/<engine>` (mysql, aurora-postgresql, sqlserver-* variants).
- MySQL baseline enables slow/general query logging with `log_output=FILE`.
- Aurora `shared_preload_libraries` is additive (baseline subset required).
- `pgaudit.role` must pre-exist in each Aurora Postgres cluster.
- SQL Server editions beyond Express are included for forward enforcement readiness.
- `selection` tag filter narrows scope; remove it to scan all RDS assets.
- `skipDefaultParameterGroups=true` skips immutable AWS defaults.

## Severity Model

The baseline now includes a `severity` map per engine (separately for `parameters`, `clusterParameters`, and `exports`). These drive:
- Detection report annotation (each deviation includes `severity`).
- Aggregated severity totals in `aggregate-summary.json`.
- Gating logic in the detection workflow (`fail_min_severity`).
- Remediation scoping via `--min-severity`.

### Meaning of Levels
| Severity | Typical Use Cases | Rationale for Priority |
|----------|-------------------|-------------------------|
| high     | Audit / security logging disabled (e.g., `pgaudit.log`), mandatory audit role mis-set (`pgaudit.role`), critical error log export missing, required library (`shared_preload_libraries` subset) missing | Directly impacts audit/compliance visibility or foundational telemetry |
| medium   | Important visibility but not core audit (e.g., connection / disconnection logging, general log, slow query log presence depending on workload) | Aids troubleshooting and performance insight; still actionable but not a blocker |
| low      | Tuning / verbosity / optimization guidance (e.g., `long_query_time` threshold, output format) | Nice-to-have improvements; safe to defer |
| unknown  | No severity mapping provided in baseline | Treated as lowest priority unless updated |

You can add new levels (e.g., `critical`) if desired—detection will pass them through; update gating logic if you want distinct behavior.

### Customizing Severities
Edit `baselines/rds-baseline.json` under each engine:
```jsonc
"severity": {
  "parameters": { "slow_query_log": "high", "general_log": "medium" },
  "exports": { "error": "high", "general": "medium", "slowquery": "low" }
}
```
For Aurora cluster-level parameters use `clusterParameters` inside severity.

### How Detection Uses Them
Detection assigns `severity` to each deviation. Totals are aggregated as:
```json
"severityTotals": {"high": 2, "medium": 3, "low": 1, "unknown": 0}
```

### Workflow Gating
In the detection workflow dispatch inputs:
- `fail_on_drift=true|false` decides whether any eligible drift can fail the run.
- `fail_min_severity=low|medium|high` sets the *minimum* severity that triggers failure.
  - `low`: any drift fails.
  - `medium`: only medium or high drift fails.
  - `high`: only high drift fails.

### Remediation Phasing
`dam-remediation.py --min-severity <level>` allows progressive rollout:
1. Start with `--min-severity high` to fix critical gaps.
2. Move to `medium` once high deviations are eliminated.
3. Finish with `low` for full alignment.

### When to Reclassify
Promote a setting to a higher severity if:
- It enables/ensures audit logging required for regulatory frameworks.
- Its absence materially increases mean time to detect (MTTD) incidents.
Demote if the signal is too noisy or cost-intensive (e.g., general log on very high throughput systems) and you plan a different control.

### Adding a New Severity Level (Optional)
1. Add the label in baseline severity maps.
2. Update detection workflow gating bash case to handle the new label.
3. Optionally adjust remediation threshold choices (`choices=["low","medium","high"]`).

### Quick Reference
| Task | File / Flag | Effect |
|------|-------------|--------|
| Change severity of a parameter | `baselines/rds-baseline.json` | Alters classification next detection run |
| Fail build only if high drift | workflow_dispatch input `fail_min_severity=high` | Medium/low ignored for failure |
| Dry-run remediation only for high | `dam-remediation.py --min-severity high` | Medium/low deviations skipped |
| Full enforcement | `fail_min_severity=low` + remediation with `--min-severity low` | All deviations treated |

If a deviation lacks a severity mapping it will appear as `unknown`; consider adding it or explicitly deciding to ignore it.

## Scripts

### dam-detection.py
Purpose: Non-destructive detection of deviations vs the baseline.

What it checks:
- Instance DB parameter groups vs `engines["rds/<engine>"].parameters` (if not `default.*` or if `skipDefaultParameterGroups=false`).
- Instance `EnabledCloudwatchLogsExports` vs baseline `exports` (MySQL, SQL Server) and optionally existence of matching CloudWatch log groups (`--check-log-groups`).
- Aurora cluster parameter groups vs `clusterParameters` and cluster exports (plus log groups if flag set).

Key safeguards / behaviors:
- Mutually exclusive credential flags: either `--account-role-arn` or `--use-current-credentials` (omitting both uses ambient creds).
- Baseline structural validation (fast fail with meaningful errors).
- Sensitive value masking: parameter names containing `password|secret|token|key|credential` are masked (`***MASKED***`) in output only.
- AccessDenied & NotFound warnings surfaced (rather than silent suppression) for tags/log groups.
- Light retry (exponential backoff) for throttled parameter/tag lookups.
- Core logic extracted to `detect()` for unit/integration testing.
- Type-aware comparison: integers, floats, booleans compared using native semantics; strings fallback to exact compare. Multi-value subset logic applied to `shared_preload_libraries`.
- Metadata embedded in report: `baselineHash` (sha256), `toolVersion`, `reportSchemaVersion` (currently 1).
- Optional strict baseline completeness enforcement via `--fail-on-unknown-severity` (exit code 3 when unknown severities exist).

Input arguments:
- `--baseline` (required) – path to baseline JSON.
- `--region` (required) – AWS region.
- `--account-role-arn` OR `--use-current-credentials`.
- `--output` – full JSON report (default `detect-report.json`).
- `--summary-output` – summary (default `detect-summary.json`).
- `--check-log-groups` – verify CloudWatch log groups exist for enabled exports.
- `--fail-on-unknown-severity` – treat any deviation whose severity cannot be mapped as a failure (exit 3).

Output artifacts:
- Report: deviations array for instances/clusters, each deviation normalized to always include `name`.
- Summary: counts + severity totals + metadata (`baselineHash`, `toolVersion`, `reportSchemaVersion`).
- Exit codes:
  - 0: No drift.
  - 1: Baseline invalid / credential / assume-role failure.
  - 2: Drift detected.
  - 3: Unknown severity encountered with `--fail-on-unknown-severity`.

Warnings (stderr) do not change exit code unless coupled with the unknown severity flag.

Example (PowerShell, assume role):
```powershell
python .\dam-detection.py `
  --baseline .\baselines\rds-baseline.json `
  --region eu-west-1 `
  --account-role-arn arn:aws:iam::<ACCOUNT_ID>:role/RDSComplianceRole `
  --output .\reports\detect-<ACCOUNT_ID>-eu-west-1.json
```

Example (ambient credentials + log group checks + strict severity):
```powershell
python .\dam-detection.py `
  --baseline .\baselines\rds-baseline.json `
  --region eu-west-1 `
  --use-current-credentials `
  --check-log-groups `
  --fail-on-unknown-severity
```
```

dam-remediation.py (Experimental)
- Current draft intended for code review / sandbox only.
- Interface, flags, and behavior may change; no backward compatibility guarantee.
- Do NOT embed in CI/CD or production GitHub Actions yet.
- Detailed usage examples intentionally removed to reduce risk of accidental deployment.

GitHub Actions

Detection workflow (scheduled + manual)
- Uses OIDC to assume per-account roles supplied as input.
- Produces per-account full reports and summaries; aggregate job combines into `all-detect.json`, `all-summaries.json`, and `aggregate-summary.json` with consolidated severity counts.
- Drift gating is configurable via dispatch inputs:
  - `fail_on_drift` (true|false, default true) – whether drift can fail the run.
  - `fail_min_severity` (low|medium|high, default low) – minimum severity that triggers failure when `fail_on_drift=true`.
    - Observation mode: fail_on_drift=false
    - Phased enforcement: fail_on_drift=true + fail_min_severity=high (start) then medium
    - Full enforcement: fail_on_drift=true + fail_min_severity=low
  - Scheduled runs can optionally be adjusted later to soft-fail automatically if desired.
Key points:
- permissions: id-token: write to enable OIDC.
- Parse a comma-separated list of role ARNs; iterate per region.

Remediation workflow (Experimental – DO NOT DEPLOY)
- Intentionally not documented for production; hold off until GA announcement.

Cross-account and permissions
- No stacks created in child accounts. You only need an IAM role per account (e.g., RDSComplianceRole) with trust policy allowing your GitHub OIDC provider to assume it, and policy with least-privilege:
  - Read: rds:Describe*, rds:ListTagsForResource
  - Write (only if remediation is used): rds:ModifyDBParameterGroup, rds:ModifyDBClusterParameterGroup, rds:ModifyDBInstance, rds:ModifyDBCluster
- Optional: logs:DescribeLogGroups if you later add log group verification (creation is out of scope here by design).

Operational guidance
- Start with detection only. Review reports and tune the baseline (PRs).
- On agreement, run remediation in dry-run; then apply with approval.
- For static parameters (require reboot), plan maintenance windows. The scripts do not reboot resources.
- Aurora exports must be modified at the cluster level (scripts handle this). Instance-level export changes are skipped for Aurora members.

Troubleshooting
- Access denied when assuming role:
  - Check the OIDC trust policy and that the role ARN matches. Ensure audience and subject conditions align with your org’s GitHub settings.
- Baseline invalid error:
  - The validator requires a non-empty `engines` object and at least one of `parameters`, `clusterParameters`, or `exports` per engine. Also warns on duplicate exports, orphan severity references, and non-standard levels (still allowed unless enforced downstream). Fix structural issues and re-run.
- Exit code 3 (unknown severity failure):
  - Add missing severity mappings or drop the `--fail-on-unknown-severity` flag if intentional during baseline evolution.
- “previous configuration is in progress” on remediation:
  - Re-run later; the script includes backoff but may need time after prior changes.
- Default parameter groups:
  - If your environments use default.* groups but you still want to enforce values, set rules.skipDefaultParameterGroups = false (note: many defaults are immutable).
- Missing CloudWatch log group warnings:
  - If you see many warnings with AccessDenied for log groups, ensure the scanning role has `logs:DescribeLogGroups`.
- Masked values in report:
  - Masking is name-based pattern matching. If a non-sensitive parameter is masked unexpectedly, rename baseline key if possible or adjust pattern (requires code edit).

License and contributions
- (Add a LICENSE file if distributing publicly.)
- PRs/issues welcome. Do not include secrets or account IDs in examples.
 
## IAM Roles (GitHub Actions OIDC)

You can now deploy detection and remediation IAM roles separately; **only the detection role should be deployed at this time**. The remediation role template is for review only.

Files:
- [`dam-detection-role.yaml`](./dam-detection-role.yaml) – Detection-only (read) role (optionally also creates the GitHub OIDC provider).
- [`dam-remediation-role.yaml`](./dam-remediation-role.yaml) – Remediation (write) role – **Experimental: do NOT deploy in production**.

Current recommended pattern:
1. Deploy detection only; run on a schedule to baseline drift.
2. Defer any remediation deployment until it reaches GA.

Shared key parameters (both templates):
- `GitHubOwner` / `GitHubRepo`: OWNER/REPO that will run the workflows.
- `IncludeOIDCProvider`: true if the GitHub OIDC provider does NOT yet exist in the account. Only one stack should create it.
- `AdditionalIAMPrincipals`: Extra principals (comma separated) permitted to assume for local or break‑glass testing.
- `PermissionBoundaryArn`: Attach an organizational permission boundary if required.

Detection template specific:
- `DetectionRestrictToBranch`: Optional; lock detection to a single branch (leave blank to allow any ref such as feature branches / PRs).

Remediation template specific (Experimental – subject to change):
- `RestrictToBranch`: Branch restriction (avoid use until GA).
- `EnableLogGroupCreation`: Potential capability; avoid enabling now.

Example deploy (detection-only) – PowerShell:
```powershell
aws cloudformation deploy `
  --stack-name rds-compliance-detection `
  --template-file dam-detection-role.yaml `
  --capabilities CAPABILITY_IAM `
  --parameter-overrides `
    GitHubOwner=your-org `
    GitHubRepo=your-repo `
    IncludeOIDCProvider=true ` # Set true only once per account
    DetectionRestrictToBranch= # blank => all refs
```

Remediation deploy example intentionally omitted (experimental).

Outputs:
- Detection stack: `DetectionRoleArn`, `ProviderCreated`, `DetectionBranchRestricted`.
- Remediation stack (if deployed only in an isolated sandbox for evaluation): `RemediationRoleArn`, `ProviderCreated`, `BranchRestricted`, `LogGroupManagementEnabled`.

If you still prefer a single combined template approach, you can synthesize one from these two files (earlier commit history in the repo also contains a combined version).

### Which template should I deploy?

| Scenario | Deploy Detection (`dam-detection-role.yaml`) | Deploy Remediation (`dam-remediation-role.yaml`) | Notes |
|----------|----------------------------------------------|--------------------------------------------------|-------|
| Baseline / observability | Yes | No | Stable read-only telemetry. |
| Severity tuning period | Yes | No | Keep remediation disabled. |
| Sandbox experimentation | Yes | Optional (sandbox only) | Never in production yet. |
| Production enforcement desire | Yes | No | Wait for remediation GA. |
| Multi-account rollout | Yes | No | Single OIDC provider; detection only. |
| Incident/drift investigation | Yes | No | Detection sufficient. |

Tip: If unsure, deploy detection only; remediation enablement will be announced when production-ready.

## Test Infrastructure (Optional)

`test-rds-dam-stack.yaml` (optional) creates:
- Public VPC, two public subnets, a permissive security group (test only!)
- Aurora PostgreSQL: two clusters (only one tagged for onboarding) + instances
- MySQL instance with intentional logging drift
- SQL Server Express instance with drift surfaces

Deployment (PowerShell example):
```powershell
aws cloudformation deploy `
  --stack-name rds-compliance-test `
  --template-file test-rds-dam-stack.yaml `
  --capabilities CAPABILITY_NAMED_IAM `
  --parameter-overrides DBUsername=admin DBPassword='YourStrongPassw0rd!' `
  --region eu-west-1
```

Run detection; review `detect-report.json`; execute remediation (dry-run first, then with --apply) to observe corrections. Delete the stack when finished to reduce cost:
```powershell
aws cloudformation delete-stack --stack-name rds-compliance-test --region eu-west-1
aws cloudformation wait stack-delete-complete --stack-name rds-compliance-test --region eu-west-1
```

Optional: extend the stack with additional engines or remove unneeded ones to minimize cost footprint.

