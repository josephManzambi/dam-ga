# RDS Compliance – Detection and Remediation (No-Infrastructure)

Overview
- Goal: Detect and optionally remediate deviations from an RDS logging/parameter baseline across multiple AWS accounts without deploying infrastructure.
- This project replaces the previous test stack (CloudFormation + Lambda + DynamoDB) with:
  - A JSON baseline file managed in Git.
  - Two Python scripts:
    - dam-detection.py: non-destructive detection (reports deviations).
    - dam-remediation.py: optional remediation (applies changes).
  - GitHub Actions workflows (optional) to run detection on schedule and remediation on demand via OIDC and AssumeRole.

Repository structure
- baselines/rds-baseline.json – baseline parameters & exports with severity.
- dam-detection.py / dam-remediation.py – detection & remediation scripts.
- iam-rds-compliance-roles.yaml – OIDC detection & remediation roles.
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

Scripts

dam-detection.py
- Purpose: Non-destructive detection of deviations vs baseline.
- What it checks:
  - Instance DB parameter groups vs engines["rds/<engine>"].parameters (if not default.* or if skipDefaultParameterGroups=false).
  - Instance EnabledCloudwatchLogsExports vs engines["..."].exports (MySQL, SQL Server).
  - Aurora cluster parameter groups vs clusterParameters and cluster EnabledCloudwatchLogsExports.
- Input arguments:
  - --baseline: path to baseline JSON.
  - --region: AWS region to scan.
  - --account-role-arn: IAM role ARN to assume in the target account (OIDC).
  - --output: output JSON report path (default detect-report.json).
- Output:
  - Full JSON report (instances/clusters with deviations) plus per-object deviation severity.
  - Summary JSON (counts: paramDrifts, exportDrifts, logGroupDrifts, severityTotals, objectsWithDrift, hasDrift).
  - Exit code 2 if deviations exist (CI will treat as failure unless overridden in workflow logic).

Example (Windows PowerShell)
```powershell
python .\scripts\dam-detection.py `
  --baseline .\baselines\rds-baseline.json `
  --region eu-west-1 `
  --account-role-arn arn:aws:iam::<ACCOUNT_ID>:role/RDSComplianceRole `
  --output .\reports\detect-<ACCOUNT_ID>-eu-west-1.json
```

dam-remediation.py
- Purpose: Optional application of changes to match the baseline (read-only unless --apply).
- What it does:
  - For instance deviations: ModifyDBParameterGroup (batched), ModifyDBInstance to enable missing exports (with retries if config in progress).
  - For cluster deviations (Aurora PG): ModifyDBClusterParameterGroup, ModifyDBCluster to enable missing cluster exports (with retries).
  - Honors a minimum severity threshold (`--min-severity`) so you can phase remediation (e.g., remediate only high first).
- Does NOT:
  - Create or delete infrastructure (no log group creation, no option groups).
  - Reboot instances/clusters automatically (RDS may set pending-reboot for static parameter changes).
- Input arguments:
  - --baseline: path to baseline JSON.
  - --report: path to a detection report (output of dam-detection.py).
  - --region, --account-role-arn: same as detection.
  - --apply: actually apply changes. Without this flag, it’s a dry-run.
  - --min-severity: low|medium|high (default low – apply all). Set to high for incremental rollout.
- Output:
  - Console logs indicating intended/applied changes.

Example (Windows PowerShell)
```powershell
# Dry-run (preview)
python .\scripts\dam-remediation.py `
  --baseline .\baselines\rds-baseline.json `
  --report .\reports\detect-<ACCOUNT_ID>-eu-west-1.json `
  --region eu-west-1 `
  --account-role-arn arn:aws:iam::<ACCOUNT_ID>:role/RDSComplianceRole

# Apply
python .\scripts\dam-remediation.py `
  --baseline .\baselines\rds-baseline.json `
  --report .\reports\detect-<ACCOUNT_ID>-eu-west-1.json `
  --region eu-west-1 `
  --account-role-arn arn:aws:iam::<ACCOUNT_ID>:role/RDSComplianceRole `
  --apply
```

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

Remediation workflow (manual, gated)
- Manual-only with environment protection/approval.
- Downloads a report artifact and runs dam-remediation.py.
- Add an explicit apply toggle or separate step requiring approval.

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
- “previous configuration is in progress” on remediation:
  - Re-run later; the script includes backoff but may need time after prior changes.
- Default parameter groups:
  - If your environments use default.* groups but you still want to enforce values, set rules.skipDefaultParameterGroups = false (note: many defaults are immutable).

License and contributions
- (Add a LICENSE file if distributing publicly.)
- PRs/issues welcome. Do not include secrets or account IDs in examples.
 
## IAM Roles (GitHub Actions OIDC)

Use the `iam-rds-compliance-roles.yaml` template to deploy detection and remediation roles.

Key parameters:
- GitHubOwner / GitHubRepo: OWNER/REPO that will run the workflows.
- IncludeOIDCProvider=true when you have NOT yet created the GitHub OIDC provider in the account (otherwise leave false).
- RestrictToBranch: Branch enforced for the remediation role (default: main). Leave blank to allow all refs.
- DetectionRestrictToBranch: (Optional) If you also want to lock detection to a branch; leave blank to allow experimentation from any ref.
- EnableLogGroupCreation=true to let remediation create and tag missing /aws/rds/* log groups (aligns with --ensure-log-groups option of remediation script).
- AdditionalIAMPrincipals: Comma-separated extra AWS principals (roles/users) that may assume the roles for local testing.
- PermissionBoundaryArn: Apply an org permission boundary if required.

Example deploy (PowerShell) using AWS CLI (adjust parameters):
```powershell
aws cloudformation deploy `
  --stack-name rds-compliance-roles `
  --template-file iam-rds-compliance-roles.yaml `
  --capabilities CAPABILITY_IAM `
  --parameter-overrides `
    GitHubOwner=your-org `
    GitHubRepo=your-repo `
    IncludeOIDCProvider=false `
    RestrictToBranch=main `
    DetectionRestrictToBranch= `
    EnableLogGroupCreation=true
```

After deployment, reference the exported role ARNs (or describe the stack) in your GitHub Actions workflows for detection and remediation.

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

