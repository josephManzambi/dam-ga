import json, argparse, time, sys, re, hashlib
import boto3
from botocore.exceptions import ClientError, NoCredentialsError

def assume_role(role_arn: str, region: str):
    sts = boto3.client("sts", region_name=region)
    creds = sts.assume_role(RoleArn=role_arn, RoleSessionName="RDSRemediate")["Credentials"]
    return boto3.session.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
        region_name=region
    )

TOOL_VERSION = "1.1.0"  # Align with detection
SENSITIVE_PARAM_PATTERN = re.compile(r"(password|secret|token|key|credential)", re.I)

def mask_value(name, value):
    if value is None:
        return None
    if SENSITIVE_PARAM_PATTERN.search(name or ""):
        return "***MASKED***"
    return value

def compute_file_sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            h.update(chunk)
    return h.hexdigest()

def validate_baseline(baseline: dict):
    if not isinstance(baseline, dict):
        raise ValueError("Baseline root must be object")
    if "engines" not in baseline or not isinstance(baseline["engines"], dict) or not baseline["engines"]:
        raise ValueError("Baseline missing non-empty 'engines'")
    for eng_name, eng_def in baseline["engines"].items():
        if not isinstance(eng_def, dict):
            raise ValueError(f"Engine '{eng_name}' def must be object")
        if not any(k in eng_def for k in ("parameters", "clusterParameters", "exports")):
            raise ValueError(f"Engine '{eng_name}' has no parameters/clusterParameters/exports")
    return True

def chunk(lst, n):
    for i in range(0, len(lst), n):
        yield lst[i:i+n]

def apply_instance_params(rds, pg, changes, dry_run):
    if dry_run or not changes: return
    for batch in chunk(changes, 20):
        rds.modify_db_parameter_group(DBParameterGroupName=pg, Parameters=batch)

def apply_cluster_params(rds, pg, changes, dry_run):
    if dry_run or not changes: return
    for batch in chunk(changes, 20):
        rds.modify_db_cluster_parameter_group(DBClusterParameterGroupName=pg, Parameters=batch)

# Helper: create CW log group if missing (idempotent)
def ensure_log_group(logs, name: str, retention_days: int | None = None, tags: dict | None = None) -> bool:
    # check existence
    try:
        paginator = logs.get_paginator("describe_log_groups")
        for page in paginator.paginate(logGroupNamePrefix=name):
            for lg in page.get("logGroups", []):
                if lg.get("logGroupName") == name:
                    return False
    except ClientError:
        pass
    # create
    params = {"logGroupName": name}
    if tags:
        params["tags"] = tags
    logs.create_log_group(**params)
    if retention_days:
        logs.put_retention_policy(logGroupName=name, retentionInDays=retention_days)
    return True

# Helper: expected log group names for exports
def expected_instance_log_groups(db_id: str, exports: list[str]) -> list[str]:
    base = f"/aws/rds/instance/{db_id}"
    return [f"{base}/{e}" for e in exports]

def expected_cluster_log_groups(cluster_id: str, exports: list[str]) -> list[str]:
    base = f"/aws/rds/cluster/{cluster_id}"
    return [f"{base}/{e}" for e in exports]

def main():
    ap = argparse.ArgumentParser(description="Apply remediation based on detection report and baseline.")
    ap.add_argument("--baseline", required=True)
    ap.add_argument("--report", required=True, help="Path to detect-report.json")
    ap.add_argument("--region", required=True)
    cred_group = ap.add_mutually_exclusive_group(required=True)
    cred_group.add_argument("--account-role-arn", help="Role to assume in the target account")
    cred_group.add_argument("--use-current-credentials", action="store_true", help="Use ambient credentials")
    ap.add_argument("--apply", action="store_true", help="Actually apply changes (otherwise dry-run)")
    ap.add_argument("--ensure-log-groups", action="store_true", help="Also create missing CloudWatch log groups for enabled exports")
    ap.add_argument("--log-retention-days", type=int, default=30, help="Retention for created log groups")
    ap.add_argument("--min-severity", default="low", choices=["low","medium","high"], help="Minimum deviation severity to remediate (default: low)")
    ap.add_argument("--fail-on-unknown-severity", action="store_true", help="Fail if unknown severity deviations meet threshold")
    args = ap.parse_args()
    dry_run = not args.apply

    try:
        baseline = json.load(open(args.baseline, "r", encoding="utf-8"))
        validate_baseline(baseline)
    except (OSError, ValueError) as e:
        print(f"ERROR: Baseline invalid: {e}", file=sys.stderr)
        sys.exit(1)
    try:
        report = json.load(open(args.report, "r", encoding="utf-8"))
    except OSError as e:
        print(f"ERROR: Unable to read report: {e}", file=sys.stderr)
        sys.exit(1)

    # Acquire session
    if args.account_role_arn:
        try:
            session = assume_role(args.account_role_arn, args.region)
        except ClientError as e:
            print(f"ERROR: AssumeRole failed: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        try:
            session = boto3.session.Session(region_name=args.region)
            session.client("sts").get_caller_identity()
        except NoCredentialsError:
            print("ERROR: No ambient credentials", file=sys.stderr)
            sys.exit(1)
        except ClientError as e:
            print(f"ERROR: Ambient credential validation failed: {e}", file=sys.stderr)
            sys.exit(1)

    rds = session.client("rds")
    logs = session.client("logs")

    severity_rank = {"high":3, "medium":2, "low":1, "unknown":0}
    threshold = severity_rank.get(args.min_severity, 1)

    # Helper to get baseline expected value (unmasked) for a deviation
    def desired_value_for(dev):
        eng = dev.get("engine") or dev.get("engineKey")
        # dev doesn't contain engine for each deviation; inherit from parent context
        return None

    engines = baseline.get("engines", {})
    def fetch_baseline_value(engine_key: str, scope: str, kind: str, name: str):
        eng_def = engines.get(engine_key, {})
        if kind == "parameter":
            if scope == "cluster":
                return (eng_def.get("clusterParameters") or {}).get(name)
            return (eng_def.get("parameters") or {}).get(name)
        if kind == "export":
            return name  # exports enabling only needs the name
        return None

    unknown_severity_flagged = False

    # Instances
    for inst in report.get("instances", []):
        db_id = inst["db"]
        engine_key = f"rds/{inst.get('engine') }"
        # Gather current describe each loop
        db = rds.describe_db_instances(DBInstanceIdentifier=db_id)["DBInstances"][0]
        # Parameters
        if db.get("DBParameterGroups"):
            pg = db["DBParameterGroups"][0]["DBParameterGroupName"]
            param_deltas = []
            for dev in inst["deviations"]:
                if dev["kind"] == "parameter":
                    sev = dev.get("severity", "unknown")
                    if sev == "unknown":
                        unknown_severity_flagged = True
                    if severity_rank.get(sev,0) < threshold:
                        continue
                    desired = fetch_baseline_value(engine_key, "instance", "parameter", dev["name"])
                    if desired is None:
                        continue  # skip if not in baseline anymore
                    apply_method = "immediate"
                    param_deltas.append({"ParameterName": dev["name"], "ParameterValue": str(desired), "ApplyMethod": apply_method})
            apply_instance_params(rds, pg, param_deltas, dry_run)
        # Exports (instance-level)
        exports = []
        for d in inst["deviations"]:
            if d["kind"] == "export" and d.get("scope") == "instance":
                sev = d.get("severity", "unknown")
                if sev == "unknown":
                    unknown_severity_flagged = True
                if severity_rank.get(sev,0) >= threshold:
                    exports.append(d["name"])
        if exports and not dry_run:
            # Backoff if busy
            for attempt in range(5):
                try:
                    rds.modify_db_instance(
                        DBInstanceIdentifier=db_id,
                        CloudwatchLogsExportConfiguration={"EnableLogTypes": sorted(set(exports))},
                        ApplyImmediately=True
                    )
                    break
                except ClientError as e:
                    msg = str(e).lower()
                    if "previous configuration is in progress" in msg:
                        time.sleep(5 + attempt * 5)
                        continue
                    raise
        # Create missing log groups if detection reported them or if --ensure-log-groups is set
        if not dry_run:
            missing_lgs = [d["logGroup"] for d in inst["deviations"] if d.get("kind") == "log-group" and severity_rank.get(d.get("severity","unknown"),0) >= threshold]
            if args.ensure_log_groups:
                # Derive for current exports (if any were enabled previously or just now)
                derived = expected_instance_log_groups(db_id, sorted(set((db.get("EnabledCloudwatchLogsExports") or []) + exports)))
                missing_lgs.extend(derived)
            created = []
            for lg in sorted(set(missing_lgs)):
                try:
                    if ensure_log_group(logs, lg, retention_days=args.log_retention_days):
                        created.append(lg)
                except ClientError as e:
                    print(f"Failed to create log group {lg}: {e}")
            if created:
                print(f"{db_id}: created log groups: {created}")

    # Clusters
    for cl in report.get("clusters", []):
        cluster_id = cl["cluster"]
        engine_key = "rds/aurora-postgresql"
        cluster = rds.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0]
        # Cluster parameters
        pg = cluster.get("DBClusterParameterGroup")
        cluster_deltas = []
        for dev in cl["deviations"]:
            if dev["kind"] == "parameter" and dev.get("scope") == "cluster":
                sev = dev.get("severity", "unknown")
                if sev == "unknown":
                    unknown_severity_flagged = True
                if severity_rank.get(sev,0) < threshold:
                    continue
                desired = fetch_baseline_value(engine_key, "cluster", "parameter", dev["name"])
                if desired is None:
                    continue
                cluster_deltas.append({"ParameterName": dev["name"], "ParameterValue": str(desired), "ApplyMethod": "immediate"})
        apply_cluster_params(rds, pg, cluster_deltas, dry_run)
        # Cluster exports
        exports = []
        for d in cl["deviations"]:
            if d["kind"] == "export" and d.get("scope") == "cluster":
                sev = d.get("severity", "unknown")
                if sev == "unknown":
                    unknown_severity_flagged = True
                if severity_rank.get(sev,0) >= threshold:
                    exports.append(d["name"])
        if exports and not dry_run:
            for attempt in range(5):
                try:
                    rds.modify_db_cluster(
                        DBClusterIdentifier=cluster_id,
                        CloudwatchLogsExportConfiguration={"EnableLogTypes": sorted(set(exports))},
                        ApplyImmediately=True
                    )
                    break
                except ClientError as e:
                    msg = str(e).lower()
                    if "previous configuration is in progress" in msg:
                        time.sleep(5 + attempt * 5)
                        continue
                    raise
        # Create missing cluster log groups
        if not dry_run:
            missing_lgs = [d["logGroup"] for d in cl["deviations"] if d.get("kind") == "log-group" and severity_rank.get(d.get("severity","unknown"),0) >= threshold]
            if args.ensure_log_groups:
                derived = expected_cluster_log_groups(cluster_id, sorted(set((cluster.get("EnabledCloudwatchLogsExports") or []) + exports)))
                missing_lgs.extend(derived)
            created = []
            for lg in sorted(set(missing_lgs)):
                try:
                    if ensure_log_group(logs, lg, retention_days=args.log_retention_days):
                        created.append(lg)
                except ClientError as e:
                    print(f"Failed to create log group {lg}: {e}")
            if created:
                print(f"{cluster_id}: created cluster log groups: {created}")

    if args.fail_on_unknown_severity and unknown_severity_flagged and severity_rank.get(args.min_severity,1) <= 1:
        print("ERROR: Unknown severity deviations encountered and --fail-on-unknown-severity specified", file=sys.stderr)
        sys.exit(3)
    print(("Remediation completed (dry-run)" if dry_run else "Remediation applied") + f" (min severity: {args.min_severity})")

if __name__ == "__main__":
    main()
