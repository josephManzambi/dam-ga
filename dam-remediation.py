import os, json, argparse, time
import boto3
from botocore.exceptions import ClientError

def assume_role(role_arn: str, region: str):
    sts = boto3.client("sts", region_name=region)
    creds = sts.assume_role(RoleArn=role_arn, RoleSessionName="RDSRemediate")["Credentials"]
    return boto3.session.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
        region_name=region
    )

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
    ap.add_argument("--account-role-arn", required=True)
    ap.add_argument("--apply", action="store_true", help="Actually apply changes (otherwise dry-run)")
    ap.add_argument("--ensure-log-groups", action="store_true", help="Also create missing CloudWatch log groups for enabled exports")
    ap.add_argument("--log-retention-days", type=int, default=30, help="Retention for created log groups")
    ap.add_argument("--min-severity", default="low", choices=["low","medium","high"], help="Minimum deviation severity to remediate (default: low)")
    args = ap.parse_args()
    dry_run = not args.apply

    baseline = json.load(open(args.baseline, "r", encoding="utf-8"))
    report = json.load(open(args.report, "r", encoding="utf-8"))
    session = assume_role(args.account_role_arn, args.region)
    rds = session.client("rds")
    logs = session.client("logs")

    severity_rank = {"high":3, "medium":2, "low":1, "unknown":0}
    threshold = severity_rank.get(args.min_severity, 1)

    # Instances
    for inst in report.get("instances", []):
        db_id = inst["db"]
        # Gather current describe each loop
        db = rds.describe_db_instances(DBInstanceIdentifier=db_id)["DBInstances"][0]
        # Parameters
        if db.get("DBParameterGroups"):
            pg = db["DBParameterGroups"][0]["DBParameterGroupName"]
            param_deltas = []
            for dev in inst["deviations"]:
                if dev["kind"] == "parameter":
                    if severity_rank.get(dev.get("severity","unknown"),0) < threshold:
                        continue
                    apply_method = "immediate"  # keep simple; static will mark pending-reboot server-side
                    param_deltas.append({"ParameterName": dev["name"], "ParameterValue": str(dev["expected"]), "ApplyMethod": apply_method})
            apply_instance_params(rds, pg, param_deltas, dry_run)
        # Exports (instance-level)
        exports = [d["name"] for d in inst["deviations"] if d["kind"] == "export" and d.get("scope") == "instance" and severity_rank.get(d.get("severity","unknown"),0) >= threshold]
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
        cluster = rds.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0]
        # Cluster parameters
        pg = cluster.get("DBClusterParameterGroup")
        cluster_deltas = []
        for dev in cl["deviations"]:
            if dev["kind"] == "parameter" and dev.get("scope") == "cluster":
                if severity_rank.get(dev.get("severity","unknown"),0) < threshold:
                    continue
                cluster_deltas.append({"ParameterName": dev["name"], "ParameterValue": str(dev["expected"]), "ApplyMethod": "immediate"})
        apply_cluster_params(rds, pg, cluster_deltas, dry_run)
        # Cluster exports
        exports = [d["name"] for d in cl["deviations"] if d["kind"] == "export" and d.get("scope") == "cluster" and severity_rank.get(d.get("severity","unknown"),0) >= threshold]
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

    print(("Remediation completed (dry-run)" if dry_run else "Remediation applied") + f" (min severity: {args.min_severity})")

if __name__ == "__main__":
    main()
