import os, json, sys, argparse
import boto3
from botocore.exceptions import ClientError, NoCredentialsError

def assume_role(role_arn: str, region: str):
    sts = boto3.client("sts", region_name=region)
    creds = sts.assume_role(RoleArn=role_arn, RoleSessionName="RDSDetect")["Credentials"]
    return boto3.session.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
        region_name=region
    )

def load_baseline(path: str):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def list_all_instances(rds):
    paginator = rds.get_paginator("describe_db_instances")
    out = []
    for page in paginator.paginate():
        out.extend(page.get("DBInstances", []))
    return out

def list_all_clusters(rds):
    paginator = rds.get_paginator("describe_db_clusters")
    out = []
    for page in paginator.paginate():
        out.extend(page.get("DBClusters", []))
    return out

def gather_params(rds, pg_name):
    params, marker = [], None
    while True:
        kwargs = {"DBParameterGroupName": pg_name}
        if marker: kwargs["Marker"] = marker
        resp = rds.describe_db_parameters(**kwargs)
        params.extend(resp.get("Parameters", []))
        marker = resp.get("Marker")
        if not marker: break
    m = {}
    for p in params:
        name = p["ParameterName"]
        m[name] = p.get("ParameterValue", p.get("ParameterDefaultValue"))
    return m

def gather_cluster_params(rds, pg_name):
    params, marker = [], None
    while True:
        kwargs = {"DBClusterParameterGroupName": pg_name}
        if marker: kwargs["Marker"] = marker
        resp = rds.describe_db_cluster_parameters(**kwargs)
        params.extend(resp.get("Parameters", []))
        marker = resp.get("Marker")
        if not marker: break
    m = {}
    for p in params:
        name = p["ParameterName"]
        m[name] = p.get("ParameterValue", p.get("ParameterDefaultValue"))
    return m

def tags_for_arn(rds, arn):
    try:
        return rds.list_tags_for_resource(ResourceName=arn).get("TagList", [])
    except ClientError:
        return []

def cw_log_group_exists(logs, name: str) -> bool:
    try:
        paginator = logs.get_paginator("describe_log_groups")
        for page in paginator.paginate(logGroupNamePrefix=name):
            for lg in page.get("logGroups", []):
                if lg.get("logGroupName") == name:
                    return True
    except ClientError:
        pass
    return False

def expected_instance_log_groups(db_id: str, exports: list[str]) -> list[str]:
    base = f"/aws/rds/instance/{db_id}"
    return [f"{base}/{e}" for e in exports]

def expected_cluster_log_groups(cluster_id: str, exports: list[str]) -> list[str]:
    base = f"/aws/rds/cluster/{cluster_id}"
    return [f"{base}/{e}" for e in exports]

def main():
    ap = argparse.ArgumentParser(description="Detect deviations from RDS baseline.")
    ap.add_argument("--baseline", required=True, help="Path to baseline JSON file")
    ap.add_argument("--region", required=True)
    ap.add_argument("--account-role-arn", required=False, help="Role to assume in the target account (omit to use ambient credentials)")
    ap.add_argument("--use-current-credentials", action="store_true", help="Do not call STS AssumeRole; use the already provided ambient credentials")
    ap.add_argument("--output", default="detect-report.json")
    ap.add_argument("--summary-output", default="detect-summary.json", help="Path to write a drift summary (counts)")
    ap.add_argument("--check-log-groups", action="store_true", help="Also detect missing CloudWatch log groups for currently enabled exports")
    args = ap.parse_args()

    baseline = load_baseline(args.baseline)
    # Decide how to obtain a session
    if args.use_current_credentials or not args.account_role_arn:
        try:
            # Validate we at least have some caller identity
            session = boto3.session.Session(region_name=args.region)
            _ = session.client("sts").get_caller_identity()
        except NoCredentialsError:
            print("ERROR: No ambient AWS credentials and no --account-role-arn provided", file=sys.stderr)
            sys.exit(1)
        except ClientError as e:
            print(f"ERROR: Unable to validate ambient credentials: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        session = assume_role(args.account_role_arn, args.region)
    rds = session.client("rds")
    logs = session.client("logs")

    selection = baseline.get("selection", {})
    tag_key = selection.get("tagKey")
    tag_val = selection.get("tagValue")

    report = {"account": None, "region": args.region, "instances": [], "clusters": []}
    sts = session.client("sts")
    report["account"] = sts.get_caller_identity()["Account"]

    # Aggregate counters
    total_param_drifts = 0
    total_export_drifts = 0
    total_log_group_drifts = 0
    objects_with_drift = 0

    # Instances
    for db in list_all_instances(rds):
        arn = db["DBInstanceArn"]
        if tag_key:
            t = {x["Key"]: x.get("Value") for x in tags_for_arn(rds, arn)}
            if t.get(tag_key) != tag_val:
                continue
        engine = (db.get("Engine") or "").lower()
        engine_key = f"rds/{engine}"
        base = baseline["engines"].get(engine_key)
        if not base:
            continue

        dev = {"db": db["DBInstanceIdentifier"], "engine": engine, "type": "instance", "deviations": []}
        # Parameter group
        if db.get("DBParameterGroups"):
            pg = db["DBParameterGroups"][0]["DBParameterGroupName"]
            if not pg.startswith("default.") or not baseline["rules"].get("skipDefaultParameterGroups", True):
                current = gather_params(rds, pg)
                for k, v in (base.get("parameters") or {}).items():
                    if str(current.get(k)) != str(v):
                        dev["deviations"].append({"kind": "parameter", "name": k, "current": current.get(k), "expected": v, "pg": pg})
        # Exports (instance-level)
        current_exports = set(db.get("EnabledCloudwatchLogsExports") or [])
        for needed in set(base.get("exports") or []):
            if needed not in current_exports:
                dev["deviations"].append({"kind": "export", "scope": "instance", "name": needed, "current": list(current_exports), "expected": base["exports"]})
        # Missing log groups for currently enabled exports (optional)
        if args.check_log_groups and current_exports:
            for lg in expected_instance_log_groups(db["DBInstanceIdentifier"], sorted(current_exports)):
                if not cw_log_group_exists(logs, lg):
                    dev["deviations"].append({"kind": "log-group", "scope": "instance", "logGroup": lg, "reason": "enabled export has no log group"})
        if dev["deviations"]:
            for d in dev["deviations"]:
                if d["kind"] == "parameter":
                    total_param_drifts += 1
                elif d["kind"] == "export":
                    total_export_drifts += 1
                elif d["kind"] == "log-group":
                    total_log_group_drifts += 1
            objects_with_drift += 1
            report["instances"].append(dev)

    # Clusters (Aurora)
    for cl in list_all_clusters(rds):
        if (cl.get("Engine") or "").lower() != "aurora-postgresql":
            continue
        engine_key = "rds/aurora-postgresql"
        base = baseline["engines"].get(engine_key)
        if not base:
            continue
        dev = {"cluster": cl["DBClusterIdentifier"], "engine": "aurora-postgresql", "type": "cluster", "deviations": []}
        # Cluster PG
        pg = cl.get("DBClusterParameterGroup")
        if pg and (not pg.startswith("default.") or not baseline["rules"].get("skipDefaultParameterGroups", True)):
            current = gather_cluster_params(rds, pg)
            for k, v in (base.get("clusterParameters") or {}).items():
                cur_val = current.get(k)
                if k == "shared_preload_libraries" and cur_val is not None:
                    want_set = set(x.strip() for x in str(v).split(',') if x.strip())
                    have_set = set(x.strip() for x in str(cur_val).split(',') if x.strip())
                    if not want_set.issubset(have_set):
                        dev["deviations"].append({"kind": "parameter", "scope": "cluster", "name": k, "current": cur_val, "expected": v, "pg": pg, "comparison": "subset"})
                    continue
                if cur_val is None or str(cur_val) != str(v):
                    dev["deviations"].append({"kind": "parameter", "scope": "cluster", "name": k, "current": cur_val, "expected": v, "pg": pg})
        # Cluster exports
        current_exports = set(cl.get("EnabledCloudwatchLogsExports") or [])
        for needed in set(base.get("exports") or []):
            if needed not in current_exports:
                dev["deviations"].append({"kind": "export", "scope": "cluster", "name": needed, "current": list(current_exports), "expected": base["exports"]})
        # Missing cluster log groups for currently enabled exports (optional)
        if args.check_log_groups and current_exports:
            for lg in expected_cluster_log_groups(cl["DBClusterIdentifier"], sorted(current_exports)):
                if not cw_log_group_exists(logs, lg):
                    dev["deviations"].append({"kind": "log-group", "scope": "cluster", "logGroup": lg, "reason": "enabled export has no log group"})
        if dev["deviations"]:
            for d in dev["deviations"]:
                if d["kind"] == "parameter":
                    total_param_drifts += 1
                elif d["kind"] == "export":
                    total_export_drifts += 1
                elif d["kind"] == "log-group":
                    total_log_group_drifts += 1
            objects_with_drift += 1
            report["clusters"].append(dev)

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    summary = {
        "account": report["account"],
        "region": report["region"],
        "objectsWithDrift": objects_with_drift,
        "paramDrifts": total_param_drifts,
        "exportDrifts": total_export_drifts,
        "logGroupDrifts": total_log_group_drifts,
        "hasDrift": bool(report["instances"] or report["clusters"])
    }
    with open(args.summary_output, "w", encoding="utf-8") as sf:
        json.dump(summary, sf, indent=2)
    print(f"Wrote detection report: {args.output}")
    print(f"Summary: {json.dumps(summary)}")
    if summary["hasDrift"]:
        sys.exit(2)

if __name__ == "__main__":
    main()