import json, sys, argparse, re, time, hashlib
import boto3
from botocore.exceptions import ClientError, NoCredentialsError

def assume_role(role_arn: str, region: str):
    """Assume the provided role and return a session.

    Raises ClientError on failure; caller should handle for clean messaging.
    """
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
        resp = call_with_retries(rds.describe_db_parameters, **kwargs)
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
        resp = call_with_retries(rds.describe_db_cluster_parameters, **kwargs)
        params.extend(resp.get("Parameters", []))
        marker = resp.get("Marker")
        if not marker: break
    m = {}
    for p in params:
        name = p["ParameterName"]
        m[name] = p.get("ParameterValue", p.get("ParameterDefaultValue"))
    return m

def validate_baseline(baseline: dict):
    """Lightweight structural validation of baseline file.

    Raises ValueError if required structure is missing or types mismatch.
    Expected top-level keys: engines (dict). Optional: rules (dict), selection (dict), schemaVersion (int).
    Each engine entry may contain: parameters (dict), clusterParameters (dict), exports (list), severity (dict).
    At least one of parameters/clusterParameters/exports must exist per engine.
    """
    if not isinstance(baseline, dict):
        raise ValueError("Baseline root must be an object (dict)")
    if "engines" not in baseline or not isinstance(baseline["engines"], dict) or not baseline["engines"]:
        raise ValueError("'engines' key must be a non-empty object")
    engines = baseline["engines"]
    allowed_severity = {"high", "medium", "low", "unknown", "critical"}  # allow future 'critical'
    for eng_name, eng_def in engines.items():
        if not isinstance(eng_def, dict):
            raise ValueError(f"Engine '{eng_name}' definition must be an object")
        has_any = False
        for key in ("parameters", "clusterParameters"):
            if key in eng_def:
                if not isinstance(eng_def[key], dict):
                    raise ValueError(f"Engine '{eng_name}' -> {key} must be an object")
                has_any = True
        if "exports" in eng_def:
            if not isinstance(eng_def["exports"], list):
                raise ValueError(f"Engine '{eng_name}' -> exports must be a list")
            # Detect duplicates
            if len(set(eng_def["exports"])) != len(eng_def["exports"]):
                print(f"WARNING: Duplicate export names found in engine '{eng_name}'", file=sys.stderr)
            has_any = True
        if not has_any:
            raise ValueError(f"Engine '{eng_name}' must define at least one of parameters/clusterParameters/exports")
        if "severity" in eng_def and not isinstance(eng_def["severity"], dict):
            raise ValueError(f"Engine '{eng_name}' -> severity must be an object")
        # Validate severity labels if present
        sev = eng_def.get("severity") or {}
        if sev:
            for sev_section, mapping in sev.items():
                if not isinstance(mapping, dict):
                    raise ValueError(f"Engine '{eng_name}' severity section '{sev_section}' must be an object")
                for name, level in mapping.items():
                    if level not in allowed_severity:
                        print(f"WARNING: Engine '{eng_name}' severity for '{name}' has non-standard level '{level}'", file=sys.stderr)
        # Orphan severity references (names not present in parameters/clusterParameters/exports)
        param_names = set((eng_def.get("parameters") or {}).keys())
        cparam_names = set((eng_def.get("clusterParameters") or {}).keys())
        export_names = set(eng_def.get("exports") or [])
        sev_map = eng_def.get("severity") or {}
        for section, mapping in sev_map.items():
            if section == "parameters":
                for n in mapping.keys():
                    if n not in param_names:
                        print(f"WARNING: Engine '{eng_name}' severity references parameter '{n}' not in parameters", file=sys.stderr)
            elif section == "clusterParameters":
                for n in mapping.keys():
                    if n not in cparam_names:
                        print(f"WARNING: Engine '{eng_name}' severity references clusterParameter '{n}' not in clusterParameters", file=sys.stderr)
            elif section == "exports":
                for n in mapping.keys():
                    if n not in export_names:
                        print(f"WARNING: Engine '{eng_name}' severity references export '{n}' not in exports", file=sys.stderr)
    # Optional types
    if "rules" in baseline and not isinstance(baseline["rules"], dict):
        raise ValueError("'rules' must be an object if provided")
    if "selection" in baseline and not isinstance(baseline["selection"], dict):
        raise ValueError("'selection' must be an object if provided")
    if "schemaVersion" in baseline and not isinstance(baseline["schemaVersion"], int):
        raise ValueError("'schemaVersion' must be an integer if provided")
    return True

# Sensitive parameter masking utilities (module-level for testability)
SENSITIVE_PARAM_PATTERN = re.compile(r"(password|secret|token|key|credential)", re.I)

def mask_value(param_name: str, value):
    if value is None:
        return None
    if SENSITIVE_PARAM_PATTERN.search(param_name or ""):
        return "***MASKED***"
    return value

def call_with_retries(fn, *args, retries: int = 3, backoff: float = 0.5, **kwargs):
    """Generic retry for throttling errors on AWS API calls.

    Retries on Throttling* error codes with simple exponential backoff.
    """
    for attempt in range(retries):
        try:
            return fn(*args, **kwargs)
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code")
            if code and (code.startswith("Throttling") or code == "RequestLimitExceeded") and attempt < retries - 1:
                sleep_time = backoff * (2 ** attempt)
                time.sleep(sleep_time)
                continue
            raise

TOOL_VERSION = "1.1.0"  # Update when logic changes materially
REPORT_SCHEMA_VERSION = 1

def compute_file_sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            h.update(chunk)
    return h.hexdigest()

def detect(baseline: dict, session, region: str, check_log_groups: bool, baseline_hash: str):
    """Core detection logic extracted for testability.

    Returns (report, summary) tuple.
    """
    rds = session.client("rds")
    logs = session.client("logs")

    selection = baseline.get("selection", {})
    tag_key = selection.get("tagKey")
    tag_val = selection.get("tagValue")

    report = {"account": None, "region": region, "schemaVersion": baseline.get("schemaVersion", 1),
              "reportSchemaVersion": REPORT_SCHEMA_VERSION,
              "toolVersion": TOOL_VERSION,
              "baselineHash": f"sha256:{baseline_hash}",
              "instances": [], "clusters": []}
    sts = session.client("sts")
    report["account"] = sts.get_caller_identity()["Account"]

    # Aggregate counters
    total_param_drifts = 0
    total_export_drifts = 0
    total_log_group_drifts = 0
    objects_with_drift = 0
    severity_totals = {"high": 0, "medium": 0, "low": 0, "unknown": 0}

    def classify(engine_key: str, scope: str, kind: str, name: str):
        eng = baseline.get("engines", {}).get(engine_key, {})
        sev_map = eng.get("severity", {})
        if kind == "parameter":
            if scope == "cluster":
                return sev_map.get("clusterParameters", {}).get(name) or sev_map.get("parameters", {}).get(name)
            return sev_map.get("parameters", {}).get(name)
        if kind == "export":
            return sev_map.get("exports", {}).get(name)
        if kind == "log-group":
            token = name.rsplit('/', 1)[-1] if '/' in name else name
            return sev_map.get("exports", {}).get(token)
        return None

    # Helper: type-aware comparison
    def values_differ(expected, current_raw):
        if expected is None and current_raw is None:
            return False
        # If expected type is numeric
        if isinstance(expected, bool):
            if current_raw is None:
                return True
            s = str(current_raw).strip().lower()
            truthy = {"1", "true", "t", "on", "yes"}
            falsy = {"0", "false", "f", "off", "no"}
            if s in truthy:
                cur_val = True
            elif s in falsy:
                cur_val = False
            else:
                return True  # Unparseable -> difference
            return cur_val != expected
        if isinstance(expected, int) and not isinstance(expected, bool):  # bool is subclass int
            try:
                return int(str(current_raw).strip()) != expected
            except (ValueError, TypeError):
                return True
        if isinstance(expected, float):
            try:
                return abs(float(str(current_raw).strip()) - expected) > 1e-9
            except (ValueError, TypeError):
                return True
        # Fallback string compare (case sensitive by default)
        return str(current_raw) != str(expected)

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
        if db.get("DBParameterGroups"):
            pg = db["DBParameterGroups"][0]["DBParameterGroupName"]
            if not pg.startswith("default.") or not baseline["rules"].get("skipDefaultParameterGroups", True):
                current = gather_params(rds, pg)
                for k, v in (base.get("parameters") or {}).items():
                    cur_val = current.get(k)
                    if values_differ(v, cur_val):
                        sev = classify(engine_key, "instance", "parameter", k) or "unknown"
                        dev["deviations"].append({
                            "kind": "parameter", "scope": "instance", "name": k,
                            "current": mask_value(k, cur_val), "expected": mask_value(k, v),
                            "pg": pg, "severity": sev
                        })
        current_exports = set(db.get("EnabledCloudwatchLogsExports") or [])
        for needed in set(base.get("exports") or []):
            if needed not in current_exports:
                sev = classify(engine_key, "instance", "export", needed) or "unknown"
                dev["deviations"].append({
                    "kind": "export", "scope": "instance", "name": needed,
                    "current": list(current_exports), "expected": base.get("exports"),
                    "severity": sev
                })
        if check_log_groups and current_exports:
            for lg in expected_instance_log_groups(db["DBInstanceIdentifier"], sorted(current_exports)):
                if not cw_log_group_exists(logs, lg):
                    sev = classify(engine_key, "instance", "log-group", lg) or "unknown"
                    dev["deviations"].append({
                        "kind": "log-group", "scope": "instance", "name": lg, "logGroup": lg,
                        "reason": "enabled export has no log group", "severity": sev
                    })
        if dev["deviations"]:
            for d in dev["deviations"]:
                if d["kind"] == "parameter":
                    total_param_drifts += 1
                elif d["kind"] == "export":
                    total_export_drifts += 1
                elif d["kind"] == "log-group":
                    total_log_group_drifts += 1
                sev = d.get("severity") or "unknown"
                severity_totals[sev] = severity_totals.get(sev, 0) + 1
            objects_with_drift += 1
            report["instances"].append(dev)

    # Clusters
    for cl in list_all_clusters(rds):
        if (cl.get("Engine") or "").lower() != "aurora-postgresql":
            continue
        engine_key = "rds/aurora-postgresql"
        base = baseline["engines"].get(engine_key)
        if not base:
            continue
        dev = {"cluster": cl["DBClusterIdentifier"], "engine": "aurora-postgresql", "type": "cluster", "deviations": []}
        pg = cl.get("DBClusterParameterGroup")
        if pg and (not pg.startswith("default.") or not baseline["rules"].get("skipDefaultParameterGroups", True)):
            current = gather_cluster_params(rds, pg)
            for k, v in (base.get("clusterParameters") or {}).items():
                cur_val = current.get(k)
                if k == "shared_preload_libraries" and cur_val is not None:
                    want_set = set(x.strip() for x in str(v).split(',') if x.strip())
                    have_set = set(x.strip() for x in str(cur_val).split(',') if x.strip())
                    if not want_set.issubset(have_set):
                        sev = classify(engine_key, "cluster", "parameter", k) or "unknown"
                        dev["deviations"].append({
                            "kind": "parameter", "scope": "cluster", "name": k,
                            "current": mask_value(k, cur_val), "expected": mask_value(k, v),
                            "pg": pg, "comparison": "subset", "severity": sev
                        })
                    continue
                if cur_val is None or values_differ(v, cur_val):
                    sev = classify(engine_key, "cluster", "parameter", k) or "unknown"
                    dev["deviations"].append({
                        "kind": "parameter", "scope": "cluster", "name": k,
                        "current": mask_value(k, cur_val), "expected": mask_value(k, v),
                        "pg": pg, "severity": sev
                    })
        current_exports = set(cl.get("EnabledCloudwatchLogsExports") or [])
        for needed in set(base.get("exports") or []):
            if needed not in current_exports:
                sev = classify(engine_key, "cluster", "export", needed) or "unknown"
                dev["deviations"].append({
                    "kind": "export", "scope": "cluster", "name": needed,
                    "current": list(current_exports), "expected": base.get("exports"),
                    "severity": sev
                })
        if check_log_groups and current_exports:
            for lg in expected_cluster_log_groups(cl["DBClusterIdentifier"], sorted(current_exports)):
                if not cw_log_group_exists(logs, lg):
                    sev = classify(engine_key, "cluster", "log-group", lg) or "unknown"
                    dev["deviations"].append({
                        "kind": "log-group", "scope": "cluster", "name": lg, "logGroup": lg,
                        "reason": "enabled export has no log group", "severity": sev
                    })
        if dev["deviations"]:
            for d in dev["deviations"]:
                if d["kind"] == "parameter":
                    total_param_drifts += 1
                elif d["kind"] == "export":
                    total_export_drifts += 1
                elif d["kind"] == "log-group":
                    total_log_group_drifts += 1
                sev = d.get("severity") or "unknown"
                severity_totals[sev] = severity_totals.get(sev, 0) + 1
            objects_with_drift += 1
            report["clusters"].append(dev)

    summary = {
        "account": report["account"],
        "region": report["region"],
        "objectsWithDrift": objects_with_drift,
        "paramDrifts": total_param_drifts,
        "exportDrifts": total_export_drifts,
        "logGroupDrifts": total_log_group_drifts,
        "hasDrift": bool(report["instances"] or report["clusters"]),
        "severityTotals": severity_totals,
        "baselineHash": f"sha256:{baseline_hash}",
        "toolVersion": TOOL_VERSION,
        "reportSchemaVersion": REPORT_SCHEMA_VERSION
    }
    return report, summary

def tags_for_arn(rds, arn):
    """Return tag list for an ARN.

    Distinguish AccessDenied (warn, return empty) from unexpected errors which are re-raised.
    """
    try:
        return call_with_retries(rds.list_tags_for_resource, ResourceName=arn).get("TagList", [])
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code")
        if code in ("AccessDenied", "AccessDeniedException"):
            print(f"WARNING: Access denied listing tags for {arn}: {code}", file=sys.stderr)
            return []
        if code and ("NotFound" in code or code.startswith("ResourceNotFound")):
            # Treat as no tags
            return []
        raise

def cw_log_group_exists(logs, name: str) -> bool:
    """Check if a CloudWatch log group exists.

    AccessDenied returns False with a warning; unexpected errors propagate.
    """
    try:
        paginator = logs.get_paginator("describe_log_groups")
        # paginate() returns a PageIterator internally calling API; wrap iteration with manual retry by materializing pages
        for page in paginator.paginate(logGroupNamePrefix=name):
            for lg in page.get("logGroups", []):
                if lg.get("logGroupName") == name:
                    return True
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code")
        if code in ("AccessDenied", "AccessDeniedException"):
            print(f"WARNING: Access denied describing log groups for prefix {name}: {code}", file=sys.stderr)
            return False
        if code and ("NotFound" in code or code.startswith("ResourceNotFound")):
            return False
        raise
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
    # Mutually exclusive credential acquisition methods
    cred_group = ap.add_mutually_exclusive_group(required=False)
    cred_group.add_argument("--account-role-arn", help="Role to assume in the target account")
    cred_group.add_argument("--use-current-credentials", action="store_true", help="Use ambient credentials; do not assume a role")
    ap.add_argument("--output", default="detect-report.json")
    ap.add_argument("--summary-output", default="detect-summary.json", help="Path to write a drift summary (counts)")
    ap.add_argument("--check-log-groups", action="store_true", help="Also detect missing CloudWatch log groups for currently enabled exports")
    ap.add_argument("--fail-on-unknown-severity", action="store_true", help="Exit with a distinct code if any deviation has unknown severity (baseline missing severity mapping)")
    # (Future) verbose flag could control warnings; currently warnings always emitted to stderr.
    args = ap.parse_args()

    baseline = load_baseline(args.baseline)
    # Validate baseline structure early
    try:
        validate_baseline(baseline)
    except ValueError as ve:
        print(f"ERROR: Invalid baseline: {ve}", file=sys.stderr)
        sys.exit(1)

    baseline_hash = compute_file_sha256(args.baseline)

    # Decide how to obtain a session (mutually exclusive flags simplify logic)
    if args.account_role_arn:
        try:
            session = assume_role(args.account_role_arn, args.region)
        except ClientError as e:
            print(f"ERROR: Unable to assume role {args.account_role_arn}: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        # Ambient credentials path
        try:
            session = boto3.session.Session(region_name=args.region)
            session.client("sts").get_caller_identity()
        except NoCredentialsError:
            print("ERROR: No ambient AWS credentials (provide --account-role-arn or configure credentials)", file=sys.stderr)
            sys.exit(1)
        except ClientError as e:
            print(f"ERROR: Unable to validate ambient credentials: {e}", file=sys.stderr)
            sys.exit(1)
    report, summary = detect(baseline, session, args.region, args.check_log_groups, baseline_hash)
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    with open(args.summary_output, "w", encoding="utf-8") as sf:
        json.dump(summary, sf, indent=2)
    print(f"Wrote detection report: {args.output}")
    print(f"Summary: {json.dumps(summary)}")
    if args.fail_on_unknown_severity and summary["severityTotals"].get("unknown", 0) > 0:
        print("Unknown severities present and --fail-on-unknown-severity specified", file=sys.stderr)
        sys.exit(3)
    if summary["hasDrift"]:
        sys.exit(2)

if __name__ == "__main__":
    main()
