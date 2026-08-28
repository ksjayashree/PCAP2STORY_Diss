"""
Full 3RR/10PE batch generation driver. Deploys via deploy_with_retry.sh,
then runs every scenario category, logging every scenario's status to one
running timestamped log. Retries individual scenarios only via
All_Scenarios.py's own bounded 2-attempt-per-scenario pattern; on
unexpected failures it logs and continues rather than stopping. Wire-level
verification is not done here.
"""
import sys
import os
import subprocess
import datetime
import itertools
import json
from pathlib import Path

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.dirname(__file__) + os.sep + "link_down")

BASE = str(Path(__file__).resolve().parents[2])
LOGDIR = os.path.join(BASE, "logs")
os.makedirs(LOGDIR, exist_ok=True)
RUN_TS = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
LOGFILE = os.path.join(LOGDIR, f"full_batch_{RUN_TS}.log")

_log_fh = open(LOGFILE, "a", encoding="utf-8")


def log(msg):
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    line = f"{ts} {msg}"
    print(line, flush=True)
    _log_fh.write(line + "\n")
    _log_fh.flush()


def deploy_fabric():
    log(f"########## DEPLOY: launching deploy_with_retry.sh ##########")
    deploy_script = os.path.join(BASE, "topology", "deploy_with_retry.sh")
    result = subprocess.run(
        ["wsl", "bash", deploy_script.replace("C:", "/mnt/c").replace("\\", "/")],
        capture_output=True, text=True,
    )
    log("---- deploy_with_retry.sh stdout ----")
    for line in result.stdout.splitlines():
        log("  " + line)
    if result.returncode != 0:
        log("---- deploy_with_retry.sh stderr ----")
        for line in result.stderr.splitlines():
            log("  " + line)
    log(f"deploy_with_retry.sh exit code: {result.returncode}")
    return result.returncode == 0


ALL_RESULTS = []


def record(category, name, status, extra=None):
    entry = {"category": category, "name": name, "status": status}
    if extra:
        entry["extra"] = extra
    ALL_RESULTS.append(entry)
    log(f"[{category}] {name}: {status}")


def run_category(category_name, fn):
    log(f"========== CATEGORY START: {category_name} ==========")
    try:
        fn()
    except Exception as e:
        log(f"[{category_name}][UNCAUGHT EXCEPTION] {e} -- logged, continuing to next category")
    log(f"========== CATEGORY END: {category_name} ==========")


def do_link_down():
    import All_Scenarios as ov
    ov.scenario_results.clear()
    ov.discover_pe_interfaces()
    ov.run_link_down()
    for r in ov.scenario_results:
        record("link_down", r["name"], r["status"])


def do_rr_down():
    import All_Scenarios as ov
    ov.scenario_results.clear()
    ov.run_rr_down()
    for r in ov.scenario_results:
        record("rr_down", r["name"], r["status"])


def do_pe_cease():
    import All_Scenarios as ov
    ov.scenario_results.clear()
    ov.run_pe_cease()
    for r in ov.scenario_results:
        record("pe_cease", r["name"], r["status"])


def do_rt_misconfig():
    import All_Scenarios as ov
    ov.scenario_results.clear()
    ov.run_rt_misconfig()
    for r in ov.scenario_results:
        record("rt_misconfig", r["name"], r["status"])


def do_rd_collision():
    import rd_collision_run as rd
    rd.results.clear()
    simple_pairs = [("xpe1", "xpe2"), ("xpe8", "xpe9"), ("xpe9", "xpe10")]
    masking_pairs = [("xpe3", "xpe4"), ("xpe6", "xpe7")]
    for pe_a, pe_b in simple_pairs + masking_pairs:
        for fixed in [False, True]:
            try:
                rd.run_scenario(pe_a, pe_b, fixed)
            except Exception as e:
                log(f"[rd_collision][EXCEPTION] {pe_a}/{pe_b} fixed={fixed}: {e} -- continuing")
    for r in rd.results:
        record("rd_collision", r["name"], r["status"])


def do_mac_mobility():
    import mac_mobility_run as mm
    mm.results.clear()
    pairs = [
        # within-RR1-domain (xpe2->xpe8 spans RR1/RR3)
        ("xpe1", "xpe2"), ("xpe2", "xpe8"), ("xpe8", "xpe1"),
        # within-RR2-domain
        ("xpe5", "xpe6"), ("xpe6", "xpe7"), ("xpe7", "xpe5"),
        # within-RR3-domain
        ("xpe9", "xpe10"), ("xpe10", "xpe9"),
        # cross-RR-domain (via RR mesh)
        ("xpe1", "xpe5"), ("xpe5", "xpe9"), ("xpe9", "xpe1"),
        ("xpe2", "xpe6"), ("xpe6", "xpe10"), ("xpe10", "xpe2"),
        ("xpe7", "xpe8"), ("xpe8", "xpe5"), ("xpe4", "xpe9"), ("xpe3", "xpe10"),
        ("xpe6", "xpe3"), ("xpe8", "xpe4"),
    ]
    log(f"[mac_mobility] running {len(pairs)} clean-move scenarios")
    for origin, dest in pairs:
        try:
            mm.run_clean_move(origin, dest)
        except Exception as e:
            log(f"[mac_mobility][EXCEPTION] {origin}->{dest}: {e} -- continuing")
    for r in mm.results:
        record("mac_mobility", r["name"], r["status"])


def do_normal_captures():
    import All_Scenarios as ov
    ov.scenario_results.clear()
    ov.run_normal_captures()
    for r in ov.scenario_results:
        record("normal", r["name"], r["status"])


def main():
    log("########## FULL BATCH RUN STARTING ##########")
    log(f"Log file: {LOGFILE}")

    if not deploy_fabric():
        log("########## ABORTING: deploy_with_retry.sh failed, cannot generate any scenarios ##########")
        write_summary()
        return

    log("---- pre-flight tcpdump already ensured by deploy_with_retry.sh, proceeding to scenario generation ----")

    run_category("link_down", do_link_down)
    run_category("rr_down", do_rr_down)
    run_category("pe_cease", do_pe_cease)
    run_category("rt_misconfig", do_rt_misconfig)
    run_category("rd_collision", do_rd_collision)
    run_category("mac_mobility", do_mac_mobility)
    run_category("normal", do_normal_captures)

    write_summary()


def write_summary():
    log("########## FULL BATCH RUN COMPLETE ##########")
    by_cat = {}
    for r in ALL_RESULTS:
        cat = r["category"]
        by_cat.setdefault(cat, {"OK": 0, "FAILED": 0, "FAILED_AFTER_RETRY": 0, "MISSING_FILES": 0, "OTHER": 0, "total": 0})
        by_cat[cat]["total"] += 1
        status = r["status"]
        if status in by_cat[cat]:
            by_cat[cat][status] += 1
        elif status == "OK":
            by_cat[cat]["OK"] += 1
        else:
            by_cat[cat]["OTHER"] += 1

    total_all = len(ALL_RESULTS)
    ok_all = sum(1 for r in ALL_RESULTS if r["status"] == "OK")
    log(f"TOTAL scenarios attempted: {total_all}")
    log(f"TOTAL OK: {ok_all}")
    log(f"TOTAL NOT OK: {total_all - ok_all}")
    log("---- breakdown by category ----")
    for cat, counts in by_cat.items():
        log(f"  {cat}: {json.dumps(counts)}")

    summary_path = os.path.join(LOGDIR, f"full_batch_{RUN_TS}_summary.json")
    with open(summary_path, "w") as f:
        json.dump({"total": total_all, "ok": ok_all, "by_category": by_cat, "all_results": ALL_RESULTS}, f, indent=2)
    log(f"Summary JSON written to: {summary_path}")


if __name__ == "__main__":
    main()
